"""Background execution of audits.

The README's architecture calls for Celery. Celery needs a broker (Redis), and
requiring one just to run an audit would make the service undeployable on its
own. So the task interface is kept, with two backends:

* ``ThreadTaskRunner`` -- the default, in-process, zero infrastructure.
* ``CeleryTaskRunner`` -- used automatically when Celery is installed *and*
  ``AUDITOR_BROKER_URL`` is set.

Both expose ``submit``/``result``, so swapping brokers later touches nothing
else.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

from app.models.audit import AuditResult
from app.services.engine import audit_sources

logger = logging.getLogger("auditor.worker")

#: Filled in by ``init_celery`` when a broker is configured.
celery_app = None


@dataclass
class JobStatus:
    id: str
    state: str = "pending"  # pending | running | completed | failed
    result: AuditResult | None = None
    error: str = ""


class ThreadTaskRunner:
    """In-process runner backed by a small thread pool."""

    def __init__(self, max_workers: int = 4) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit")
        self._jobs: dict[str, JobStatus] = {}
        self._futures: dict[str, Future] = {}
        self._lock = threading.Lock()

    def submit(
        self, sources: dict[str, str], **kwargs
    ) -> str:
        job_id = uuid.uuid4().hex
        status = JobStatus(id=job_id)
        with self._lock:
            self._jobs[job_id] = status

        def _run() -> None:
            with self._lock:
                status.state = "running"
            try:
                result = audit_sources(sources, **kwargs)
                with self._lock:
                    status.result = result
                    status.state = "completed"
            except Exception as exc:  # surfaced to the caller, not swallowed
                logger.exception("audit job %s failed", job_id)
                with self._lock:
                    status.error = str(exc)
                    status.state = "failed"

        self._futures[job_id] = self._pool.submit(_run)
        return job_id

    def status(self, job_id: str) -> JobStatus | None:
        with self._lock:
            return self._jobs.get(job_id)

    def wait(self, job_id: str, timeout: float | None = None) -> JobStatus | None:
        future = self._futures.get(job_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.status(job_id)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)


class CeleryTaskRunner:
    """Thin wrapper that defers to a Celery task when a broker is configured."""

    TASK_NAME = "auditor.tasks.run_audit"

    def __init__(self, app) -> None:
        self._app = app

    def submit(self, sources: dict[str, str], **kwargs) -> str:
        async_result = self._app.send_task(self.TASK_NAME, args=[sources], kwargs=kwargs)
        return async_result.id

    def status(self, job_id: str) -> JobStatus | None:
        async_result = self._app.AsyncResult(job_id)
        state = str(async_result.state).lower()
        if state in ("success", "completed"):
            payload = async_result.result
            result = AuditResult.model_validate(payload) if payload else None
            return JobStatus(id=job_id, state="completed", result=result)
        if state == "failure":
            return JobStatus(id=job_id, state="failed", error=str(async_result.result))
        return JobStatus(id=job_id, state=state)

    def wait(self, job_id: str, timeout: float | None = None) -> JobStatus | None:
        async_result = self._app.AsyncResult(job_id)
        async_result.get(timeout=timeout)
        return self.status(job_id)

    def shutdown(self, wait: bool = True) -> None:
        return None


@dataclass
class WorkerConfig:
    broker_url: str = ""
    max_workers: int = 4
    backend: str = field(default="")


def init_celery(broker_url: str = ""):
    """Create the Celery app when celery is installed and a broker is given."""
    global celery_app
    broker_url = broker_url or os.environ.get("AUDITOR_BROKER_URL", "")
    if not broker_url:
        return None
    try:
        from celery import Celery
    except ImportError:
        logger.info("celery not installed; using the in-process task runner")
        return None

    celery_app = Celery("auditor", broker=broker_url, backend=broker_url)

    @celery_app.task(name=CeleryTaskRunner.TASK_NAME)
    def run_audit(sources: dict[str, str], **kwargs) -> dict:  # pragma: no cover
        return audit_sources(sources, **kwargs).model_dump(mode="json")

    return celery_app


def build_runner(config: WorkerConfig | None = None) -> ThreadTaskRunner | CeleryTaskRunner:
    """Pick the best available backend for this environment."""
    config = config or WorkerConfig(
        broker_url=os.environ.get("AUDITOR_BROKER_URL", "")
    )
    app = init_celery(config.broker_url)
    if app is not None:
        logger.info("using Celery task runner (broker=%s)", config.broker_url)
        return CeleryTaskRunner(app)
    return ThreadTaskRunner(max_workers=config.max_workers)
