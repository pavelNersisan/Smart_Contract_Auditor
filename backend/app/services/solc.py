"""Solidity compiler adapter.

The engine needs a real ``solc`` AST (not regex) to reason about code. This
module drives any ``solc``-compatible binary through its *standard JSON*
interface, which both the native compiler and the WASM ``solcjs`` shipped on
npm implement.

Behaviours encoded here were established empirically against solcjs 0.8.24:

* Top-level ``{"urls": [...]}`` sources are rejected ("File import callback not
  supported"), so every source is passed **inline** as ``content``.
* ``import "./Other.sol"`` inside a source *is* resolved from disk when
  ``--base-path`` points at the directory holding the files, so sources are
  also written to a temporary base path.
* The AST is a **file-level** output: it must be requested as
  ``{"*": {"": ["ast"]}}``, not under the per-contract ``"*"`` key.
* solcjs prints a ``>>> Cannot retry compilation with SMT ...`` banner before
  the JSON document, so the response is sliced from its first ``{``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class CompilerUnavailable(RuntimeError):
    """No usable solc binary could be found."""


@dataclass
class CompiledContract:
    name: str
    source_unit: str
    kind: str = "contract"
    abi: list = field(default_factory=list)
    bytecode: str = ""
    deployed_bytecode: str = ""

    @property
    def qualified_name(self) -> str:
        return f"{self.source_unit}:{self.name}"


@dataclass
class CompilerMessage:
    severity: str
    type: str
    message: str
    formatted: str = ""
    file: str = ""
    line: int = 0
    column: int = 0


@dataclass
class Compilation:
    """Result of one compiler invocation."""

    ok: bool
    solc_version: str
    sources: dict[str, str]
    asts: dict[str, dict] = field(default_factory=dict)
    contracts: dict[str, CompiledContract] = field(default_factory=dict)
    messages: list[CompilerMessage] = field(default_factory=list)
    #: fileIndex (as used in ``src`` strings) -> source path
    file_index_to_name: dict[int, str] = field(default_factory=dict)
    #: byte offset -> (line, column) per file, for turning ``src`` into lines
    line_indexes: dict[str, list[int]] = field(default_factory=dict)

    @property
    def has_ast(self) -> bool:
        return bool(self.asts)

    @property
    def errors(self) -> list[CompilerMessage]:
        return [m for m in self.messages if m.severity == "error"]

    @property
    def warnings(self) -> list[CompilerMessage]:
        return [m for m in self.messages if m.severity == "warning"]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------
def discover_solc(preferred: str = "") -> str | None:
    """Locate a solc-compatible binary.

    Order: explicit config, ``AUDITOR_SOLC``, ``solc`` on PATH, then the WASM
    ``solcjs`` installed under the repo's ``node_modules``.
    """
    for candidate in (preferred, os.environ.get("AUDITOR_SOLC", "")):
        if candidate:
            resolved = shutil.which(candidate) or (
                candidate if Path(candidate).exists() else None
            )
            if resolved:
                return resolved

    native = shutil.which("solc")
    if native:
        return native

    for base in (REPO_ROOT, Path.cwd()):
        solcjs = base / "node_modules" / ".bin" / "solcjs"
        if solcjs.exists():
            return str(solcjs)
    return shutil.which("solcjs")


def solc_version(binary: str) -> str:
    """Return the compiler version string, or ``"unknown"``."""
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    out = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r"(\d+\.\d+\.\d+(?:[+-][\w.]+)?)", out)
    return match.group(1) if match else (out.strip().splitlines() or ["unknown"])[0]


# --------------------------------------------------------------------------
# Line mapping
# --------------------------------------------------------------------------
def build_line_index(text: str) -> list[int]:
    """Byte offset of the start of each line, for ``src`` -> line conversion."""
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def offset_to_line_column(offsets: list[int], offset: int) -> tuple[int, int]:
    """Binary search ``offset`` into a 1-based (line, column)."""
    if not offsets:
        return (0, 0)
    lo, hi = 0, len(offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offsets[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return (lo + 1, offset - offsets[lo] + 1)


# --------------------------------------------------------------------------
# Compilation
# --------------------------------------------------------------------------
def _extract_json(raw: str) -> dict:
    """Parse solc's stdout, skipping any non-JSON banner lines."""
    start = raw.find("{")
    if start == -1:
        raise ValueError(f"no JSON in compiler output: {raw[:200]!r}")
    return json.loads(raw[start:])


def compile_sources(
    sources: dict[str, str],
    binary: str | None = None,
    timeout: int = 120,
) -> Compilation:
    """Compile ``sources`` (path -> Solidity text) to AST, ABI and bytecode.

    Never raises for *contract* errors: parse failures are returned in
    ``messages`` so the source-level detectors still get a chance to run.
    Only a missing/broken compiler raises :class:`CompilerUnavailable`.
    """
    if not sources:
        raise ValueError("no sources to compile")

    binary = binary or discover_solc()
    if not binary:
        raise CompilerUnavailable(
            "no solc binary found; install solc, or run `npm install solc` "
            "in the repository root to use the WASM compiler"
        )
    version = solc_version(binary)

    if not any(name.endswith(".sol") for name in sources):
        # Give the compiler something named like Solidity source.
        sources = {"Contract.sol": next(iter(sources.values()))}

    with tempfile.TemporaryDirectory(prefix="auditor-solc-") as tmp:
        base = Path(tmp)
        for name, text in sources.items():
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

        payload = {
            "language": "Solidity",
            # Inline content (urls are unsupported) + on-disk copies so that
            # `import` statements resolve against base_path.
            "sources": {name: {"content": text} for name, text in sources.items()},
            "settings": {
                "optimizer": {"enabled": False},
                "outputSelection": {
                    "*": {"": ["ast"], "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}
                },
            },
        }

        # stdout is redirected to a regular file rather than captured from a
        # pipe. Node (which backs the WASM solcjs) writes to pipes
        # asynchronously and can exit before the buffer drains, truncating the
        # JSON mid-document at a 64 KiB boundary -- intermittently, which makes
        # it especially nasty. Writes to a regular file are synchronous.
        out_file = base / ".solc-output.json"
        err_file = base / ".solc-stderr.txt"
        try:
            with out_file.open("wb") as out_fh, err_file.open("wb") as err_fh:
                subprocess.run(
                    [binary, "--standard-json", "--base-path", str(base)],
                    input=json.dumps(payload).encode("utf-8"),
                    stdout=out_fh,
                    stderr=err_fh,
                    timeout=timeout,
                    cwd=str(base),
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise CompilerUnavailable(f"compiler timed out after {timeout}s") from exc
        except OSError as exc:
            raise CompilerUnavailable(f"cannot execute compiler: {exc}") from exc

        stdout_text = out_file.read_text(encoding="utf-8", errors="replace")
        stderr_text = err_file.read_text(encoding="utf-8", errors="replace")

        try:
            out = _extract_json(stdout_text)
        except (ValueError, json.JSONDecodeError) as exc:
            raise CompilerUnavailable(
                f"unparsable compiler output ({exc}); stderr={stderr_text[:300]!r}"
            ) from exc

        # A source may pull in files we never received (resolved off the base
        # path). Recover their text now, before the temp dir is removed, so
        # findings in them still get accurate line numbers.
        for name in out.get("sources") or {}:
            if name not in sources:
                candidate = base / name
                if candidate.exists():
                    sources[name] = candidate.read_text(encoding="utf-8")

    # ---- harvest ---------------------------------------------------------
    # Sources solc actually parsed include files pulled in by `import`.
    parsed_sources = dict(sources)
    asts: dict[str, dict] = {}
    file_index_to_name: dict[int, str] = {}
    for name, info in (out.get("sources") or {}).items():
        ast = info.get("ast")
        if ast is None:
            continue
        asts[name] = ast
        # The third component of a `src` string is the *file index*, which is
        # NOT the SourceUnit node id (verified: id=43 while src="32:308:0").
        # Each SourceUnit's own `src` therefore identifies its file index.
        src = ast.get("src") or ""
        parts = src.split(":")
        if len(parts) == 3 and parts[2].lstrip("-").isdigit():
            file_index_to_name[int(parts[2])] = name
        if name not in parsed_sources:
            # File was pulled in by an `import`; solc did not echo its text.
            parsed_sources[name] = ""

    line_indexes = {name: build_line_index(text) for name, text in parsed_sources.items()}

    contracts: dict[str, CompiledContract] = {}
    for file_name, by_contract in (out.get("contracts") or {}).items():
        for contract_name, data in by_contract.items():
            evm = data.get("evm") or {}
            contracts[f"{file_name}:{contract_name}"] = CompiledContract(
                name=contract_name,
                source_unit=file_name,
                abi=data.get("abi") or [],
                bytecode=(evm.get("bytecode") or {}).get("object", "") or "",
                deployed_bytecode=(evm.get("deployedBytecode") or {}).get("object", "")
                or "",
            )

    messages: list[CompilerMessage] = []
    for entry in out.get("errors") or []:
        loc = (entry.get("sourceLocation") or {})
        file_name = loc.get("file", "")
        line = column = 0
        if file_name and "start" in loc:
            idx = line_indexes.get(file_name)
            if idx:
                line, column = offset_to_line_column(idx, int(loc["start"]))
        messages.append(
            CompilerMessage(
                severity=entry.get("severity", "error"),
                type=entry.get("type", ""),
                message=entry.get("message", ""),
                formatted=entry.get("formattedMessage", ""),
                file=file_name,
                line=line,
                column=column,
            )
        )

    return Compilation(
        ok=not any(m.severity == "error" for m in messages),
        solc_version=version,
        sources=parsed_sources,
        asts=asts,
        contracts=contracts,
        messages=messages,
        file_index_to_name=file_index_to_name,
        line_indexes=line_indexes,
    )
