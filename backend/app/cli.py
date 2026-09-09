"""Command-line interface.

Stdlib ``argparse`` only, so the CLI works without installing the API extras::

    auditor audit fixtures/vulnerable/ReentrantVault.sol
    auditor audit contracts/ -f html -o reports/
    auditor serve --port 8000
    auditor detectors
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.core.config import get_settings
from app.services.engine import AuditEngine, audit_sources
from app.services.report_generator import to_json, to_markdown, write_reports
from app.services.solc import discover_solc, solc_version

SEVERITY_ICON = {
    "Critical": "CRIT",
    "High": "HIGH",
    "Medium": "MED ",
    "Low": "LOW ",
    "Informational": "INFO",
    "Optimization": "OPT ",
}


def _collect_sources(paths: list[str]) -> dict[str, str]:
    """Read every ``.sol`` under the given files/directories into one unit."""
    sources: dict[str, str] = {}
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files = sorted(path.rglob("*.sol"))
            if not files:
                raise SystemExit(f"no .sol files under {path}")
            for file in files:
                sources[str(file.relative_to(path))] = file.read_text(encoding="utf-8")
        elif path.is_file():
            sources[path.name] = path.read_text(encoding="utf-8")
        else:
            raise SystemExit(f"no such file or directory: {raw}")
    return sources


def _print_table(result, stream) -> None:
    counts = result.counts_by_severity()
    print(f"\nsolc: {result.solc_version or 'unavailable'}   "
          f"compiled: {'yes' if result.compiled else 'NO'}   "
          f"{result.duration_ms} ms", file=stream)
    print(f"score: {result.score}/100 (grade {result.grade})   "
          f"findings: {len(result.findings)}  " +
          "  ".join(f"{k}={v}" for k, v in counts.items() if v), file=stream)
    if result.contracts:
        print("\ncontracts:", file=stream)
        for c in result.contracts:
            print(f"  {c.name:<28} {c.kind:<9} fns={c.functions:<3} "
                  f"vars={c.state_variables:<3} bytecode={c.bytecode_size}B  ({c.file})",
                  file=stream)
    if not result.findings:
        print("\nNo findings.", file=stream)
        return
    print("\nfindings:", file=stream)
    for f in result.sorted_findings():
        where = f.location.file or "?"
        line = f":{f.location.line}" if f.location.line else ""
        scope = f"  [{f.contract}.{f.function}]" if f.contract else ""
        print(f"  {SEVERITY_ICON.get(f.severity.label, '?')}  "
              f"{f.check_id:<30} {where}{line}{scope}", file=stream)
        print(f"        {f.title}", file=stream)


def cmd_audit(args: argparse.Namespace) -> int:
    sources = _collect_sources(args.paths)
    settings = get_settings()
    result = audit_sources(
        sources,
        settings=settings,
        include_optimizations=not args.no_optimizations,
        run_external_tools=not args.no_external_tools,
    )

    if args.format == "table":
        _print_table(result, sys.stdout)
    elif args.format == "json":
        print(to_json(result))
    elif args.format == "md":
        print(to_markdown(result))

    if args.output:
        formats = ("json", "md", "html") if args.format == "table" else (args.format,)
        written = write_reports(result, args.output, formats=formats)
        print("\nwrote:", file=sys.stderr)
        for fmt, path in written.items():
            print(f"  {fmt:<5} {path}", file=sys.stderr)

    if args.fail_under is not None and result.score < args.fail_under:
        print(f"\nFAILED: score {result.score} < {args.fail_under}", file=sys.stderr)
        return 1
    if args.fail_on and any(
        f.severity.label.lower() in {s.strip().lower() for s in args.fail_on.split(",")}
        for f in result.findings
    ):
        print(f"\nFAILED: findings at or above {args.fail_on}", file=sys.stderr)
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


def cmd_detectors(args: argparse.Namespace) -> int:
    from app.services.detectors import build_default_registry

    registry = build_default_registry(include_optimizations=True)
    rows = registry.all()
    if args.json:
        print(json.dumps(
            [{"check_id": d.check_id, "title": d.title, "swc": d.swc, "cwe": d.cwe,
              "requires_compilation": d.requires_ast} for d in rows], indent=2))
        return 0
    print(f"{len(rows)} checks available:\n")
    for d in rows:
        needs = " [needs solc]" if d.requires_ast else ""
        refs = " ".join(x for x in (d.swc, d.cwe) if x)
        print(f"  {d.check_id:<32} {d.title}{needs}")
        if d.blurb:
            print(f"  {'':<32} {d.blurb}  {refs}".rstrip())
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what this environment can and cannot do -- no guesswork."""
    settings = get_settings()
    binary = discover_solc(settings.solc_bin)
    print("environment")
    print(f"  solc binary : {binary or 'NOT FOUND'}")
    print(f"  solc version: {solc_version(binary) if binary else 'n/a'}")
    if not binary:
        print("  -> AST checks are disabled. Run `npm install solc` in the repo root,")
        print("     or install a native solc and set AUDITOR_SOLC.")
    import shutil

    for tool, hint in (("slither", "pip install slither-analyzer"),
                       ("myth", "pip install mythril")):
        found = shutil.which(tool)
        print(f"  {tool:<12}: {found or f'not installed ({hint})'}")
    print(f"  database    : {settings.database_url}")
    print(f"  reports     : {settings.report_dir}")
    print(f"  auth        : {'enabled' if settings.auth_enabled else 'disabled'}")
    return 0 if binary else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Static analysis and risk scoring for Solidity contracts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="audit files or directories")
    p_audit.add_argument("paths", nargs="+", help=".sol files or directories")
    p_audit.add_argument("-f", "--format", default="table",
                         choices=["table", "json", "md"], help="stdout format")
    p_audit.add_argument("-o", "--output", help="write reports to this directory")
    p_audit.add_argument("--no-optimizations", action="store_true",
                         help="skip gas/style checks")
    p_audit.add_argument("--no-external-tools", action="store_true",
                         help="skip Slither/Mythril even if installed")
    p_audit.add_argument("--fail-under", type=int, metavar="SCORE",
                         help="exit 1 if the score is below SCORE (for CI)")
    p_audit.add_argument("--fail-on", metavar="SEVERITIES",
                         help="exit 1 if any of these severities appear, e.g. high,critical")
    p_audit.set_defaults(func=cmd_audit)

    p_serve = sub.add_parser("serve", help="run the REST API")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=cmd_serve)

    p_det = sub.add_parser("detectors", help="list available checks")
    p_det.add_argument("--json", action="store_true")
    p_det.set_defaults(func=cmd_detectors)

    p_doc = sub.add_parser("doctor", help="show toolchain availability")
    p_doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
