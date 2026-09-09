"""Built-in detector set.

Every check lives in its own class so it can be listed, disabled and tested
individually. ``build_default_registry`` is the single place the set is
assembled, which keeps the API's ``GET /detectors`` in step with reality.
"""

from __future__ import annotations

from . import (
    access_control,
    arithmetic,
    external_calls,
    hygiene,
    reentrancy,
    source_checks,
)
from .base import AnalysisContext, AstDetector, ContractInfo, Detector, DetectorRegistry

__all__ = [
    "AnalysisContext",
    "AstDetector",
    "ContractInfo",
    "Detector",
    "DetectorRegistry",
    "build_default_registry",
]


def build_default_registry(
    include_optimizations: bool = True,
    disabled: set[str] | None = None,
) -> DetectorRegistry:
    """Assemble the standard detector set.

    ``include_optimizations=False`` drops gas/style advice so a report can focus
    on security findings only.
    """
    disabled = disabled or set()
    detectors: list[Detector] = [
        # Reentrancy
        reentrancy.ReentrancyEth(),
        reentrancy.ReentrancyNoEth(),
        # Access control
        access_control.Suicidal(),
        access_control.UnprotectedEtherWithdrawal(),
        access_control.UnprotectedInitializer(),
        access_control.MissingAccessControlOnSetter(),
        access_control.TxOriginAuth(),
        # External calls
        external_calls.UncheckedSend(),
        external_calls.UncheckedLowLevelCall(),
        external_calls.CallsInsideLoop(),
        external_calls.MsgValueInLoop(),
        external_calls.DelegatecallToUntrustedInput(),
        # Arithmetic
        arithmetic.IntegerOverflow(),
        arithmetic.UncheckedArithmeticBlock(),
        arithmetic.DivideBeforeMultiply(),
        arithmetic.UnvalidatedDivisor(),
        # Hygiene
        hygiene.FloatingPragma(),
        hygiene.AncientSolcVersion(),
        hygiene.TimestampDependency(),
        hygiene.WeakRandomness(),
        hygiene.AssemblyUsage(),
        hygiene.HardcodedAddress(),
        hygiene.MissingZeroAddressCheck(),
        hygiene.Erc20ApproveRace(),
        hygiene.DeprecatedUsage(),
        hygiene.LongFunction(),
        hygiene.CompilerDiagnostics(),
        # Source-level (no AST required)
        source_checks.MissingLicenseHeader(),
        source_checks.TodoComments(),
        source_checks.LegacyCallSyntax(),
        source_checks.HardcodedSecret(),
        source_checks.UncompilableSource(),
        # Gas / style -- opt-in
        hygiene.ExternalFunction(),
    ]

    registry = DetectorRegistry()
    for detector in detectors:
        if not include_optimizations and detector.check_id in {
            "external-function",
            "long-function",
        }:
            continue
        if detector.check_id in disabled:
            continue
        registry.register(detector)
    return registry
