"""Shared evidence lifecycle and output policies for the two inventory CLIs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from brotli_attestations import CapturedDocument, capture_attestation_inputs, capture_document
from brotli_debug_companions import DEFAULT_DEBUG_LIMITS
from brotli_flirt import DEFAULT_FLIRT_BUNDLE
from brotli_report_finalizer import (
    IdentityData,
    IdentityPath,
    collect_cli_identities,
    finalize_report,
    verify_identity_stability,
)

if TYPE_CHECKING:
    import argparse

    from brotli_inventory import Inventory
    from brotli_report_finalizer import FinalizationIdentities, FinalizedReport

SCANNER_VERSION = "0.3.0"
MAX_FEED_BYTES = 64 * 1024 * 1024
OUTPUT_OPTIONS = frozenset({"json", "sarif", "baseline", "fail_on", "roots"})


def add_reporting_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sarif", action="store_true", help="render canonical evidence as SARIF 2.1.0"
    )
    parser.add_argument(
        "--baseline", type=Path, help="explicit prior JSON report for compatible-scope comparison"
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "affected", "coverage", "new_affected"),
        default="none",
        help="explicit policy; none preserves normal exit semantics",
    )


def _configuration(args: argparse.Namespace) -> dict:
    result = {}
    for name, original in vars(args).items():
        value = original
        if name in OUTPUT_OPTIONS:
            continue
        if isinstance(value, Path):
            value = str(value.expanduser().absolute())
        elif isinstance(value, list):
            value = [
                str(item.expanduser().absolute()) if isinstance(item, Path) else item
                for item in value
            ]
        result[name] = value
    return result


class CliEvidence:
    def __init__(self, args: argparse.Namespace, registry: Path) -> None:
        self.args = args
        self.registry = registry
        self.attestation_inputs = capture_attestation_inputs(
            getattr(args, "attestation", []), getattr(args, "attestation_policy", None)
        )
        symbol_paths = getattr(args, "debug_symbols", [])
        if len(symbol_paths) > DEFAULT_DEBUG_LIMITS.max_companions:
            message = "Supplied debug-symbol packet count exceeds limit"
            raise ValueError(message)
        self.debug_symbol_inputs: tuple[CapturedDocument, ...] = tuple(
            capture_document(path) for path in symbol_paths
        )
        self.before = self.collect()

    def collect(self) -> FinalizationIdentities:
        args = self.args
        feeds = []
        for path in args.vendor_snapshot:
            with path.expanduser().open("rb") as stream:
                raw = stream.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                message = "Vendor snapshot exceeds metadata byte budget"
                raise ValueError(message)
            feeds.append(IdentityData("vendor-snapshot", str(path), raw))
        bundle = (args.flirt_references or DEFAULT_FLIRT_BUNDLE) if args.flirt else None
        extras = []
        feeds.extend(
            IdentityData("attestation", item.label, item.raw)
            for item in self.attestation_inputs.bundles
        )
        if self.attestation_inputs.policy is not None:
            item = self.attestation_inputs.policy
            feeds.append(IdentityData("trust-policy", item.label, item.raw))
        feeds.extend(
            IdentityData("debug-symbol-export", item.label, item.raw)
            for item in self.debug_symbol_inputs
        )
        if getattr(args, "catalog", None) is not None:
            extras.append(IdentityPath("catalog", "artifact-labels", args.catalog))
        extras.extend(IdentityPath("debug-companion", str(path), path) for path in args.debug_file)
        return collect_cli_identities(
            scanner_version=SCANNER_VERSION,
            analysis_config=_configuration(args),
            code_references=args.code_references,
            source_fingerprints=self.registry,
            flirt_bundle=bundle,
            vendor_feeds=tuple(feeds),
            extra_catalog_files=tuple(extras),
        )

    def check_inputs(self, inventory: Inventory) -> FinalizationIdentities:
        identities = verify_identity_stability(self.before, self.collect())
        for reason in identities.gaps:
            inventory.gap("<analysis-inputs>", reason)
        return identities

    def finalize(self, report: dict, identities: FinalizationIdentities) -> FinalizedReport:
        report["analysis_inputs_changed"] = identities.input_changed
        return finalize_report(
            report,
            scanner=identities.scanner,
            catalogs=identities.catalogs,
            feeds=identities.feeds,
            optional_tools=identities.optional_tools,
            baseline=self.args.baseline,
            fail_policy=self.args.fail_on,
        )


def policy_exit(normal: int, finalized: FinalizedReport, policy: str) -> int:
    return normal if policy == "none" else int(finalized.policy.fail)
