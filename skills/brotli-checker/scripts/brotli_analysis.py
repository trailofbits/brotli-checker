"""Per-scan artifact registry and qualified cross-artifact evidence joins."""

from __future__ import annotations

import hashlib
import posixpath
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from brotli_attestations import (
    AttestationInputs,
    CapturedDocument,
    capture_attestation_inputs,
    capture_document,
    inspect_captured_attestations,
)
from brotli_binary_data import file_data, sha256_data
from brotli_binary_graph import InstructionPacket, build_elf_graph, seeds_from_assessment
from brotli_binary_layout import inspect_layout
from brotli_debug_companions import (
    SuppliedCompanion,
    debug_symbol_export_identity,
    expected_mach_export_scopes,
    verify_debug_companions,
    verify_mach_debug_export,
    verify_pdb_symbol_export,
)
from brotli_graph_packets import graph_triage_target_sha256, instruction_packet_from_triage
from brotli_package_provenance import (
    MetadataRecord,
    PackageDatabase,
    assess_vendor_assertions,
    build_ownership_index,
    load_vendor_snapshot,
    package_from_rpm_metadata,
    parse_apk_database,
    parse_dpkg_database,
    resolve_ownership_hashes,
)
from brotli_provenance import parse_provenance_json
from brotli_providers import elf_dependencies, provider_graph
from brotli_runtime_evidence import inspect_runtime_traces
from brotli_trust_inputs import TrustInputs, capture_trust_arguments, inspect_trust_inputs

if TYPE_CHECKING:
    import argparse
    from collections.abc import Sequence

    from brotli_binary_data import Buffer
    from brotli_inventory import Inventory
    from brotli_package_provenance import VendorSnapshot

MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_RELATIONS = 100000
HASH_CHUNK = 1024 * 1024
MAX_ANALYSIS_GAPS = 200
MAX_IMAGE_HISTORY = 100000


def _hashes(data: Buffer, sha256: str) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    for offset in range(0, len(data), HASH_CHUNK):
        part = data[offset : min(len(data), offset + HASH_CHUNK)]
        md5.update(part)
        sha1.update(part)
    return {"SHA-256": sha256, "MD5": md5.hexdigest(), "SHA-1": sha1.hexdigest()}


class AnalysisSession:
    def __init__(  # noqa: PLR0913 -- Independent supplied evidence populations.
        self,
        roots: list[Path],
        *,
        deployment_roots: Sequence[Path] = (),
        xrefs: bool = True,
        companions: tuple[SuppliedCompanion, ...] = (),
        debug_symbol_exports: tuple[CapturedDocument, ...] = (),
        snapshots: tuple[VendorSnapshot, ...] = (),
        graph_triage: tuple[CapturedDocument, ...] = (),
    ) -> None:
        self.roots = [str(path.absolute()) for path in roots]
        self.deployment_roots = [str(path.absolute()) for path in deployment_roots]
        self.xrefs = xrefs
        self.gaps: list[dict] = []
        self.gap_count = 0
        self.companions = companions
        self.debug_symbol_exports = debug_symbol_exports
        self._used_debug_symbol_exports: set[str] = set()
        self._debug_symbols_by_target: dict[str, list[tuple[CapturedDocument, str, str, str]]] = {}
        for item in debug_symbol_exports:
            try:
                family, target_sha256, companion_sha256, scope = debug_symbol_export_identity(
                    item.raw
                )
            except ValueError as error:
                self._used_debug_symbol_exports.add(item.label)
                self.gap(item.label, f"Invalid debug-symbol packet: {error}")
                continue
            self._debug_symbols_by_target.setdefault(target_sha256, []).append(
                (item, companion_sha256, family, scope)
            )
        self._companions_by_sha256: dict[str, list[SuppliedCompanion]] = {}
        for companion in companions:
            self._companions_by_sha256.setdefault(sha256_data(companion.data), []).append(companion)
        self.graph_triage = graph_triage
        self._used_graph_triage: set[str] = set()
        self._graph_triage_by_target: dict[str, list[CapturedDocument]] = {}
        for item in graph_triage:
            try:
                target = graph_triage_target_sha256(item.raw)
            except ValueError as error:
                self._used_graph_triage.add(item.label)
                self.gap(item.label, f"Invalid graph-triage packet: {error}")
            else:
                self._graph_triage_by_target.setdefault(target, []).append(item)
        self.snapshots = snapshots
        self.artifacts: list[dict] = []
        self._by_path: dict[tuple[str, int], dict] = {}
        self.images: list[dict] = []
        self._images_by_label: dict[str, dict] = {}
        self.image_history_count = 0
        self.metadata_bytes = 0
        self.sidecars: set[str] = set()

    def gap(self, path: str, reason: str) -> None:
        self.gap_count += 1
        if len(self.gaps) < MAX_ANALYSIS_GAPS:
            self.gaps.append({"path": path, "reason": reason})

    def checkpoint(self) -> tuple[int, int, int, int, int, int]:
        return (
            len(self.artifacts),
            len(self.gaps),
            self.metadata_bytes,
            self.gap_count,
            len(self.images),
            self.image_history_count,
        )

    def rollback(self, checkpoint: tuple[int, int, int, int, int, int]) -> None:
        (
            artifacts,
            gaps,
            self.metadata_bytes,
            self.gap_count,
            images,
            self.image_history_count,
        ) = checkpoint
        del self.artifacts[artifacts:]
        self._by_path = {(item["path"], item["depth"]): item for item in self.artifacts}
        del self.gaps[gaps:]
        del self.images[images:]
        self._images_by_label = {item["label"]: item for item in self.images}

    def register_image(
        self,
        image_label: str,
        parent_label: str,
        depth: int,
        manifest: str,
        history: tuple[dict, ...],
    ) -> dict:
        """Register one virtual final image without inventing a file artifact identity."""
        parent = self._by_path.get((parent_label, depth))
        if parent is None:
            self.gap(image_label, "OCI image parent artifact is unavailable")
            namespace = "unresolved-image:" + image_label
            parent_id = None
        else:
            parent_id = parent["id"]
            namespace = (
                "image:"
                + hashlib.sha256(
                    (parent_id + "\0" + image_label + "\0" + manifest).encode(
                        "utf-8", errors="surrogatepass"
                    )
                ).hexdigest()
            )
        remaining = max(0, MAX_IMAGE_HISTORY - self.image_history_count)
        retained = tuple(history[:remaining])
        omitted = len(history) - len(retained)
        self.image_history_count += len(retained)
        if omitted:
            self.gap(image_label, "OCI image history retention limit reached")
        record = {
            "id": namespace,
            "label": image_label,
            "parent": parent_id,
            "member_depth": depth + 1,
            "manifest": manifest,
            "history": retained,
            "history_omitted": omitted,
        }
        self.images.append(record)
        self._images_by_label[image_label] = record
        return record

    def _scope(  # noqa: PLR0911 -- Each namespace boundary returns a complete scope.
        self, path: str, depth: int
    ) -> dict:
        images = [
            item
            for label, item in self._images_by_label.items()
            if depth == item["member_depth"] and path.startswith(label + "!")
        ]
        if images:
            image = max(images, key=lambda item: len(item["label"]))
            member = path[len(image["label"]) + 1 :]
            if "\\" in member or member.startswith("/") or ".." in member.split("/"):
                self.gap(path, "OCI image member path is unsafe; relationships omitted")
                return {
                    "namespace": "unresolved:" + path,
                    "logical_path": path,
                    "boundary": "/",
                    "deployment_root": False,
                }
            return {
                "namespace": image["id"],
                "logical_path": "/" + member,
                "boundary": "/",
                "deployment_root": True,
            }
        if depth:
            parents = [
                self._by_path[(path[:index], depth - 1)]
                for index, char in enumerate(path)
                if char == "!" and (path[:index], depth - 1) in self._by_path
            ]
            if not parents:
                return {
                    "namespace": "unresolved:" + path,
                    "logical_path": path,
                    "boundary": "/",
                    "deployment_root": False,
                }
            parent = max(parents, key=lambda item: len(item["path"]))
            member = path[len(parent["path"]) + 1 :]
            if "\\" in member or member.startswith("/") or ".." in member.split("/"):
                self.gap(path, "Archive relation path is unsafe; relationships omitted")
                return {
                    "namespace": "unresolved:" + path,
                    "logical_path": path,
                    "boundary": "/",
                    "deployment_root": False,
                }
            return {
                "namespace": parent["id"],
                "logical_path": "/" + member,
                "boundary": "/",
                "deployment_root": True,
            }
        for root in sorted(self.deployment_roots, key=len, reverse=True):
            if path == root or path.startswith(root.rstrip("/") + "/"):
                return {
                    "namespace": "deployment:" + root,
                    "logical_path": "/" + path[len(root) :].lstrip("/"),
                    "boundary": "/",
                    "deployment_root": True,
                }
        boundaries = [root for root in self.roots if path.startswith(root.rstrip("/") + "/")]
        return {
            "namespace": "filesystem",
            "logical_path": path,
            "boundary": max(boundaries, key=len) if boundaries else posixpath.dirname(path),
            "deployment_root": False,
        }

    def record(self, data: Buffer, path: str, sha256: str, depth: int) -> dict:
        scope = self._scope(path, depth)
        identifier = (
            "artifact:"
            + hashlib.sha256(
                (scope["namespace"] + "\0" + path + "\0" + sha256).encode(
                    "utf-8", errors="surrogatepass"
                )
            ).hexdigest()
        )
        record = {
            "id": identifier,
            "path": path,
            "sha256": sha256,
            "size_bytes": len(data),
            "depth": depth,
            **scope,
        }
        if data.startswith(b"\x7fELF"):
            record["loader"] = elf_dependencies(data)
            for reason in record["loader"]["gaps"]:
                self.gap(path, reason)
        elif data.startswith(
            (
                b"MZ",
                b"\0asm",
                b"\xfe\xed",
                b"\xce\xfa",
                b"\xcf\xfa",
                b"\xca\xfe",
                b"\xbe\xba",
                b"\xbf\xba",
            )
        ):
            record["layout"] = inspect_layout(data)
        self._record_metadata(data, record)
        if record["deployment_root"]:
            record["_hashes"] = _hashes(data, sha256)
        self.artifacts.append(record)
        self._by_path[(path, depth)] = record
        return record

    def _record_metadata(self, data: Buffer, record: dict) -> None:
        path = record["path"]
        name = Path(path).name.lower()
        logical = record["logical_path"]
        metadata = (
            path in self.sidecars
            or name.endswith((".cdx.json", ".spdx.json"))
            or name in {"bom.json", "sbom.json"}
        )
        package_metadata = record["deployment_root"] and (
            logical in {"/var/lib/dpkg/status", "/lib/apk/db/installed", "/etc/os-release"}
            or (
                logical.startswith("/var/lib/dpkg/info/")
                and logical.endswith((".list", ".md5sums"))
            )
        )
        if metadata or package_metadata:
            if self.metadata_bytes + len(data) > MAX_METADATA_BYTES:
                self.gap(path, "Structured metadata cumulative byte budget exceeded")
            else:
                raw = data[:]
                self.metadata_bytes += len(raw)
                if metadata:
                    try:
                        record["provenance"] = asdict(
                            parse_provenance_json(raw.decode("utf-8"), path)
                        )
                        for reason in record["provenance"]["gaps"]:
                            self.gap(path, reason)
                    except ValueError as error:
                        self.gap(path, str(error))
                if package_metadata:
                    record["_metadata"] = raw

    def enrich(  # noqa: C901 -- Independent evidence enrichments remain ordered.
        self, data: Buffer, path: str, assessment: dict
    ) -> dict:
        record = next((item for item in reversed(self.artifacts) if item["path"] == path), None)
        if record is None:
            return {}
        result = {"artifact_id": record["id"]}
        if "loader" in record:
            result["loader"] = record["loader"]
        if "layout" in record:
            result["layout"] = record["layout"]
        if (
            self.xrefs
            and data.startswith(b"\x7fELF")
            and (
                assessment.get("detection_status")
                not in {None, "not_detected", "name_or_string_only", "decoder_import_detected"}
                or record["sha256"] in self._graph_triage_by_target
            )
        ):
            try:
                instructions = self._graph_packet(data, record)
                graph = build_elf_graph(
                    data, seeds_from_assessment(assessment), instructions
                ).as_dict()
                result["function_graph"] = graph
                for gap in graph["gaps"]:
                    self.gap(path, gap["reason"])
            except ValueError as error:
                self.gap(path, f"Function graph incomplete: {error}")
        symbol_exports = self._symbol_exports(data, record, path)
        result.update(symbol_exports)
        mach_export_route = record.get("layout", {}).get("kind") in {
            "mach_o",
            "mach_o_universal",
        } and any(
            family == "mach"
            for _, _, family, _ in self._debug_symbols_by_target.get(record["sha256"], [])
        )
        if mach_export_route:
            self._mach_export_coverage(data, path, symbol_exports.get("mach_symbol_exports", []))
        elif self.companions and ("loader" in record or "layout" in record):
            debug = verify_debug_companions(data, self.companions).as_dict()
            result["debug_companions"] = debug
            for gap in debug["gaps"]:
                self.gap(path, gap["reason"])
        record["analysis"] = result
        return result

    def _mach_export_coverage(self, data: Buffer, path: str, exports: list[dict]) -> None:
        try:
            expected = expected_mach_export_scopes(data)
        except ValueError as error:
            self.gap(path, f"Mach debug slice coverage unresolved: {error}")
            return
        verified = {item["scope"] for item in exports if item["status"] == "verified"}
        for scope in expected:
            if scope not in verified:
                self.gap(path, f"Mach debug export missing for target slice {scope}")

    def _graph_packet(self, data: Buffer, record: dict) -> InstructionPacket | None:
        selected = self._graph_triage_by_target.get(record["sha256"], [])
        self._used_graph_triage.update(item.label for item in selected)
        if len(selected) > 1:
            message = (
                "Multiple graph-triage packets match one artifact; combine ranges in one triage run"
            )
            raise ValueError(message)
        return instruction_packet_from_triage(data, selected[0].raw) if selected else None

    def _symbol_exports(self, data: Buffer, record: dict, path: str) -> dict:
        results: dict[str, list[dict]] = {}
        selected = self._debug_symbols_by_target.get(record["sha256"], [])
        populations: dict[tuple[str, str], int] = {}
        for _, _, family, scope in selected:
            populations[(family, scope)] = populations.get((family, scope), 0) + 1
        for item, companion_sha256, family, scope in selected:
            self._used_debug_symbol_exports.add(item.label)
            if populations[(family, scope)] != 1:
                self.gap(path, "Multiple debug-symbol packets match one artifact slice")
                continue
            companions = self._companions_by_sha256.get(companion_sha256, [])
            if len(companions) != 1:
                self.gap(
                    item.label,
                    "Debug-symbol packet requires exactly one hash-matched supplied companion",
                )
                continue
            verifier = verify_pdb_symbol_export if family == "pdb" else verify_mach_debug_export
            verified = verifier(data, companions[0].data, item.raw).as_dict()
            key = "pdb_symbol_exports" if family == "pdb" else "mach_symbol_exports"
            results.setdefault(key, []).append(
                {"label": item.label, "companion": companions[0].label, "scope": scope, **verified}
            )
            for gap in verified["gaps"]:
                self.gap(item.label, gap["reason"])
        return results

    def finish(self) -> dict:
        for item in self.graph_triage:
            if item.label not in self._used_graph_triage:
                self.gap(item.label, "Graph-triage packet matched no analyzed ELF artifact")
        for item in self.debug_symbol_exports:
            if item.label not in self._used_debug_symbol_exports:
                self.gap(item.label, "Debug-symbol packet matched no supplied artifact")
        graph = provider_graph(self.artifacts)
        for gap in graph["gaps"]:
            self.gap("<providers>", gap)
        relations = list(graph["edges"])
        relations = self._sbom_relations(relations)
        packages, ownership, assertions = self._packages()
        return {
            "artifacts": [
                {key: value for key, value in item.items() if not key.startswith("_")}
                for item in self.artifacts
            ],
            "images": self.images,
            "relations": relations,
            "packages": packages,
            "ownership": ownership,
            "vendor_assertions": assertions,
            "gaps": self.gaps,
            "gap_details_omitted": self.gap_count - len(self.gaps),
        }

    def _sbom_relations(self, relations: list[dict]) -> list[dict]:
        by_hash: dict[str, list[str]] = {}
        for artifact in self.artifacts:
            by_hash.setdefault(artifact["sha256"], []).append(artifact["id"])
        for artifact in self.artifacts:
            for component in artifact.get("provenance", {}).get("components", []):
                for checksum in component["hashes"]:
                    if checksum["algorithm"] == "SHA-256":
                        for target in by_hash.get(checksum["value"], []):
                            relations.append(
                                {
                                    "source": artifact["id"],
                                    "component": component["identifier"],
                                    "target": target,
                                    "kind": "artifact_hash_bound",
                                }
                            )
                            if len(relations) > MAX_RELATIONS:
                                self.gap("<relations>", "Relationship budget exceeded")
                                return relations[:MAX_RELATIONS]
        return relations

    @staticmethod
    def _package_databases(metadata: dict) -> list:
        databases = []
        if "/var/lib/dpkg/status" in metadata:
            infos = tuple(
                MetadataRecord(path, item["_metadata"])
                for path, item in metadata.items()
                if path.startswith("/var/lib/dpkg/info/")
            )
            databases.append(
                parse_dpkg_database(metadata["/var/lib/dpkg/status"]["_metadata"], infos)
            )
        if "/lib/apk/db/installed" in metadata:
            databases.append(parse_apk_database(metadata["/lib/apk/db/installed"]["_metadata"]))
        return databases

    def register_package_archive(self, path: str, metadata: dict) -> None:
        record = next((item for item in reversed(self.artifacts) if item["path"] == path), None)
        if record is None:
            message = "Package archive must be recorded before ownership registration"
            raise ValueError(message)
        try:
            record["_package"] = package_from_rpm_metadata(metadata)
        except ValueError as error:
            self.gap(path, str(error))

    def _package_namespaces(self) -> tuple[dict[str, list[dict]], dict[str, PackageDatabase]]:
        members_by_namespace: dict[str, list[dict]] = {}
        archive_packages: dict[str, PackageDatabase] = {}
        for artifact in self.artifacts:
            members_by_namespace.setdefault(artifact["namespace"], []).append(artifact)
            if "_package" in artifact:
                archive_packages[artifact["id"]] = PackageDatabase(
                    (artifact["_package"],), (), limited=False
                )
        return members_by_namespace, archive_packages

    def _packages(  # noqa: C901 -- Namespace-local ownership and advisory joins.
        self,
    ) -> tuple[list, list, list]:
        packages, ownership, assertions = [], [], []
        members_by_namespace, archive_packages = self._package_namespaces()
        for namespace, members in sorted(members_by_namespace.items()):
            metadata = {item["logical_path"]: item for item in members if "_metadata" in item}
            databases = self._package_databases(metadata)
            if namespace in archive_packages:
                databases.append(archive_packages[namespace])
            os_release = (
                metadata.get("/etc/os-release", {})
                .get("_metadata", b"")
                .decode("utf-8", errors="replace")
            )
            release = dict(
                line.split("=", 1)
                for line in os_release.splitlines()
                if "=" in line and not line.startswith("#")
            )
            vendor = release.get("ID", "").strip('"')
            version = release.get("VERSION_ID", "").strip('"')
            for database in databases:
                ownership_index = build_ownership_index(database)
                packages.extend(
                    {"namespace": namespace, **asdict(package)} for package in database.packages
                )
                for gap in database.gaps:
                    self.gap(namespace, gap)
                for artifact in members:
                    if "_hashes" not in artifact:
                        continue
                    matched = resolve_ownership_hashes(
                        artifact["logical_path"],
                        artifact["_hashes"],
                        database,
                        index=ownership_index,
                    )
                    if matched.matches:
                        ownership.append({"artifact": artifact["id"], **asdict(matched)})
                        for gap in matched.gaps:
                            self.gap(artifact["path"], gap)
                assertions.extend(self._vendor_assertions(namespace, database, vendor, version))
        return packages, ownership, assertions

    def _vendor_assertions(
        self, namespace: str, database: PackageDatabase, vendor: str, version: str
    ) -> list:
        assertions = []
        expected_vendor = "redhat" if vendor in {"rhel", "redhat"} else vendor
        for snapshot in self.snapshots:
            if snapshot.vendor != expected_vendor or snapshot.release != version:
                self.gap(
                    namespace,
                    "Vendor snapshot does not match supplied root OS identity",
                )
                continue
            for package in database.packages:
                assertions.extend(
                    {"namespace": namespace, **asdict(item)}
                    for item in assess_vendor_assertions(package, snapshot)
                )
        return assertions


def add_analysis_arguments(parser: argparse.ArgumentParser) -> None:
    for flag, help_text in (
        ("--graph-triage", "hash-bound bounded objdump report from brotli_binary_triage.py"),
        ("--sigstore-bundle", "captured offline Sigstore bundle for a scanned artifact"),
        ("--jsf", "signed CycloneDX JSF document"),
    ):
        parser.add_argument(flag, action="append", default=[], type=Path, help=help_text)
    for flag, help_text in (
        ("--sigstore-trust-config", "captured local Sigstore ClientTrustConfig"),
        ("--sigstore-policy", "explicit certificate identity, issuer, and freshness policy"),
        ("--sigstore-verifier", "absolute isolated maintained Sigstore executable"),
        ("--jsf-policy", "pinned JSF keys and explicit freshness policy"),
    ):
        parser.add_argument(flag, type=Path, help=help_text)
    parser.add_argument(
        "--runtime-trace",
        action="append",
        default=[],
        type=Path,
        help="explicit deployment observations bound to exact artifact paths/hashes",
    )
    parser.add_argument(
        "--attestation",
        action="append",
        default=[],
        type=Path,
        help="local DSSE/in-toto attestation; requires explicit trust policy",
    )
    parser.add_argument(
        "--attestation-policy",
        type=Path,
        help="local pinned Ed25519 keys, threshold, and allowed predicates",
    )
    parser.add_argument(
        "--no-xrefs", action="store_true", help="disable function graph decoding explicitly"
    )
    parser.add_argument(
        "--deployment-root",
        action="append",
        default=[],
        type=Path,
        help="supplied filesystem root for isolated provider/package relationships",
    )
    parser.add_argument(
        "--debug-file",
        action="append",
        default=[],
        type=Path,
        help="explicit debug companion; identity must match before use",
    )
    parser.add_argument(
        "--debug-symbols",
        action="append",
        default=[],
        type=Path,
        help="hash-bound PDB or per-slice Mach dSYM symbol packet",
    )
    parser.add_argument(
        "--sbom",
        action="append",
        default=[],
        type=Path,
        help="supplied CycloneDX/SPDX JSON sidecar",
    )
    parser.add_argument(
        "--vendor-snapshot",
        action="append",
        default=[],
        type=Path,
        help="local dated vendor assertion snapshot; never fetched implicitly",
    )


def _runtime_observations(
    inventory: Inventory,
    args: argparse.Namespace,
    result: dict,
    documents: tuple[CapturedDocument, ...] | None,
) -> None:
    if documents is None:
        documents = tuple(capture_document(path) for path in getattr(args, "runtime_trace", []))
    traces, gaps = inspect_runtime_traces(documents, result["artifacts"])
    result["runtime_observations"] = traces
    for gap in gaps:
        inventory.gap(gap["path"], gap["reason"])


def _trust_observations(
    inventory: Inventory, args: argparse.Namespace, result: dict, inputs: TrustInputs | None
) -> None:
    if inputs is None:
        inputs = capture_trust_arguments(args)
    records, gaps = inspect_trust_inputs(inputs, result["artifacts"])
    result["authenticated_provenance"] = records
    for gap in gaps:
        inventory.gap(gap["path"], gap["reason"])


def scan_with_analysis(  # noqa: PLR0913 -- Independently captured evidence populations.
    inventory: Inventory,
    roots: list[Path],
    args: argparse.Namespace,
    *,
    attestation_inputs: AttestationInputs | None = None,
    debug_symbol_inputs: tuple[CapturedDocument, ...] | None = None,
    runtime_trace_inputs: tuple[CapturedDocument, ...] | None = None,
    trust_inputs: TrustInputs | None = None,
    graph_triage_inputs: tuple[CapturedDocument, ...] | None = None,
) -> dict:
    """Keep supplied companion descriptors stable for the entire scan."""
    roots = list(dict.fromkeys(roots))
    with ExitStack() as stack:
        companions = []
        for path in args.debug_file:
            stream = stack.enter_context(path.expanduser().open("rb"))
            data = stack.enter_context(file_data(stream, None))
            companions.append(SuppliedCompanion(str(path), data))
        snapshots = []
        for path in args.vendor_snapshot:
            with path.expanduser().open("rb") as stream:
                raw = stream.read(MAX_METADATA_BYTES + 1)
            if len(raw) > MAX_METADATA_BYTES:
                message = "Vendor snapshot exceeds metadata byte budget"
                raise ValueError(message)
            snapshots.append(load_vendor_snapshot(raw.decode("utf-8")))
        if debug_symbol_inputs is None:
            debug_symbol_inputs = tuple(
                capture_document(path) for path in getattr(args, "debug_symbols", [])
            )
        session = AnalysisSession(
            roots,
            deployment_roots=[p.expanduser().absolute() for p in args.deployment_root],
            xrefs=not args.no_xrefs,
            companions=tuple(companions),
            debug_symbol_exports=debug_symbol_inputs,
            snapshots=tuple(snapshots),
            graph_triage=graph_triage_inputs
            if graph_triage_inputs is not None
            else tuple(capture_document(path) for path in getattr(args, "graph_triage", [])),
        )
        session.sidecars = {str(path.expanduser().absolute()) for path in args.sbom}
        inventory.analysis = session
        inventory.scan_roots(roots)
        result = session.finish()
        if attestation_inputs is None:
            attestation_inputs = capture_attestation_inputs(
                getattr(args, "attestation", []), getattr(args, "attestation_policy", None)
            )
        attestations, attestation_gaps = inspect_captured_attestations(
            attestation_inputs, result["artifacts"]
        )
        result["attestations"] = attestations
        _runtime_observations(inventory, args, result, runtime_trace_inputs)
        _trust_observations(inventory, args, result, trust_inputs)
        for gap in attestation_gaps:
            inventory.gap(gap["path"], gap["reason"])
        for gap in result.pop("gaps"):
            inventory.gap(gap["path"], gap["reason"])
        inventory.gap_count += result["gap_details_omitted"]
        result["analysis_configuration"] = {
            "xrefs": session.xrefs,
            "deployment_roots": session.deployment_roots,
            "debug_files": [str(path) for path in args.debug_file],
            "debug_symbols": [item.label for item in debug_symbol_inputs],
            "sboms": sorted(session.sidecars),
            "vendor_snapshots": [str(path) for path in args.vendor_snapshot],
        }
        return result
