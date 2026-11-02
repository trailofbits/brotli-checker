# Supplied deployment observations

Use `--runtime-trace trace.json` with an explicitly supplied scan root. This is an
**evidence import**, not a target launcher, tracer, or host-loader simulation.
The scanner captures each packet once and includes its exact SHA-256 in the
reproducibility envelope. It binds both ends of every observation to exactly one
scanned artifact using namespace, logical path, and SHA-256 together. Identical
library bytes in another image or directory cannot satisfy the join.

A packet describes positive observations from a separately reviewed collector:

```json
{
  "schema_version": 1,
  "deployment": {
    "id": "cluster/pod-uid/process-start-identity",
    "namespace": "deployment:/absolute/extracted-image",
    "configuration_sha256": "<64 lowercase hex characters>"
  },
  "collector": "reviewed collector name/version and capture reference",
  "events": [{
    "kind": "symbol_binding",
    "source": {"logical_path": "/app/server", "sha256": "<sha256>"},
    "target": {"logical_path": "/lib/libbrotlidec.so", "sha256": "<sha256>"},
    "symbol": "BrotliDecoderDecompressStream",
    "observed_at": "2026-11-02T12:00:00Z"
  }]
}
```

Use the exact namespace and logical paths from the scanner's `artifacts` output;
OCI final images have isolated image namespaces. `configuration_sha256` identifies
the reviewed deployment configuration, but the scanner does not itself obtain or
verify that configuration. The deployment/process identity and timestamps scope
the claim; they are not proof of freshness. The packet has a closed schema so an
unsupported safety assertion cannot masquerade as an accepted field.

Supported event kinds are `symbol_binding` and `decoder_call`. A binding records
provider selection at that observation; a call records observed execution. A
loaded library, dependency declaration, or mapped page is neither. Do not convert
`/proc/maps`, `ldd`, or DT_NEEDED entries into either event. The scanner never runs
`ldd`, a target loader, or application code to collect these observations.

Output is under `runtime_observations`. `scope_status=artifact_identity_bound`
means identity joins succeeded, **not that a packet's observations were independently
verified**. Collector authenticity, call attribution, process/container identity,
and configuration must be checked by the analyst against the original trace.
Retain that trace and its capture method alongside the packet. The importer does
not authorize or establish trust in a collector merely because its name is present.

No observation changes patch state or the static provider candidate graph. A
single selected fixed provider does not clear another copy. A call does not prove
attacker-controlled input, CVE triggerability, or exploitability. Missing events
never prove unreachability. Negative/load-only events are rejected, and a malformed
or ambiguously bound event makes its entire packet a coverage gap rather than
accepting a partial success. Separate valid packets remain available.

Limits apply to supplied metadata, not target file sizes: 64 packets, 16 MiB per
captured document, and 10,000 events per packet. No packet path is opened as a
target or followed to obtain additional artifacts.
