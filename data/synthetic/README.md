# Northstar synthetic FHIR R4 dataset

`fhir-r4/bundle.json` is the canonical synthetic-only dataset for the Polaris simulation. It is
controlled as Northstar Restricted Health Data even though it contains no real patient data.

The pipeline pins Synthea v4.0.0, its JAR checksum, a Java 17 container digest, generation seeds,
dates, configuration, transformation code, and the HAPI interoperability image in
`toolchain-lock.json`. Raw Synthea output and the JAR live under ignored `artifacts/runtime/` paths.

From a clean Docker-enabled environment:

```bash
make synthea-pull
make synthea-tool
make synthea-generate
make synthea-reproduce
make synthetic-data-build
make synthetic-data-verify
```

Generation is network-disabled, non-root, read-only except for its output mount, capability-free,
resource-bounded, and refuses to overwrite a non-empty output directory. The transform admits only
three valid source Patient IDs/hashes, then replaces identifiers and direct-contact fields with the
approved Northstar minimum dataset. `synthea-reproduce` performs two fresh runs and requires both to
match the canonical raw FHIR files byte-for-byte.

Never place production exports, real demographics, PHI/PII, credentials, or user-supplied clinical
records in this pipeline. A dataset change requires provenance review, safety/privacy impact review,
test refresh, and a new gate record.
