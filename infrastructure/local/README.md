# Local FHIR R4 interoperability lab

This lab runs the pinned HAPI FHIR JPA starter against an in-memory H2 database. It is a
disposable interoperability target, not an EHR, authorization server, production architecture,
or claim of FHIR/SMART/HIPAA conformance.

Security boundaries:

- binds only to `127.0.0.1:18080`;
- runs as the image's non-root user with a read-only root filesystem;
- drops Linux capabilities and enables `no-new-privileges`;
- uses a dedicated bridge network and no persistent data volume;
- restricts browser CORS to the loopback lab origin;
- disables subscriptions, clinical-reasoning hooks, MDM, MCP, OpenAPI, and Swagger UI;
- configures the bundled tester to refuse third-party URL fetches;
- contains only the repository's labeled synthetic dataset.

Docker Desktop requires a bridge network for the published loopback port, so the container is not
an egress-isolated workload. The loopback binding, disabled outbound-capable features, synthetic-
only data rule, and disposable lifecycle are compensating lab controls. A production design would
require network-policy-enforced default-deny egress.

The upstream HAPI starter does not provide enterprise authentication or security logging. Never
expose this service beyond loopback and never load real PHI, PII, credentials, or production
exports.

## Commands

```bash
make fhir-up
make fhir-seed
make fhir-integration
make fhir-down
```

`make fhir-seed` is idempotent and validates the committed dataset before writing its resources.
`make fhir-integration` runs the HTTP gateway and broker contract against the local server. The
normal `make verify` path does not require Docker.
