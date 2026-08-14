# ADR-002 — Provider-Neutral Model Boundary

**Status:** Accepted  
**Date:** 2026-08-11

## Decision

No model or cloud provider is selected in the foundation milestone. Future model access must use a
typed adapter with capability, data-use, regional, retention, safety, telemetry, and failure
contracts defined by Northstar.

## Consequences

Provider selection becomes an explicit risk and procurement decision. The application can compare,
test, disable, or roll back providers without moving authorization or execution into model code.
