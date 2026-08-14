# ADR-001 — Deterministic Baseline Before Hosted Models

**Status:** Accepted  
**Date:** 2026-08-11

## Decision

The first vertical slice uses deterministic retrieval and orchestration. Security boundaries are
implemented and tested without an API key or stochastic model dependency.

## Consequences

Core invariants are reproducible, cheap to test, and attributable to trusted application code.
Model quality and model-specific threats remain open work and will be introduced behind an adapter.
