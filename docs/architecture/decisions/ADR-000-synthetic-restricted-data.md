# ADR-000 — Synthetic Data Treated as Restricted Health Data

**Status:** Accepted  
**Date:** 2026-08-11

## Decision

Polaris uses synthetic data only. Northstar classifies that data internally as Restricted Health
Data and applies realistic access, purpose, sensitivity, minimization, logging, retention, and
incident controls to it.

## Consequences

The project can demonstrate healthcare controls without creating real privacy exposure. Synthetic
status must remain explicit so no one mistakes these controls for a HIPAA compliance determination.
