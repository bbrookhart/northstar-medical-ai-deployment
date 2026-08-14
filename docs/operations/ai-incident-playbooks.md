# NS-OPS-004 — AI Incident Playbooks

**Status:** Written; **no playbook has been exercised**  
**Owners:** SOC on-call, SRE on-call, AI Security Lead, Clinical Safety Lead  
**Related:** REQ-OPS-003, REQ-OPS-004, REQ-OPS-005, CTL-OPS-002, CTL-OPS-003, BLK-005

## Standing rules

1. **Contain before you investigate.** The kill switches are independent for exactly this reason:
   disabling writes does not disable reads, and disabling the model does not disable the
   deterministic retrieval path clinicians use.
2. **Do not clear a control because a symptom stopped.** Every recovery has explicit exit criteria.
3. **Preserve the audit chain.** Never edit audit records. Export and verify the chain before and
   after any recovery step.
4. **No incident authorizes real PHI, a clinical decision, or bypassing approval.** If containment
   appears to require one of those, stop and escalate.

Each playbook names the detection that should raise it. If an incident is found another way, that
gap is itself a finding.

## PB-01 — Data disclosure

**Raised by:** `DET-006` (output withheld for secret or envelope disclosure), or a report.

1. Disable `MODEL` and `WRITE`. Reads may continue unless the disclosure came from retrieval.
2. Identify the correlation IDs and the corpus version from the audit events.
3. Determine what was disclosed and to whom. Do **not** copy the disclosed content into the ticket.
4. If a source document is implicated, roll the corpus back (`GD-02`) and open a poisoning incident.
5. Exit: the disclosure path is closed by a test that fails without the fix, the audit chain
   verifies, and Privacy has reviewed scope.

## PB-02 — Injection or agent compromise

**Raised by:** `DET-004` (fabricated citation or unknown tool request).

1. Disable `WRITE` first. The agent may keep answering while you determine scope.
2. Confirm whether any proposal was created; a proposal is not an execution, and neither is an
   approval. Check for executions explicitly.
3. Pull the run transcripts by `run_id`. They record state transitions, not model reasoning.
4. If the trigger is in retrieved content, treat it as poisoning (PB-03).
5. Exit: no proposal exists that a human did not independently approve, the injection case is added
   to the adversarial campaign, and the campaign passes.

## PB-03 — Corpus poisoning

**Raised by:** `DET-005` (corpus rolled back), an ingestion rejection spike, or PB-02.

1. Roll back to the last known-good corpus version. Rollback is an append, so the history of what
   served when is preserved.
2. Quarantine the candidate source. Its promotion record already states why it was admitted.
3. Re-run the retrieval evaluation. Security cases must be 100%.
4. Exit: the serving manifest checksum matches an approved version, the poisoned source is refused
   by a test, and the evaluation thresholds hold.

## PB-04 — Provider or model compromise

**Raised by:** provider advisory, `DET-009` (drift), or anomalous refusals.

1. Disable `MODEL`. The deterministic retrieval path stays available — this is the degraded mode
   `GD-03` exercises.
2. Record the model identity and system-contract digest from the AIBOM at the time of the incident.
3. Do not fail over to another provider. No second provider is approved (`BLK-004`).
4. Exit: provider integrity is confirmed or the provider is replaced through the vendor process, and
   the adversarial campaign is re-run against it.

## PB-05 — Unsafe output or action

**Raised by:** a clinician report, or `DET-003` (cross-scope proposals).

1. Disable `WRITE`. Notify Clinical Safety immediately — this is the only playbook with a standing
   clinical notification.
2. Identify whether anything executed. Approval and execution are separate records.
3. If clinical content was produced, treat the clinical-boundary control as failed and add the case
   to the safety suite.
4. Exit: Clinical Safety accepts the analysis, and a test reproduces the unsafe output and fails
   without the fix.

## PB-06 — Outage or dependency failure

**Raised by:** readiness failure, `DET-008` (budget halts), or `DET-009`.

1. Confirm the system is failing closed rather than serving stale state. Readiness requires state
   integrity and a valid audit chain.
2. Do not relax staleness or freshness bounds to restore service. That converts an availability
   incident into a correctness one.
3. If state is corrupt, restore from backup (`GD-05`) and verify the chain.
4. Exit: readiness passes on its own terms, and the restore is recorded with its measured duration.

## PB-07 — Supply-chain compromise

**Raised by:** an advisory, a Dependabot alert, or a release-policy blocker.

1. Freeze releases. The release policy already blocks unpinned inputs, so a failing gate is a signal,
   not an obstacle to remove.
2. Compare the SBOM and AIBOM against the last known-good versions. Both are committed, so the diff
   is a review artifact rather than a reconstruction.
3. Rebuild from pinned digests and verify the application starts and serves health.
4. Exit: the policy gate passes without exemptions, and the bills of materials are regenerated and
   reviewed.

## What these playbooks are not

None has been exercised. `NS-ASR-008` specifies the tabletop that would exercise them, and its
results table is empty. There is no on-call rotation, no paging integration, no SIEM, and no
dashboard — `NS-EXC-003` records that deferral. A written playbook is a plan, not an operational
capability.
