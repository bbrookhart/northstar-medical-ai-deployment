# Lab Safety Contract

Every learner accepts this before starting. An instructor who waives it has changed the course into
something else.

## Rules

1. **Synthetic targets only.** The labs attack this repository running on your own machine. You may
   not point any exercise at a third-party system, a colleague's machine, a cloud account, or any
   production service.
2. **No real data.** Do not add real patient data, real PHI, real credentials, or production secrets
   to any lab. The repository's own checks will fail the build if you do, and that is the cheap
   failure — the expensive one is the copy you made first.
3. **Generated credentials only.** Keys in `.env` are development values you generate locally. They
   are not shared, committed, or reused anywhere else.
4. **Offensive exercises have rules of engagement.** Each lab states its objective, its stop
   condition, and how to reset. Stop when the objective is met; the goal is understanding the
   control, not maximising damage.
5. **Report, do not exploit.** If a lab reveals a genuine weakness in the repository, open an issue
   describing it. Do not publish a working exploit against anything you do not own.
6. **No claims.** Completing the course does not make you, or any system you build, compliant,
   certified, cleared, or ready for production use. It makes you someone who has practised.

## Reset

Every lab resets with:

```bash
git checkout -- .
make verify
```

If `make verify` does not pass after a reset, stop and ask the instructor. A dirty baseline makes
every subsequent result meaningless.

## Instructor obligations

- Confirm every learner has an isolated environment before the first offensive lab.
- Do not answer for a control during an exercise. A learner who is told the answer has not tested it.
- Record which labs produced a genuine finding. A cohort that finds nothing is a signal about the
  labs, not about the learners.
