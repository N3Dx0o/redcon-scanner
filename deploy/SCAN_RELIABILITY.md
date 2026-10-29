# Durable scan jobs

Manual project scans and scheduled scans enter `scan_jobs.db`. A single
`scanner-worker.service` worker runs one at a time, independently of Gunicorn.

- One active job per project, enforced transactionally in SQLite.
- Two attempts maximum. HTTP 408/429/502/503/504 and known connection/timeouts
  can retry after backoff; authentication, credit, validation and code failures
  do not automatically retry.
- On worker restart, orphan child processes are identified using PID creation
  time, terminated, and interrupted jobs requeued within the attempt limit.
  Recovery starts the scan again; it does not resume the AI reasoning state.
- Repeated SDK payment/authentication errors stop promptly even if the AI
  library swallows them. Temporary failures receive a 30-second recovery grace
  period, reset by successful agent progress, so historical errors cannot cancel
  a recovered scan. Logs stop at 128 MB per job.
- Each job has its own append-only log in `logs/jobs/<job-id>.log`.
- The project page displays queue state, attempts and target counts. It never
  invents a percentage for AI analysis. Cancellation terminates the process group.
- Default timeout: two hours, adjustable using SCAN_JOB_TIMEOUT_SECONDS.
- Queue status and cancellation require login/project ownership; cancellation
  retains Flask-WTF CSRF protection. Model ownership and spending limits are
  checked at enqueue and again at execution.
- Old scans started before this deployment remain detectable and block duplicate
  launch. Validation/fact gathering still use their existing launch paths.

Testing:
`venv/bin/python -m unittest discover -s tests -v`

Deploy the supplied worker unit, initialize the queue as www-data, enable the
worker, and restart scanner.service. Back up the source and SQLite database
using sqlite3.Connection.backup before deployment. Do not restore an old customer
database when rolling back code: stop worker, preserve queue/logs, restore source.

## Remaining upgrade sequence

1. Durable project scan lifecycle: this change.
2. Evidence requirements, measured finding quality and deduplication.
3. Independent review with disagreements visible.
4. Static analyzers, dependency and secret checks in isolated execution.
5. Provider controls beyond the existing LarpRouter support.
6. Complete workspace isolation and encrypted provider credentials.
7. Pull-request scans and baseline comparison.
8. Reports with evidence/provenance/review status.

Passing tests are evidence for covered behavior, not proof that a program has no
bugs. Large-project behavior and provider limits need continued observation.
