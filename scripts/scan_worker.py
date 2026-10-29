#!/usr/bin/env python3
"""Single durable scan worker. Run under systemd with KillMode=control-group."""
import fcntl
import logging
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils.scan_jobs import Queue

log = logging.getLogger('scan_worker')


def validate_job(job):
    from utils.flask_helpers import get_orm_instance
    from db.models import Project, AIModel, User
    with get_orm_instance().get_session() as session:
        project = session.query(Project).filter_by(id=job['project_id']).first()
        model = session.query(AIModel).filter_by(id=job['model_id']).first()
        user = session.query(User).filter_by(id=job['owner_id']).first()
        if not project or not model or not user:
            raise ValueError('Project, model or user no longer exists')
        if not user.is_admin and project.owner_id != user.id:
            raise ValueError('Project access was revoked')
        if not user.is_admin and model.owner_id != user.id:
            raise ValueError('AI model access was revoked')
        if float(project.cost or 0) >= float(project.max_cost if project.max_cost is not None else 50):
            raise ValueError('Project spending limit reached')


def kill_recorded(job):
    """PID creation time prevents signaling a reused unrelated PID after a restart."""
    import psutil
    if not job.get('pid') or not job.get('pid_created'):
        return
    try:
        proc = psutil.Process(job['pid'])
        if abs(proc.create_time() - job['pid_created']) < .01:
            os.killpg(proc.pid, signal.SIGKILL)
    except (psutil.NoSuchProcess, ProcessLookupError):
        pass


def recover(queue):
    with queue.connect() as db:
        jobs = [dict(r) for r in db.execute("SELECT * FROM scan_jobs WHERE state='running'")]
    for job in jobs:
        kill_recorded(job)
        queue.resolve(job['id'], None, interrupted=True)


def provider_failure(text):
    """Detect repeated SDK failures even when an agent library swallows them."""
    for status, message in (
        (402, 'Provider rejected the request: insufficient account credit'),
        (401, 'Provider authentication failed; update the API key'),
        (403, 'Provider denied access to this model'),
        (404, 'Provider could not find the selected model'),
        (429, 'Provider rate limit reached'),
        (503, 'Provider is temporarily unavailable'),
        (502, 'Provider gateway failure'),
        (504, 'Provider request timed out'),
    ):
        if len(re.findall(r'Error code: ?' + str(status) + r'\b', text)) >= 2:
            return (75 if status in (429,502,503,504) else 1), message
    return None


def execute(queue, job, *, command=None, validate=validate_job, timeout=7200, poll=1):
    """Run in a process group; cancellation, timeout and shutdown terminate descendants."""
    proc = None
    try:
        validate(job)
        logs = ROOT / 'logs' / 'jobs'
        logs.mkdir(parents=True, exist_ok=True)
        path = logs / (job['id'] + '.log')
        cmd = command or [sys.executable, '-u', str(ROOT/'run_scan.py'), '--project-id', str(job['project_id']), '--model-id', str(job['model_id'])]
        with path.open('ab') as output:
            output.write(('\nAttempt %s\n' % job['attempts']).encode())
            output.flush()
            proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            import psutil
            created = psutil.Process(proc.pid).create_time()
            queue.update(job['id'], pid=proc.pid, pid_created=created, progress='Analyzing source code')
            began = time.monotonic()
            cancelled = timed_out = False
            failure = None
            while proc.poll() is None:
                current = queue.get(job['id'])
                cancelled = bool(current['cancel_requested'])
                timed_out = time.monotonic() - began >= timeout
                if cancelled or timed_out:
                    break
                # Report phases/target counts, never pretend to know an AI percentage.
                with path.open('rb') as stream:
                    stream.seek(max(0, path.stat().st_size - 8192))
                    text = stream.read().decode('utf-8', 'replace').rsplit('Attempt ', 1)[-1]
                failure = provider_failure(text)
                if path.stat().st_size >= 128 * 1024 * 1024:
                    failure = (1, 'Scan stopped because its diagnostic log exceeded 128 MB')
                if failure:
                    break
                matches = re.findall(r'PROCESSING TARGET (\d+)/(\d+)', text)
                progress = 'Analyzing target %s of %s' % matches[-1] if matches else 'Analyzing source code'
                queue.update(job['id'], heartbeat=time.time(), progress=progress)
                time.sleep(poll)
            if cancelled or timed_out or failure:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
            queue.resolve(job['id'], failure[0] if failure else code, cancelled=cancelled, timed_out=timed_out)
            if failure and not cancelled and not timed_out:
                state = queue.get(job['id'])['state']
                queue.update(job['id'], error=failure[1], progress=('Waiting to retry: ' if state == 'retry_wait' else '') + failure[1])
    except BaseException as exc:
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            queue.resolve(job['id'], None, interrupted=True)
            raise
        log.exception('Job %s failed', job['id'])
        queue.resolve(job['id'], 1)
        if isinstance(exc, ValueError):
            queue.update(job['id'], error=str(exc), progress=str(exc))
    finally:
        # Terminate any MCP descendants that outlived the direct child.
        if proc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main():
    logging.basicConfig(level=logging.INFO)
    os.chdir(ROOT)
    os.umask(0o077)
    queue = Queue()
    with open(queue.path + '.worker.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        recover(queue)
        while True:
            job = queue.claim()
            if job:
                execute(queue, job, timeout=int(os.getenv('SCAN_JOB_TIMEOUT_SECONDS','7200')))
            else:
                time.sleep(1)

if __name__ == '__main__':
    main()
