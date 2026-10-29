"""Durable scan queue. Uses a separate SQLite database; no customer schema migration."""
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = ('queued', 'running', 'retry_wait')
TERMINAL = ('completed', 'failed', 'cancelled', 'timed_out')

class Queue:
    def __init__(self, path=None):
        self.path = str(path or os.getenv('SCAN_JOBS_DATABASE', ROOT / 'scan_jobs.db'))
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY, project_id INTEGER NOT NULL,
                    model_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2, created REAL NOT NULL,
                    updated REAL NOT NULL, available REAL NOT NULL,
                    heartbeat REAL, started REAL, finished REAL,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    pid INTEGER, pid_created REAL, exit_code INTEGER,
                    error TEXT, progress TEXT NOT NULL DEFAULT 'Waiting for worker'
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_scan_per_project
                ON scan_jobs(project_id) WHERE state IN ('queued','running','retry_wait');
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=15000')
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def enqueue(self, project_id, model_id, owner_id):
        if any(type(v) is not int or v <= 0 for v in (project_id, model_id, owner_id)):
            raise ValueError('Project, model and owner IDs must be positive integers')
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM scan_jobs WHERE project_id=? AND state IN ('queued','running','retry_wait')", (project_id,)).fetchone()
            if row:
                return dict(row), False
            job_id = uuid.uuid4().hex
            db.execute('INSERT INTO scan_jobs (id,project_id,model_id,owner_id,created,updated,available) VALUES (?,?,?,?,?,?,?)',
                       (job_id, project_id, model_id, owner_id, now, now, now))
            return dict(db.execute('SELECT * FROM scan_jobs WHERE id=?', (job_id,)).fetchone()), True

    def claim(self):
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM scan_jobs WHERE state IN ('queued','retry_wait') AND available<=? ORDER BY created LIMIT 1", (now,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE scan_jobs SET state='running',attempts=attempts+1,started=?,updated=?,heartbeat=?,progress='Starting scan',error=NULL WHERE id=?", (now, now, now, row['id']))
            return dict(db.execute('SELECT * FROM scan_jobs WHERE id=?', (row['id'],)).fetchone())

    def get(self, job_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM scan_jobs WHERE id=?', (job_id,)).fetchone()
            return dict(row) if row else None

    def list(self, project_id, limit=10):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM scan_jobs WHERE project_id=? ORDER BY created DESC LIMIT ?', (project_id, limit))]

    def update(self, job_id, **fields):
        allowed = {'state','heartbeat','started','finished','pid','pid_created','exit_code','error','progress','available'}
        if not fields or not set(fields) <= allowed:
            raise ValueError('Invalid job update')
        fields['updated'] = time.time()
        with self.connect() as db:
            db.execute('UPDATE scan_jobs SET ' + ','.join(k+'=?' for k in fields) + ' WHERE id=?', (*fields.values(), job_id))

    def cancel(self, job_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM scan_jobs WHERE id=?', (job_id,)).fetchone()
            if row and row['state'] in ACTIVE:
                now = time.time()
                if row['state'] == 'running':
                    db.execute('UPDATE scan_jobs SET cancel_requested=1,updated=? WHERE id=?', (now, job_id))
                else:
                    db.execute("UPDATE scan_jobs SET state='cancelled',cancel_requested=1,finished=?,updated=?,progress='Cancelled' WHERE id=?", (now, now, job_id))
            return self.get_after_connection(db, job_id)

    @staticmethod
    def get_after_connection(db, job_id):
        row = db.execute('SELECT * FROM scan_jobs WHERE id=?', (job_id,)).fetchone()
        return dict(row) if row else None

    def resolve(self, job_id, exit_code, *, cancelled=False, timed_out=False, interrupted=False):
        job = self.get(job_id)
        now = time.time()
        if cancelled or job['cancel_requested']:
            state, message = 'cancelled', 'Cancelled by user'
        elif timed_out:
            state, message = 'timed_out', 'Scan exceeded the configured time limit'
        elif interrupted or exit_code == 75:
            if job['attempts'] < job['max_attempts']:
                self.update(job_id, state='retry_wait', pid=None, pid_created=None, exit_code=exit_code,
                            error='Worker interrupted' if interrupted else 'Temporary provider failure',
                            available=now + min(60 * max(job['attempts'],1), 300), progress='Waiting to retry')
                return
            state, message = 'failed', 'Retry limit reached; review provider connection and scan logs'
        elif exit_code == 0:
            state, message = 'completed', 'Scan completed'
        else:
            state, message = 'failed', 'Scan failed; check the model connection and scan logs'
        self.update(job_id, state=state, finished=now, exit_code=exit_code,
                    pid=None, pid_created=None, error=None if state=='completed' else message, progress=message)


def public_job(job):
    """No process details, paths, credentials or log contents in the API."""
    return {k: job[k] for k in ('id','project_id','model_id','state','attempts','max_attempts',
                               'created','updated','started','finished','heartbeat','progress','error','cancel_requested')}
