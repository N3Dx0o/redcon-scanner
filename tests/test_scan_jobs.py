"""Durability, concurrency, cancellation and process lifecycle regression tests."""
import concurrent.futures
import importlib.util
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from utils.scan_jobs import Queue, public_job
from scripts import scan_worker as worker


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.queue = Queue(pathlib.Path(self.tmp.name)/'queue.db')
        self.job, _ = self.queue.enqueue(1, 2, 3)

    def tearDown(self):
        self.tmp.cleanup()

    def test_persists_across_connections(self):
        self.assertEqual(Queue(self.queue.path).get(self.job['id'])['state'], 'queued')

    def test_concurrent_enqueue_is_unique(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            jobs = list(pool.map(lambda _: self.queue.enqueue(1, 2, 3), range(20)))
        self.assertEqual({j[0]['id'] for j in jobs}, {self.job['id']})
        self.assertEqual(len(self.queue.list(1)), 1)

    def test_concurrent_claim_only_once(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda _: self.queue.claim(), range(12)))
        self.assertEqual(sum(j is not None for j in claims), 1)

    def test_cancel_queued_job_never_claimed(self):
        self.queue.cancel(self.job['id'])
        self.assertIsNone(self.queue.claim())
        self.assertEqual(self.queue.get(self.job['id'])['state'], 'cancelled')

    def test_bounded_retry_and_backoff(self):
        job = self.queue.claim()
        self.queue.resolve(job['id'], 75)
        self.assertEqual(self.queue.get(job['id'])['state'], 'retry_wait')
        self.assertIsNone(self.queue.claim())
        self.queue.update(job['id'], available=0)
        job = self.queue.claim()
        self.queue.resolve(job['id'], 75)
        self.assertEqual(self.queue.get(job['id'])['state'], 'failed')

    def test_permanent_failure_no_retry(self):
        job = self.queue.claim()
        self.queue.resolve(job['id'], 1)
        self.assertEqual(self.queue.get(job['id'])['state'], 'failed')

    def test_restart_recovery_and_cancel_precedence(self):
        job = self.queue.claim()
        with patch.object(worker, 'kill_recorded'):
            worker.recover(self.queue)
        self.assertEqual(self.queue.get(job['id'])['state'], 'retry_wait')
        self.queue.update(job['id'], available=0)
        self.queue.claim()
        self.queue.cancel(job['id'])
        with patch.object(worker, 'kill_recorded'):
            worker.recover(self.queue)
        self.assertEqual(self.queue.get(job['id'])['state'], 'cancelled')

    def test_success_and_next_scan(self):
        job = self.queue.claim()
        self.queue.resolve(job['id'], 0)
        new, created = self.queue.enqueue(1, 2, 3)
        self.assertTrue(created)
        self.assertNotEqual(job['id'], new['id'])

    def test_reject_command_injection_ids(self):
        with self.assertRaises(ValueError):
            self.queue.enqueue('1; echo injected', 2, 3)

    def test_public_record_has_no_sensitive_fields(self):
        fields = public_job(self.job)
        self.assertNotIn('pid', fields)
        self.assertNotIn('pid_created', fields)

    def run_child(self, code, **kwargs):
        job = self.queue.claim()
        with patch.object(worker, 'ROOT', pathlib.Path(self.tmp.name)):
            worker.execute(self.queue, job, command=[sys.executable, '-u', '-c', code],
                           validate=lambda _: None, poll=.02, **kwargs)
        return self.queue.get(job['id'])

    def test_child_success_and_progress(self):
        job = self.run_child("print('PROCESSING TARGET 1/2'); import time; time.sleep(.1)")
        self.assertEqual(job['state'], 'completed')
        self.assertEqual(job['exit_code'], 0)
        self.assertIsNotNone(job['heartbeat'])

    def test_child_permanent_failure(self):
        self.assertEqual(self.run_child('raise SystemExit(1)')['state'], 'failed')

    def test_child_transient_retry(self):
        self.assertEqual(self.run_child('raise SystemExit(75)')['state'], 'retry_wait')

    def test_timeout_terminates_process(self):
        self.assertEqual(self.run_child('import time; time.sleep(30)', timeout=.1)['state'], 'timed_out')

    def test_running_cancellation(self):
        def cancel():
            for _ in range(100):
                if self.queue.get(self.job['id'])['pid']:
                    self.queue.cancel(self.job['id'])
                    return
                time.sleep(.02)
        thread = threading.Thread(target=cancel)
        thread.start()
        job = self.run_child('import time; time.sleep(30)')
        thread.join(timeout=3)
        self.assertEqual(job['state'], 'cancelled')

    def test_repeated_payment_error_fails_fast_without_retry(self):
        code = "print('openai.APIStatusError: Error code: 402 - insufficient_credit', flush=True); print('openai.APIStatusError: Error code: 402 - insufficient_credit', flush=True); import time; time.sleep(30)"
        job = self.run_child(code)
        self.assertEqual(job['state'], 'failed')
        self.assertIn('insufficient account credit', job['error'])

    def test_repeated_rate_limit_retries_with_bound(self):
        code = "print('Error code: 429', flush=True); print('Error code: 429', flush=True); import time; time.sleep(30)"
        job = self.run_child(code, transient_grace=.05)
        self.assertEqual(job['state'], 'retry_wait')
        self.assertIn('rate limit', job['error'])

    def test_recovered_provider_error_does_not_fail_successful_scan(self):
        code = "print('Error code: 503', flush=True); print('Error code: 503', flush=True); import time; time.sleep(.15); print('📊 [step 2] [usage cost=0.001]', flush=True); time.sleep(.1)"
        job = self.run_child(code, transient_grace=.2)
        self.assertEqual(job['state'], 'completed')

    def test_revalidation_failure_never_starts_child(self):
        job = self.queue.claim()
        def deny(_):
            raise ValueError('Project access was revoked')
        with patch.object(worker.subprocess, 'Popen') as popen:
            worker.execute(self.queue, job, validate=deny)
            popen.assert_not_called()
        self.assertEqual(self.queue.get(job['id'])['error'], 'Project access was revoked')

if __name__ == '__main__':
    unittest.main()

class RecoveryProcessTest(unittest.TestCase):
    def test_actual_worker_crash_kills_orphan_and_requeues(self):
        import os
        import signal
        import subprocess
        import psutil
        with tempfile.TemporaryDirectory() as directory:
            queue = Queue(pathlib.Path(directory)/'queue.db')
            job, _ = queue.enqueue(1,2,3)
            code = '''import pathlib, sys
from utils.scan_jobs import Queue
from scripts import scan_worker as w
w.ROOT = pathlib.Path(sys.argv[1])
q=Queue(sys.argv[2])
w.execute(q,q.claim(),command=[sys.executable,'-c','import time; time.sleep(30)'],validate=lambda _:None,poll=.02)
'''
            # pathlib imported below; this process acts like a crashed worker.
            process = subprocess.Popen([sys.executable,'-c',code,directory,queue.path])
            child_pid = None
            try:
                for _ in range(200):
                    current = queue.get(job['id'])
                    if current['pid']:
                        child_pid = current['pid']
                        break
                    time.sleep(.02)
                self.assertIsNotNone(child_pid)
                process.kill()
                process.wait(timeout=5)
                worker.recover(queue)
                self.assertEqual(queue.get(job['id'])['state'],'retry_wait')
                for _ in range(100):
                    if not psutil.pid_exists(child_pid) or psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE:
                        break
                    time.sleep(.02)
                else:
                    self.fail('Orphan process survived recovery')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if child_pid:
                    try:
                        os.killpg(child_pid,signal.SIGKILL)
                    except ProcessLookupError:
                        pass
