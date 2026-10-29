"""HTTP authorization/CSRF/validation checks without production data or API calls."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import tempfile
import unittest
from flask import Flask
from flask_login import LoginManager, UserMixin
from flask_wtf.csrf import CSRFProtect, generate_csrf
from db.models import Project, AIModel
from routes import projects_bp
import routes.projects as routes
from utils.scan_jobs import Queue

class User(UserMixin):
    id = 7
    is_admin = False

class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.queue = Queue(Path(self.tmp.name)/'jobs.db')
        self.project = SimpleNamespace(id=1, owner_id=7, cost=0, max_cost=10)
        self.model = SimpleNamespace(id=2, owner_id=7)
        session = MagicMock()
        session.query.side_effect = lambda entity: self.query(self.project if entity is Project else self.model)
        @contextmanager
        def get_session():
            yield session
        orm = SimpleNamespace(get_session=get_session)
        self.patches = [patch.object(routes, 'get_orm_instance', return_value=orm),
                        patch('utils.scan_jobs.Queue', return_value=self.queue),
                        patch('utils.auto_scheduler._is_any_scan_running', return_value=False)]
        for p in self.patches:
            p.start()
        app = Flask(__name__)
        app.config.update(SECRET_KEY='test-only', TESTING=True)
        login = LoginManager(app)
        login.user_loader(lambda _: User())
        CSRFProtect(app)
        app.register_blueprint(projects_bp)
        @app.route('/test-csrf')
        def token():
            return generate_csrf()
        self.client = app.test_client()
        with self.client.session_transaction() as s:
            s['_user_id'] = '7'
            s['_fresh'] = True
        self.token = self.client.get('/test-csrf').text

    @staticmethod
    def query(record):
        q = MagicMock()
        q.filter_by.return_value.first.return_value = record
        return q

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def post(self, path, **kwargs):
        return self.client.post(path, headers={'X-CSRFToken':self.token}, **kwargs)

    def test_enqueue_and_list(self):
        response = self.post('/projects/1/start-scan', json={'model_id':2})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json['job']['state'], 'queued')
        response = self.client.get('/projects/1/scan-jobs')
        self.assertEqual(len(response.json['jobs']), 1)

    def test_duplicate_enqueue(self):
        self.post('/projects/1/start-scan', json={'model_id':2})
        self.assertTrue(self.post('/projects/1/start-scan', json={'model_id':2}).json['already_running'])

    def test_other_owner_cannot_enqueue_or_list(self):
        self.project.owner_id = 8
        self.assertEqual(self.post('/projects/1/start-scan', json={'model_id':2}).status_code, 404)
        self.assertEqual(self.client.get('/projects/1/scan-jobs').status_code, 404)

    def test_null_owner_not_public(self):
        self.project.owner_id = None
        self.assertEqual(self.client.get('/projects/1/scan-jobs').status_code, 404)

    def test_other_model_cannot_be_spent(self):
        self.model.owner_id = 8
        self.assertEqual(self.post('/projects/1/start-scan', json={'model_id':2}).status_code, 404)

    def test_invalid_request_and_budget(self):
        self.assertEqual(self.post('/projects/1/start-scan', json={'model_id':'2;id'}).status_code, 400)
        self.project.cost = 10
        self.assertEqual(self.post('/projects/1/start-scan', json={'model_id':2}).status_code, 400)

    def test_cancellation_cannot_cross_projects(self):
        job, _ = self.queue.enqueue(9,2,7)
        self.assertEqual(self.post('/projects/1/scan-jobs/'+job['id']+'/cancel').status_code,404)
        self.assertEqual(self.queue.get(job['id'])['state'],'queued')

    def test_cancel_own_job(self):
        job, _ = self.queue.enqueue(1,2,7)
        response = self.post('/projects/1/scan-jobs/'+job['id']+'/cancel')
        self.assertEqual(response.json['job']['state'],'cancelled')

    def test_missing_csrf_rejected(self):
        response = self.client.post('/projects/1/start-scan',json={'model_id':2})
        self.assertEqual(response.status_code,400)

    def test_login_required(self):
        with self.client.session_transaction() as s:
            s.clear()
        self.assertEqual(self.client.get('/projects/1/scan-jobs').status_code,401)
