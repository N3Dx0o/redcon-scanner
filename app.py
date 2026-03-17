#!/usr/bin/env python3
"""
Flask web application for security analysis
Main entry point - registers all blueprints
"""

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

# Disable SQLAlchemy engine INFO logs - MUST be before any db imports
# Comprehensive list to disable all SQLAlchemy logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

# Initialize Sentry SDK - only capture exceptions and error/critical logs
sentry_logging = LoggingIntegration(
    level=logging.ERROR,        # Capture ERROR and CRITICAL logs
    event_level=logging.ERROR   # Send events for ERROR and CRITICAL only
)

sentry_sdk.init(
    dsn="",  # Set SENTRY_DSN env var to enable (moved from hardcoded)
    send_default_pii=False,  # Never send PII to third-party
    integrations=[
        FlaskIntegration(),
        sentry_logging,
    ],
    # Only capture exceptions (not debug/info logs)
    traces_sample_rate=0.0,  # Disable performance monitoring
    # Only capture exceptions and error/critical logs, not debug/info/warning
    before_send=lambda event, hint: (
        event if (
            hint.get('exc_info') or  # Exceptions
            (event.get('level') in ('error', 'fatal', 'critical'))  # Error/Critical logs
        ) else None
    ),
)

from flask import Flask, redirect, url_for, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import os
import markdown
import platform

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
_secret_key = os.getenv('SECRET_KEY')
if not _secret_key:
    raise RuntimeError('SECRET_KEY environment variable must be set. Refusing to start.')
app.secret_key = _secret_key

# Session / cookie security
app.config["SESSION_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_DURATION"] = __import__("datetime").timedelta(days=14)
app.config["REMEMBER_COOKIE_SECURE"]   = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"]       = 500 * 1024 * 1024  # 500 MB max upload
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 28800  # 8 hours

# ─── Flask-Login setup ────────────────────────────────────────────────────────
login_manager = LoginManager()
csrf = CSRFProtect()
login_manager.init_app(app)
csrf.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access the Security Scanner.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    from utils.flask_helpers import get_orm_instance
    from db.models import User
    try:
        orm = get_orm_instance()
        with orm.get_session() as sess:
            return sess.query(User).filter_by(id=int(user_id)).first()
    except Exception:
        return None


# ─── First-run redirect (no users yet → go to register) ──────────────────────
@app.before_request
def redirect_to_setup_if_no_users():
    from flask import request as req
    from flask_login import current_user as _cu
    from utils.flask_helpers import get_orm_instance
    from db.models import User

    # Always allow: static files, auth routes, landing page, API routes
    if req.endpoint and (
        req.endpoint.startswith('auth.')
        or req.endpoint == 'static'
        or req.endpoint == 'home.landing'
        or req.endpoint and req.endpoint.startswith('api.')
    ):
        return

    # First-run: no users exist → force registration
    try:
        orm = get_orm_instance()
        with orm.get_session() as sess:
            count = sess.query(User).count()
        if count == 0:
            return redirect(url_for('auth.register'))
    except Exception:
        pass


# Add CORS headers for API endpoints
@app.after_request
def after_request(response):
    allowed_origins = [
        'https://scanner.redconoffence.com',
        'http://127.0.0.1:8002',
        'http://localhost:8002',
    ]
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-CSRFToken'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
        # X-XSS-Protection removed (deprecated, no longer supported)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response



@app.before_request
def api_key_auth():
    """Allow API key authentication for /api/ routes via X-API-Key header"""
    from flask import request as _req
    from flask_login import current_user as _cu, login_user as _lu
    if _req.path.startswith('/api/'):
        api_key = _req.headers.get('X-API-Key')
        if api_key and not _cu.is_authenticated:
            try:
                from db.models import User as _User
                from utils.flask_helpers import get_orm_instance as _get_orm
                _orm = _get_orm()
                with _orm.get_session() as _sess:
                    _user = _sess.query(_User).filter_by(api_key=api_key).first()
                    if _user:
                        _lu(_user)
            except Exception as _e:
                logger.warning('API key auth error: %s', _e)



@login_manager.unauthorized_handler
def unauthorized():
    """Return 401 JSON for API requests; redirect to login for browser requests."""
    from flask import request as _req, jsonify as _json, redirect as _redir, url_for as _ufl
    if _req.path.startswith('/api/') or _req.headers.get('X-API-Key') or _req.headers.get('Accept') == 'application/json':
        return _json({'success': False, 'error': 'Authentication required', 'code': 401}), 401
    return _redir(_ufl('auth.login', next=_req.path))

@app.context_processor
def inject_ai_models_count():
    """Inject ai_models_count into every template so banners can show."""
    from flask_login import current_user
    try:
        if current_user and current_user.is_authenticated:
            import sqlite3 as _sq
            _db_name = os.getenv('DB_DATABASE', 'scanner.db')
            _db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _db_name)
            _c = _sq.connect(_db_path)
            _count = _c.execute('SELECT COUNT(*) FROM ai_models').fetchone()[0]
            _c.close()
            return dict(ai_models_count=_count)
    except Exception:
        pass
    return dict(ai_models_count=0)


# Markdown bleach sanitizer (XSS protection for AI-generated content)
import markupsafe as _markupsafe
try:
    import bleach as _bleach
    _BLEACH_AVAILABLE = True
    _ALLOWED_TAGS = list(_bleach.sanitizer.ALLOWED_TAGS) + [
        'p', 'pre', 'code', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'hr', 'br', 'strong', 'em', 'del', 's', 'table',
        'thead', 'tbody', 'tr', 'th', 'td', 'span', 'div',
    ]
    _ALLOWED_ATTRS = {
        **_bleach.sanitizer.ALLOWED_ATTRIBUTES,
        'code': ['class'],
        'span': ['class'],
        'div':  ['class'],
        'td':   ['align'],
        'th':   ['align'],
    }
except ImportError:
    _BLEACH_AVAILABLE = False

# Add markdown filter
@app.template_filter('markdown')
def markdown_filter(text):
    if not text:
        return ''
    try:
        raw_html = markdown.markdown(text, extensions=['codehilite', 'fenced_code', 'tables', 'nl2br'])
    except Exception:
        raw_html = markdown.markdown(text, extensions=['nl2br'])
    if _BLEACH_AVAILABLE:
        return _markupsafe.Markup(_bleach.clean(raw_html, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True))
    return _markupsafe.Markup(raw_html)

# Register blueprints
from routes import (
    home_bp, projects_bp, findings_bp, ai_models_bp,
    threat_models_bp, summarize_bp, export_bp, api_bp, status_bp, logs_bp
)

# Backward-compatibility: redirect old /auth/* URLs to correct paths
@app.route('/auth/login')
def compat_login():
    from flask import redirect, url_for
    return redirect(url_for('auth.login'), 301)

@app.route('/auth/register')  
def compat_register():
    from flask import redirect, url_for
    return redirect(url_for('auth.register'), 301)

from routes.auth import auth_bp

app.register_blueprint(auth_bp)
app.register_blueprint(home_bp)
app.register_blueprint(projects_bp)
app.register_blueprint(findings_bp)
app.register_blueprint(ai_models_bp)
app.register_blueprint(threat_models_bp)
app.register_blueprint(summarize_bp)
app.register_blueprint(export_bp)
app.register_blueprint(api_bp)
csrf.exempt(api_bp)
app.register_blueprint(status_bp)
app.register_blueprint(logs_bp)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    from flask import render_template
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    from flask import render_template
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database
    from utils.flask_helpers import initialize_database
    database_name = os.getenv('DB_DATABASE', 'dev.db')
    initialize_database(database_name)
    
    # Run the app
    app.run(debug=False, host='0.0.0.0', port=8000)
