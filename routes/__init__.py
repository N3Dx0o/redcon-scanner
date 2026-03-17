"""Flask blueprints for organizing routes"""
from flask import Blueprint

# Create blueprints
home_bp = Blueprint('home', __name__)
projects_bp = Blueprint('projects', __name__, url_prefix='')
findings_bp = Blueprint('findings', __name__)
ai_models_bp = Blueprint('ai_models', __name__, url_prefix='/ai-models')
threat_models_bp = Blueprint('threat_models', __name__, url_prefix='/threat-models')
summarize_bp = Blueprint('summarize', __name__)
export_bp = Blueprint('export', __name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')
status_bp = Blueprint('status', __name__)
logs_bp = Blueprint('logs', __name__)

# Import routes to register them (imports must be after blueprint creation)
from . import home, projects, findings, ai_models, threat_models, summarize, export, api, status, logs

