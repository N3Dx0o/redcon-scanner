"""AI model-related routes"""
from flask_login import login_required, current_user
from flask import render_template, request, jsonify, flash
from routes import ai_models_bp
from utils.flask_helpers import get_orm_instance
from db.models import AIModel
import logging

logger = logging.getLogger(__name__)


@ai_models_bp.route('')
@login_required
def ai_models_list():
    """List AI models"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            models = orm.get_all(session, AIModel)
            return render_template('ai_models_list.html', models=models)
    except Exception as e:
        logger.error(f"Error listing AI models: {e}")
        flash('Error loading AI models', 'error')
        return render_template('ai_models_list.html', models=[])

