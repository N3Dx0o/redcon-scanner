"""Threat model-related routes"""
from flask_login import login_required, current_user
from flask import render_template, flash
from routes import threat_models_bp
from utils.tools_utils import get_all_tools_metadata, get_tools_by_category
import logging

logger = logging.getLogger(__name__)


@threat_models_bp.route('')
@login_required
def threat_models_list():
    """List threat models"""
    try:
        tools_metadata = get_all_tools_metadata()
        tools_by_category = get_tools_by_category()
        return render_template('threat_models_list.html', 
                             tools=tools_metadata, 
                             tools_by_category=tools_by_category)
    except Exception as e:
        logger.error(f"Error listing threat models: {e}")
        flash('Error loading threat models', 'error')
        return render_template('threat_models_list.html', tools=[], tools_by_category={})

