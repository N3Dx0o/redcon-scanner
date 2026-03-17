"""
Authentication routes — login, logout, register, change password
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import logging
import time as _time
from collections import defaultdict
from urllib.parse import urlparse
import re as _re_pwd

def _validate_password_strength(password: str):
    """Returns error message if invalid, None if OK."""
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not _re_pwd.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not _re_pwd.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not _re_pwd.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    if not _re_pwd.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character."
    return None


from db import get_orm

# ── Brute-force protection ─────────────────────────────────────
_login_attempts = defaultdict(list)
_MAX_ATTEMPTS   = 10
_WINDOW_SECS    = 300   # 5 min window
_LOCKOUT_SECS   = 900   # 15 min lockout

def _get_ip(req):
    # Use X-Real-IP set by nginx (after Cloudflare IP restoration), not X-Forwarded-For
    # which can be spoofed by clients to bypass rate limiting.
    return req.headers.get("X-Real-IP", req.remote_addr) or req.remote_addr

def _is_locked(ip):
    now = _time.time()
    recent = [t for t in _login_attempts[ip] if now - t < _WINDOW_SECS]
    _login_attempts[ip] = recent
    if len(recent) >= _MAX_ATTEMPTS:
        wait = int(_LOCKOUT_SECS - (now - recent[0]))
        return True, max(wait, 0)
    return False, 0

def _record_fail(ip):
    _login_attempts[ip].append(_time.time())
from db.models import User

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _get_orm():
    from utils.flask_helpers import get_orm_instance
    return get_orm_instance()


# ─── login ────────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home.index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if not username or not password:
            error = 'Username and password are required.'
        else:
            _ip = _get_ip(request)
            _locked, _wait = _is_locked(_ip)
            if _locked:
                _mins = (_wait // 60) + 1
                error = f'Too many failed attempts. Try again in {_mins} minute(s).'
                logger.warning(f'Login blocked: IP={_ip}')
            else:
                orm = _get_orm()
                with orm.get_session() as sess:
                    user = sess.query(User).filter(
                        (User.username == username) | (User.email == username)
                    ).first()

                    if user and user.check_password(password):
                        user.last_login_at = datetime.utcnow()
                        sess.commit()
                        session.clear()
                        login_user(user, remember=remember)
                        logger.info(f"User '{user.username}' logged in successfully.")
                        next_page = request.args.get('next', '')
                        if next_page:
                            p = urlparse(next_page)
                            if p.scheme or p.netloc or not next_page.startswith('/'):
                                next_page = ''
                        return redirect(next_page or url_for('home.index'))
                    else:
                        error = 'Invalid username or password.'
                        _record_fail(_ip)

    return render_template('auth/login.html', error=error)


# ─── logout ───────────────────────────────────────────────────────────────────

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User '{username}' logged out.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ─── register ─────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Registration is only available to admins, or when no users exist yet (first run)."""
    orm = _get_orm()

    # Allow anyone to register when there are zero users (first-run onboarding)
    with orm.get_session() as sess:
        user_count = sess.query(User).count()

    first_run = (user_count == 0)

    # If users exist, only admins may register new accounts
    if not first_run:
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Only administrators can register new accounts.', 'danger')
            return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        make_admin = first_run or request.form.get('is_admin') == 'on'

        # Validation
        if not username or not email or not password:
            error = 'All fields are required.'
        elif len(username) < 3:
            error = 'Username must be at least 3 characters.'
        elif _validate_password_strength(password) is not None:
            error = _validate_password_strength(password)
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            with orm.get_session() as sess:
                existing = sess.query(User).filter(
                    (User.username == username) | (User.email == email)
                ).first()

                if existing:
                    error = 'Username or email is already taken.'
                else:
                    new_user = User(
                        username=username,
                        email=email,
                        is_admin=make_admin,
                    )
                    new_user.set_password(password)
                    sess.add(new_user)
                    sess.commit()
                    logger.info(f"New user '{username}' registered (admin={make_admin}).")

                    if first_run:
                        flash(f'Admin account "{username}" created! Please log in.', 'success')
                        return redirect(url_for('auth.login'))
                    else:
                        flash(f'User "{username}" created successfully.', 'success')
                        return redirect(url_for('auth.manage_users'))

    return render_template('auth/register.html', error=error, first_run=first_run)


# ─── manage users (admin) ─────────────────────────────────────────────────────

@auth_bp.route('/settings/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('home.index'))

    orm = _get_orm()
    with orm.get_session() as sess:
        users = sess.query(User).order_by(User.created_at).all()
        users_data = [
            {
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'is_admin': u.is_admin,
                'created_at': u.created_at,
                'last_login_at': u.last_login_at,
            }
            for u in users
        ]

    return render_template('auth/users.html', users=users_data)


@auth_bp.route('/settings/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('home.index'))

    if user_id == current_user.id:
        flash("You can't delete your own account.", 'danger')
        return redirect(url_for('auth.manage_users'))

    orm = _get_orm()
    with orm.get_session() as sess:
        user = sess.query(User).filter_by(id=user_id).first()
        if user:
            sess.delete(user)
            sess.commit()
            flash(f'User "{user.username}" deleted.', 'success')
        else:
            flash('User not found.', 'danger')

    return redirect(url_for('auth.manage_users'))


# ─── change password ──────────────────────────────────────────────────────────

@auth_bp.route('/settings/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None

    if request.method == 'POST':
        current_pw  = request.form.get('current_password', '')
        new_pw      = request.form.get('new_password', '')
        confirm_pw  = request.form.get('confirm_password', '')

        if not current_pw or not new_pw or not confirm_pw:
            error = 'All fields are required.'
        elif not current_user.check_password(current_pw):
            error = 'Current password is incorrect.'
        elif _validate_password_strength(new_pw) is not None:
            error = _validate_password_strength(new_pw)
        elif new_pw != confirm_pw:
            error = 'New passwords do not match.'
        else:
            orm = _get_orm()
            with orm.get_session() as sess:
                user = sess.query(User).filter_by(id=current_user.id).first()
                user.set_password(new_pw)
                sess.commit()
            success = 'Password changed successfully.'
            logger.info(f"User '{current_user.username}' changed their password.")

    return render_template('auth/change_password.html', error=error, success=success)


# ─── API key management ────────────────────────────────────────────────────────
import secrets as _secrets
from flask import jsonify as _jsonify

@auth_bp.route('/settings/api-key', methods=['POST'])
@login_required
def generate_api_key():
    """Generate or regenerate user API key"""
    orm = _get_orm()
    with orm.get_session() as session:
        user = session.query(User).filter_by(id=current_user.id).first()
        user.api_key = _secrets.token_hex(32)
        session.commit()
        return _jsonify({'success': True, 'api_key': user.api_key})

@auth_bp.route('/settings/api-key', methods=['DELETE'])
@login_required
def revoke_api_key():
    """Revoke user API key"""
    orm = _get_orm()
    with orm.get_session() as session:
        user = session.query(User).filter_by(id=current_user.id).first()
        user.api_key = None
        session.commit()
        return _jsonify({'success': True})


# ─── account settings page ─────────────────────────────────────────────────────

@auth_bp.route('/settings')
@login_required
def settings():
    return render_template('auth/settings.html')

@auth_bp.route('/settings/notifications', methods=['POST'])
@login_required
def update_notifications():
    orm = _get_orm()
    with orm.get_session() as session:
        user = session.query(User).filter_by(id=current_user.id).first()
        user.notify_scan_complete = 'notify_scan_complete' in request.form
        user.notify_critical_findings = 'notify_critical_findings' in request.form
        session.commit()
    flash('Notification preferences saved.', 'success')
    return redirect(url_for('auth.settings'))


# ─── onboarding ────────────────────────────────────────────────────────────────

@auth_bp.route('/onboarding/complete', methods=['POST'])
@login_required
def complete_onboarding():
    """Mark onboarding as complete for the current user."""
    from flask import jsonify
    orm = _get_orm()
    with orm.get_session() as session:
        user = session.get(User, current_user.id)
        if user:
            user.onboarding_complete = True
            session.commit()
    return jsonify({'success': True})
