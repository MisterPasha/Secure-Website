from flask import Blueprint, session, flash, redirect, url_for

user_bp = Blueprint('user', __name__)


@user_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access this page.", 'danger')
        return redirect(url_for('auth.login'))
    return "Welcome to your dashboard!"
