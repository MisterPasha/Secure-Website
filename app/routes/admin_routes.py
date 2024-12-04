from flask import Blueprint, render_template, redirect, url_for, flash, session
from app.models import Requests

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/list-requests')
def list_requests():
    """
    Lists requests from Database
    :return: web page, requests
    """
    # Check if the user is admin
    if 'user_id' not in session or session['user_id'] != 33:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('auth.login'))

    # Query all requests from the database
    requests = Requests.query.all()

    # pass requests to HTML
    return render_template('listRequests.html', requests=requests)
