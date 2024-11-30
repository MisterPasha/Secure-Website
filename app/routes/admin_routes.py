from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from app.forms import RegistrationForm, LoginForm
from app.models import User
from app import db, s
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import SignatureExpired
from flask_mail import Message
from app import mail, sender_email
from datetime import datetime, timedelta
from app.models import Requests
import re
import random
import os
from flask_simple_captcha import CAPTCHA


admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/list-requests')
def list_requests():
    # Check if the user is admin
    print(f"Session in admin: {session}")
    if 'user_id' not in session or session['user_id'] != 33:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('auth.login'))

    # Query all requests from the database
    requests = Requests.query.all()

    return render_template('listRequests.html', requests=requests)
