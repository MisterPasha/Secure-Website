from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.forms import RegistrationForm, LoginForm
from app.models import User
from app import db, s
from werkzeug.security import generate_password_hash, check_password_hash
import re
from itsdangerous import SignatureExpired
from flask_mail import Mail, Message
from app import mail
from app import sender_email
import random
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)


def validate_password(password, email=None, name=None):
    common_passwords = {"password", "123456", "qwerty", "abc123", "iloveyou", "letmein", "welcome"}
    # Check minimum length
    if len(password) < 12:  # Increase minimum length for better security
        return "Password must be at least 12 characters long."
    # Check for uppercase letters
    elif not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter (A-Z)."
    # Check for lowercase letters
    elif not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter (a-z)."
    # Check for digits
    elif not re.search(r"\d", password):
        return "Password must contain at least one digit (0-9)."
    # Check for special characters
    elif not re.search(r"[@$!%*?&^#\-_=+]", password):  # Allow more special characters
        return "Password must contain at least one special character (@$!%*?&^#-=+)."
    # Check for sequences of repeated characters
    elif re.search(r"(.)\1{2,}", password):  # Prevent more than 2 repeated characters
        return "Password must not contain sequences of more than 2 repeated characters."
    # Check for common passwords (using a sample list)
    elif password.lower() in common_passwords:
        return "Password is too common. Please choose a stronger password."
    elif email:
        local_part = email.split('@')[0]
        if local_part.lower() in password.lower():
            return "Password must not contain parts of your email address."
    elif name:
        if name.lower() in password.lower():
            return "Password must not contain your name."

    # Passed all checks
    return True


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    sec_questions1 = {
        'q1': 'What was the name of your first pet?',
        'q2': 'What is your favourite dish?',
        'q3': 'What was the name of your elementary school?',
        'q4': 'In what city were you born?'
    }
    sec_questions2 = {
        'q1': 'What is your mother’s maiden name?',
        'q2': 'What is your favorite book or movie??',
        'q3': 'What is your dream job?',
        'q4': 'What was the name of your childhood best friend?'
    }
    form = RegistrationForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        name = form.name.data
        phone = form.phone.data
        security_question1_label = form.security_question1.data
        security_question1_value = sec_questions1.get(security_question1_label)
        security_question2_label = form.security_question2.data
        security_question2_value = sec_questions2.get(security_question2_label)
        security_answer1 = form.security_answer1.data
        security_answer2 = form.security_answer2.data

        # Check if user with this email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account with this email already exists.")
            return redirect(url_for('auth.register'))

        if validate_password(password, email, name) is not True:
            message = validate_password(password, email)
            flash(message)
            return redirect(url_for('auth.register'))

        # Hash the password
        hashed_password = generate_password_hash(password)  # Salt is automatically applied
        hashed_security_answer1 = generate_password_hash(security_answer1)  # Salt is automatically applied
        hashed_security_answer2 = generate_password_hash(security_answer2)  # Salt is automatically applied

        # Create a new user instance with is_verified=False
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            phone=phone,
            is_verified=False,
            security_question1=security_question1_value,
            security_answer1=hashed_security_answer1,
            security_question2=security_question2_value,
            security_answer2=hashed_security_answer2,
        )

        # Add the new user to the database session and commit
        db.session.add(new_user)
        db.session.commit()  # Save the user to the database

        print(f"security answers: '{security_answer1}', '{security_answer2}'")
        print(f"hashes:")
        print(hashed_security_answer1)
        print(hashed_security_answer2)

        # Generate a token for email verification
        token = s.dumps(email, salt='email-confirm')

        # Send the verification email
        msg = Message('Confirm Your Email', sender=sender_email, recipients=[email])
        link = url_for('email.confirm_email', token=token, _external=True)
        msg.body = f'Thank you for registering at Lovejoy! Please click the link to verify your email: {link}'
        mail.send(msg)

        flash(
            'A confirmation email has been sent to your email address. '
            'Please verify your email to complete registration.')
        return redirect(url_for('auth.login'))

        # If GET request, render registration form
    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # Check if form is valid and submitted
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('auth.register'))
            # Check if the account is locked
            elif user.lockout_until and datetime.utcnow() < user.lockout_until:
                lockout_time_remaining = (user.lockout_until - datetime.utcnow()).seconds
                flash(f"Your account is locked. Try again in {lockout_time_remaining} seconds.", 'danger')
                return redirect(url_for('auth.login'))

            # Check the password
            if check_password_hash(user.password, password):
                # Reset failed attempts on successful login
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()

                # Generate a 6-digit verification code
                verification_code = random.randint(100000, 999999)
                session['verification_code'] = verification_code  # Store in session
                session['user_id'] = user.id  # Store user ID in session for the next step

                # Send the verification code via email
                msg = Message('Your Login Verification Code',
                              sender=sender_email, recipients=[email])
                msg.body = f'Your verification code is: {verification_code}'
                mail.send(msg)

                flash('A verification code has been sent to your email. Please check your inbox.', 'info')
                return redirect(url_for('auth.verify_code'))  # Redirect to the code verification page
            else:
                # Increment failed attempts
                user.failed_attempts += 1

                # Lock the account if attempts exceed 5
                if user.failed_attempts >= 5:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=15)  # Lock for 15 minutes
                    flash("Too many failed attempts. Your account is locked for 15 minutes.", 'danger')
                else:
                    attempts_remaining = 5 - user.failed_attempts
                    flash(f"Invalid credentials. You have {attempts_remaining} attempts remaining.", 'danger')

                db.session.commit()
                return redirect(url_for('auth.login'))
        else:
            flash('User not found. Please register.', 'danger')
            return redirect(url_for('auth.register'))

    return render_template('login.html', form=form)


@auth_bp.route('/verify-code', methods=['GET', 'POST'])
def verify_code():
    if 'verification_code' not in session or 'user_id' not in session:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        entered_code = request.form['verification_code']

        # Check if the entered code matches the one in the session
        if str(entered_code) == str(session['verification_code']):
            # Log in the user and clear the session data
            session.pop('verification_code', None)  # Remove verification code from session
            flash('Login successful!', 'success')
            return redirect(url_for('auth.request_evaluation'))  # Redirect to the target page

        else:
            flash('Incorrect code. Please try again.', 'danger')

    return render_template('verifyCode.html')


@auth_bp.route('/request-evaluation')
def request_evaluation():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('auth.login'))

    return render_template('requestEvaluation.html')


@auth_bp.route('/resetPassword/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify the token
        email = s.loads(token, salt='password-recovery', max_age=3600)  # Token expires in 1 hour
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('password_recovery'))

    if request.method == 'POST':
        new_password = request.form['password']
        security_answer = request.form['security_answer']
        user = User.query.filter_by(email=email).first()

        if user:
            # Validate new password
            if not validate_password(new_password):
                flash("Password must be at least 8 characters long and contain at least one uppercase letter, "
                      "one lowercase letter, one digit, and one special character (@$!%*?&).")
                return redirect(url_for('auth.reset_password', token=token))
            elif not check_password_hash(user.security_answer2, security_answer):
                flash("Incorrect Security Answer, please try again")
                return redirect(url_for('auth.reset_password', token=token))
            # Hash the new password
            hashed_password = generate_password_hash(new_password)

            # Update the user's password in the database
            user.password = hashed_password
            db.session.commit()

            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('resetPassword.html', token=token)
