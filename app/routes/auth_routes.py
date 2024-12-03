from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from app.forms import RegistrationForm, LoginForm
from app.models import User
from app import db, s
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import SignatureExpired
from flask_mail import Message
from app import mail, sender_email, captcha
from datetime import datetime, timedelta
import re
import random

auth_bp = Blueprint('auth', __name__)

show_captcha = False


def validate_password(password, email=None, name=None):
    """
    Validates password for the strong password format. If has vulnerability in the password then returns message
    with an advice of what needs to be improved. Otherwise returns True
    :param password
    :param email
    :param name
    :return: String or Boolean
    """

    # List of common passwords
    common_passwords = {
        "password", "123456", "qwerty", "abc123", "iloveyou", "letmein", "welcome",
        "admin", "123456789", "12345678", "12345", "1234", "111111", "123123",
        "654321", "000000", "1q2w3e4r", "sunshine", "monkey", "football",
        "master", "shadow", "dragon", "baseball", "superman", "trustno1",
        "michael", "password1", "123qwe", "qwertyuiop", "1qaz2wsx", "asdfghjkl",
        "zxcvbnm", "987654321", "qazwsx", "password123", "welcome1", "iloveyou1",
        "1q2w3e", "654321", "123321", "abc12345", "qwerty123", "loveyou"
    }
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
    # Check for password containing email part
    elif email:
        local_part = email.split('@')[0]
        if local_part.lower() in password.lower():
            return "Password must not contain parts of your email address."
    # Check for password containing user's name
    elif name:
        if name.lower() in password.lower():
            return "Password must not contain your name."
    # Passed all checks
    return True


def like_old_password(new_password, old_password):
    """
    Designed to match existing password in the Database with new password.
    Used during password recovery
    :param new_password:
    :param old_password:
    :return: boolean
    """
    return check_password_hash(old_password, new_password)


def validate_email(email):
    """
    Validation for the email input during registration and login.
    Is used to match strings that consist only of valid email format string (e.g. example.mail.uk)
    Spaces and length longer than 100 characters are not allowed either
    :param email:
    :return: boolean
    """
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) and len(email) < 100


def validate_name(name):
    """
    Validation for the name input during registering.
    Is used to match strings that consist only of letters (both uppercase and lowercase)
    No spaces are allowed either
    :param name:
    :return: boolean
    """
    return re.match(r'^[a-zA-Z]+$', name)


def validate_phone(phone):
    """
    Validation for the phone number input during registration.
    Is used to match strings that consist only 10 to 15 digits with optional '+' sign
    :param phone:
    :return: boolean
    """
    return re.match(r'^\+?[0-9]{10,15}$', phone)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    This function performs registering process.
    Gathers User input from the fields, validates input, encrypts password and security answers,
    adds data to the Database, and sends confirmation email.
    :return: web page
    """

    # Set of questions for Security Question 1
    sec_questions1 = {
        'q1': 'What was the name of your first pet?',
        'q2': 'What is your favourite dish?',
        'q3': 'What was the name of your elementary school?',
        'q4': 'In what city were you born?'
    }
    # Set of questions for Security Question 2
    sec_questions2 = {
        'q1': 'What is your mother’s maiden name?',
        'q2': 'What is your favorite book or movie??',
        'q3': 'What is your dream job?',
        'q4': 'What was the name of your childhood best friend?'
    }

    # Introduce RegistrationForm object
    form = RegistrationForm()

    if request.method == 'POST':  # Gather data from the User inputs
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
        # Validate email for valid format
        elif not validate_email(email):
            flash("Please enter a valid email address (e.g. example@email.uk)")
            return redirect(url_for('auth.register'))
        # Validate name
        elif not validate_name(name):
            flash("Please enter only First Name")
            return redirect(url_for('auth.register'))
        elif not validate_phone(phone):
            flash("Please enter a valid phone number")
            return redirect(url_for('auth.register'))
        elif validate_password(password, email, name) is not True:
            message = validate_password(password, email, name)
            flash(message)
            return redirect(url_for('auth.register'))

        # Hash the password and security answers
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
    """
    This function performs login process
    Gathers User input from the fields, validates input, creates CAPTCHA, redirects user,
    sends email with the code.
    :return: web page
    """
    form = LoginForm()
    new_captcha_dict = captcha.create()
    global show_captcha
    if form.validate_on_submit():  # Check if form is valid and submitted
        email = form.email.data
        password = form.password.data
        # Validate email address for valid format
        if not validate_email(email):
            flash("Invalid email format, try again!")
            render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if user:
            if not user.is_verified:  # Check if user's email address is verified
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('auth.register'))
            # Check if the account is locked
            elif user.lockout_until and datetime.utcnow() < user.lockout_until and not show_captcha:
                # if user is locked then show captcha
                show_captcha = True
                # Get remaining time of lockout
                lockout_time_remaining = (user.lockout_until - datetime.utcnow()).seconds
                flash(f"Your account is locked. Try again in {lockout_time_remaining} seconds.", 'danger')
                flash(f"Solve CAPTCHA to unlock your account")
                return render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)

            if user.lockout_until and datetime.utcnow() < user.lockout_until and show_captcha:
                # Create CAPTCHA
                new_captcha_dict = captcha.create()
                # Get remaining time of lockout and notify
                lockout_time_remaining = (user.lockout_until - datetime.utcnow()).seconds
                flash(f"Your account is locked. Try again in {lockout_time_remaining} seconds.", 'danger')
                if request.method == 'POST':
                    # Verify CAPTCHA input
                    c_hash = request.form.get('captcha-hash')
                    c_text = request.form.get('captcha-text')
                    # check captcha hash and user input
                    if captcha.verify(c_text, c_hash):  # if success
                        user.lockout_until = None  # Unlock account
                        db.session.commit()  # Add to Database
                        show_captcha = False
                        flash('CAPTCHA solved! Please try logging in again.', 'success')
                        return render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)
                    else:
                        show_captcha = True
                        new_captcha_dict = captcha.create()
                        flash('Incorrect CAPTCHA. Please try again.', 'warning')
                        return render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)

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

                # Send the verification code by email
                msg = Message('Your Login Verification Code',  # Email subject text
                              sender=sender_email, recipients=[email])
                msg.body = f'Your verification code is: {verification_code}'  # Body of the email
                mail.send(msg)  # Sends email

                flash('A verification code has been sent to your email. Please check your inbox.', 'info')
                return redirect(url_for('auth.verify_code'))  # Redirect to the code verification page
            else:
                # Increment failed attempts if password is incorrect
                user.failed_attempts += 1

                # Lock the account if attempts exceed 5
                if user.failed_attempts >= 5:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=15)  # Lock for 15 minutes
                    flash("Too many failed attempts. Your account is locked for 15 minutes.", 'danger')
                else:
                    attempts_remaining = 5 - user.failed_attempts
                    flash(f"Invalid credentials. You have {attempts_remaining} attempts remaining.", 'danger')

                db.session.commit()
                return render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)
        else:
            flash('User not found. Please register.', 'danger')
            return redirect(url_for('auth.register'))

    return render_template('login.html', captcha=new_captcha_dict, form=form, show_captcha=show_captcha)


@auth_bp.route('/logout')
def logout():
    """
    Logout user from the session
    :return:
    """
    session.clear()  # Clear all session data
    return redirect(url_for('auth.login'))


@auth_bp.route('/verify-code', methods=['GET', 'POST'])
def verify_code():
    """
    Function that verifies verification code and redirects user to the "Request Evaluation" page
    or "List Requests" page (if admin credentials).
    :return: web page
    """
    if 'verification_code' not in session or 'user_id' not in session:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        entered_code = request.form['verification_code']

        # Check if the entered code matches the one in the session
        if str(entered_code) == str(session['verification_code']):
            # Log in the user and clear the session data
            session.pop('verification_code', None)  # Remove verification code from session
            if session['user_id'] == 33:  # Admin ID
                return redirect(url_for('admin.list_requests'))  # Redirect admin to list_requests

            return redirect(url_for('user.request_evaluation'))  # Redirect to the target page
        else:
            flash('Incorrect code. Please login again.', 'danger')
            session.pop('verification_code', None)  # Remove verification code from session

    return redirect(url_for('auth.login'))


@auth_bp.route('/resetPassword/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Validates answer for security question, validates new password, and resets the password
    :param token: Unique token included in the emailed link for verification
    :return: web page
    """
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
            if validate_password(new_password, email, user.name) is not True:
                message = validate_password(new_password, email, user.name)
                flash(message)
                return redirect(url_for('auth.reset_password', token=token))
            # Compare if new and old passwords are the same
            elif like_old_password(new_password, user.password):
                flash("Your new password cannot be like your old password, please change")
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
