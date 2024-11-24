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

auth_bp = Blueprint('auth', __name__)


def validate_password(password):
    if (len(password) < 8 or
            not re.search(r"[A-Z]", password) or  # At least one uppercase letter
            not re.search(r"[a-z]", password) or  # At least one lowercase letter
            not re.search(r"\d", password) or  # At least one digit
            not re.search(r"[@$!%*?&]", password)):  # At least one special character
        return False
    return True


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    sec_questions = {
        'q1': 'What was the name of your first pet?',
        'q2': 'What is your favourite dish?',
        'q3': 'What was the name of your elementary school?',
        'q4': 'In what city were you born?'
    }
    form = RegistrationForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        name = form.name.data
        phone = form.phone.data
        security_question_label = form.security_question.data
        security_question_value = sec_questions.get(security_question_label)
        security_answer = form.security_answer.data

        # Check if user with this email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account with this email already exists.")
            return redirect(url_for('auth.register'))

        if not validate_password(password):
            flash("Password must be at least 8 characters long and contain at least one uppercase letter, "
                  "one lowercase letter, one digit, and one special character (@$!%*?&).")
            return redirect(url_for('auth.register'))

        # Hash the password
        hashed_password = generate_password_hash(password)  # Salt is automatically applied
        hashed_security_answer = generate_password_hash(security_answer)  # Salt is automatically applied

        # Create a new user instance with is_verified=False
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            phone=phone,
            is_verified=False,
            security_question=security_question_value,
            security_answer=hashed_security_answer
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
    form = LoginForm()
    if form.validate_on_submit():  # Check if form is valid and submitted
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.')
                return redirect(url_for('auth.register'))
            flash('Login successful!')
            session['user_id'] = user.id
            # Proceed with login
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html', form=form)


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
        user = User.query.filter_by(email=email).first()

        if user:
            # Validate new password
            if not validate_password(new_password):
                flash("Password must be at least 8 characters long and contain at least one uppercase letter, "
                      "one lowercase letter, one digit, and one special character (@$!%*?&).")
                return redirect(url_for('auth.reset_password', token=token))
            # Hash the new password
            hashed_password = generate_password_hash(new_password)

            # Update the user's password in the database
            user.password = hashed_password
            db.session.commit()

            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('resetPassword.html', token=token)
