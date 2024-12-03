from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.models import User
from app import db, mail, s
from flask_mail import Message
from app import sender_email
from itsdangerous import SignatureExpired, BadSignature
from werkzeug.security import check_password_hash

email_bp = Blueprint('email', __name__)


@email_bp.route('/passwordRecovery', methods=['GET', 'POST'])
def password_recovery():
    if request.method == 'POST':
        email = request.form['email']

        # Check if the user exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Render the form to verify the security question
            return render_template('verifySecurityQuestion.html', email=email, question=user.security_question1)
        else:
            flash('Email address not found.', 'danger')
            return redirect(url_for('email.password_recovery'))

    return render_template('passwordRecovery.html')


@email_bp.route('/verifySecurityQuestion', methods=['POST'])
def verify_security_question():
    email = request.form['email']
    security_answer = request.form['security_answer']

    # Retrieve the user from the database
    user = User.query.filter_by(email=email).first()
    if user:
        print(user.security_answer1)
        # Check if the security answer is correct
        if check_password_hash(user.security_answer1, security_answer):
            # Generate a token for the password reset link
            token = s.dumps(email, salt='password-recovery')

            # Send the reset email
            link = url_for('auth.reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender=sender_email, recipients=[email])
            msg.body = f'Click the following link to reset your password: {link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email address.', 'info')
            return redirect(url_for('auth.login'))
        else:
            flash('Incorrect answer to the security question.', 'danger')
            return redirect(url_for('email.password_recovery'))
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('email.password_recovery'))


@email_bp.route('/confirm_email/<token>')
def confirm_email(token):
    """
    Verifies the token used in email confirmation link.
    If success then set account as verified and proceed to the login page.
    :param token:
    :return: web page
    """
    try:
        # Verify the token (set expiration time to 1 hour (e.g. 3600 seconds))
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('The confirmation link has expired.', 'error')
        return redirect(url_for('auth.register'))
    except BadSignature:
        flash('The confirmation link is invalid.', 'error')
        return redirect(url_for('auth.register'))

    # Mark the user as verified in the database
    user = User.query.filter_by(email=email).first()  # Find user by the email
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Your email has been confirmed. You can now log in.')
        return redirect(url_for('auth.login'))  # redirect to login page
    else:
        flash('User not found.')
        return redirect(url_for('auth.register'))  # redirect to the register page otherwise
