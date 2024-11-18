import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import pymysql

# http://127.0.0.1:5000/login

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a more secure key in production

# Configure the MySQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/lovejoy_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

with open('C:\Sussex\Programming\Personal_data\data.txt', 'r') as file:
    # Read all lines in the file
    content = file.read()
    sender_email = content[:28]
    sender_security_sequence = content[28:]

# Configure Flask-Mail for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = sender_email
app.config['MAIL_PASSWORD'] = sender_security_sequence

mail = Mail(app)

# Serializer for generating tokens
s = URLSafeTimedSerializer(app.secret_key)

# Initialize the database
db = SQLAlchemy(app)


# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    security_question = db.Column(db.String(150), nullable=False)
    security_answer = db.Column(db.String(50), nullable=False)


# Define the registration form
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8),  # Minimum length of 8 characters
            Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one digit, "
                        "and one special character."
            )
        ]
    )
    # Security question dropdown
    security_question = SelectField(
        'Security Question',
        choices=[
            ('', 'Select a security question'),
            ('q1', 'What was the name of your first pet?'),
            ('q2', 'What is your favourite dish?'),
            ('q3', 'What was the name of your elementary school?'),
            ('q4', 'In what city were you born?')
        ],
        validators=[DataRequired()]
    )

    security_answer = StringField('Your Answer', validators=[DataRequired(), Length(min=2, max=50)])
    phone = StringField('Contact Number', validators=[DataRequired(), Length(min=10, max=15)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


def validate_password(password):
    if (len(password) < 8 or
            not re.search(r"[A-Z]", password) or  # At least one uppercase letter
            not re.search(r"[a-z]", password) or  # At least one lowercase letter
            not re.search(r"\d", password) or  # At least one digit
            not re.search(r"[@$!%*?&]", password)):  # At least one special character
        return False
    return True


# Route for the registration form
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        name = form.name.data
        phone = form.phone.data
        security_question = form.security_question.data
        security_answer = form.security_answer.data

        # Check if user with this email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account with this email already exists.")
            return redirect(url_for('register'))

        if not validate_password(password):
            flash("Password must be at least 8 characters long and contain at least one uppercase letter, "
                  "one lowercase letter, one digit, and one special character (@$!%*?&).")
            return redirect(url_for('register'))

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
            security_question=security_question,
            security_answer=hashed_security_answer
        )

        # Add the new user to the database session and commit
        db.session.add(new_user)
        db.session.commit()  # Save the user to the database

        # Generate a token for email verification
        token = s.dumps(email, salt='email-confirm')

        # Send the verification email
        msg = Message('Confirm Your Email', sender='gorillaz99@mail.ru', recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f'Thank you for registering at Lovejoy! Please click the link to verify your email: {link}'
        mail.send(msg)

        flash(
            'A confirmation email has been sent to your email address. '
            'Please verify your email to complete registration.')
        return redirect(url_for('login'))

        # If GET request, render registration form
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # Check if form is valid and submitted
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.')
                return redirect(url_for('register'))
            flash('Login successful!')
            session['user_id'] = user.id
            # Proceed with login
        else:
            flash('Invalid credentials. Please try again.')

    return render_template('login.html', form=form)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # Verify the token (set expiration time to 1 hour, for example)
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('The confirmation link has expired.', 'error')
        return redirect(url_for('register'))
    except BadSignature:
        flash('The confirmation link is invalid.', 'error')
        return redirect(url_for('register'))

    # Mark the user as verified in the database
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Your email has been confirmed. You can now log in.')
        return redirect(url_for('login'))
    else:
        flash('User not found.')
        return redirect(url_for('register'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access this page.", 'danger')
        return redirect(url_for('login'))
    return "Welcome to your dashboard!"


# Run the app
if __name__ == '__main__':
    # Create database tables if they don't exist yet
    with app.app_context():
        db.create_all()
    app.run(debug=True)
