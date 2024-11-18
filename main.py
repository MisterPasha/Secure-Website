from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a more secure key in production

# Configure the MySQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/lovejoy_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    phone = StringField('Contact Number', validators=[DataRequired(), Length(min=10, max=15)])
    submit = SubmitField('Register')


# Route for the registration form
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)  # Hash password

        # Create a new user instance with form data
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password,  # Save hashed password
            phone=form.phone.data
        )

        # Add the new user to the database session and commit
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Welcome, {}'.format(new_user.name))
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            flash('Error: Could not register. This email might already be registered.')
            print(e)  # Log the error for debugging purposes

    return render_template('register.html', form=form)


# Run the app
if __name__ == '__main__':
    # Create database tables if they don't exist yet
    with app.app_context():
        db.create_all()
    app.run(debug=True)