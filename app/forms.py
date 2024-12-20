from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length


class RegistrationForm(FlaskForm):
    """
    Registration Form containing all input options (e.g. textBoxes, dropdowns, buttons)
    """
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email(message="Please enter a valid email address.")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12)])
    security_question1 = SelectField(
        'Security Question 1',
        choices=[
            ('', 'Select a security question'),
            ('q1', 'What was the name of your first pet?'),
            ('q2', 'What is your favourite dish?'),
            ('q3', 'What was the name of your elementary school?'),
            ('q4', 'In what city were you born?')
        ],
        validators=[DataRequired()]
    )
    security_answer1 = StringField('Your Answer', validators=[DataRequired(), Length(min=2, max=500)])
    security_question2 = SelectField(
        'Security Question 2',
        choices=[
            ('', 'Select a security question'),
            ('q1', 'What is your mother’s maiden name?'),
            ('q2', 'What is your favorite book or movie??'),
            ('q3', 'What is your dream job?'),
            ('q4', 'What was the name of your childhood best friend?')
        ],
        validators=[DataRequired()]
    )
    security_answer2 = StringField('Your Answer', validators=[DataRequired(), Length(min=2, max=500)])
    phone = StringField('Contact Number', validators=[DataRequired(), Length(min=10, max=15)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """
    Login Form containing all input on the login page
    """
    email = StringField('Email', validators=[DataRequired(), Email(message="Please enter a valid email address.")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')
