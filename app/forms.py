from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, Regexp


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
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
