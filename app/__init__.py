from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from flask_simple_captcha import CAPTCHA
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
mail = Mail()
s = URLSafeTimedSerializer('secret_key')
csrf = CSRFProtect()  # Checks the CSRF_token field sent with forms

# CAPTCHA configuration
CAPTCHA_CONFIG = {
    'SECRET_CAPTCHA_KEY': 'LONG_KEY',
    'CAPTCHA_LENGTH': 6,
    'CAPTCHA_DIGITS': True,
    'EXPIRE_SECONDS': 600,
}
captcha = CAPTCHA(CAPTCHA_CONFIG)

# read the txt file with email credentials
with open('data.txt', 'r') as file:
    content = file.read()
    sender_email = content[:28]
    sender_security_sequence = content[28:]


def create_app():
    """
    Creates app with all necessary configurations
    :return: app (Flask Object)
    """
    app = Flask(__name__)
    app.secret_key = 'your_secret_key'

    # Configurations
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/lovejoy_db'  # Connect to DB
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Mail Server
    app.config['MAIL_PORT'] = 587  # Mail Port
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = sender_email
    app.config['MAIL_PASSWORD'] = sender_security_sequence
    app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection for forms
    app.config['UPLOAD_FOLDER'] = 'app/uploads/'  # Folder where uploaded images from Requested Evaluations are stored

    # Initialize extensions
    db.init_app(app)  # Initialise Database
    mail.init_app(app)  # Initialise Mail Server
    captcha.init_app(app)  # Initialize CAPTCHA
    csrf.init_app(app)  # Enable CSRF protection

    # Register blueprints
    from app.routes import register_routes
    register_routes(app)

    return app
