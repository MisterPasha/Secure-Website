from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from flask_simple_captcha import CAPTCHA

db = SQLAlchemy()
mail = Mail()
s = URLSafeTimedSerializer('secret_key')
# CAPTCHA configuration
CAPTCHA_CONFIG = {
    'SECRET_CAPTCHA_KEY': 'LONG_KEY',
    'CAPTCHA_LENGTH': 6,
    'CAPTCHA_DIGITS': True,
    'EXPIRE_SECONDS': 600,
}
captcha = CAPTCHA(CAPTCHA_CONFIG)
with open('data.txt', 'r') as file:
    content = file.read()
    sender_email = content[:28]
    sender_security_sequence = content[28:]


def create_app():
    app = Flask(__name__)
    app.secret_key = 'your_secret_key'

    # Configurations
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/lovejoy_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = sender_email
    app.config['MAIL_PASSWORD'] = sender_security_sequence
    app.config['UPLOAD_FOLDER'] = 'app/uploads/'

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    captcha.init_app(app)  # Initialize CAPTCHA

    # Register blueprints
    from app.routes import register_routes
    register_routes(app)

    return app
