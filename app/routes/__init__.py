from .auth_routes import auth_bp
from .user_routes import user_bp
from .email_routes import email_bp


def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(email_bp)
