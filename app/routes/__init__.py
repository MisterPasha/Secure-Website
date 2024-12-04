from .auth_routes import auth_bp
from .user_routes import user_bp
from .email_routes import email_bp
from .admin_routes import admin_bp


def register_routes(app):
    """
    Registers routes for each blueprint
    :param app: Flask Object
    :return:  None
    """
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(admin_bp)
