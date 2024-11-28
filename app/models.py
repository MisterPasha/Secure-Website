from app import db


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    security_question1 = db.Column(db.String(150), nullable=False)
    security_answer1 = db.Column(db.String(500), nullable=False)
    security_question2 = db.Column(db.String(150), nullable=False)
    security_answer2 = db.Column(db.String(500), nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
