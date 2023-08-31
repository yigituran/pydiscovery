from datetime import datetime
from pydiscovery import db 


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(20), nullable=False)
    account_picture = db.Column(db.String(100), default="default.jpg")  # Default picture filename
    discovery_results = db.relationship('DiscoveryResult', backref='user', lazy=True) # One-to-many

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username})>"


class DiscoveryResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    method = db.Column(db.String(50), nullable=False)
    ip_range = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<DiscoveryResult(id={self.id}, method={self.method}, ip_range={self.ip_range})>"
