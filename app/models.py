from datetime import datetime
from flask_login import UserMixin
from app import db

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    items = db.relationship('Item', backref='user', lazy=True)

    def get_id(self):
        """
        This method is used by Flask-Login to retrieve the user ID.
        """
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username}>'

class Item(db.Model):
    __tablename__ = 'item'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="lost", nullable=False)  # 'lost' or 'found'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(100), nullable=True)  # Add image field for storing image filenames

    def __repr__(self):
        return f'<Item {self.name} - {self.status}>'

    __table_args__ = (
        db.CheckConstraint("status IN ('lost', 'found')", name="check_status"), 
    )



