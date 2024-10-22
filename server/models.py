from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import validates

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    
    recipes = db.relationship('Recipe', backref='user', lazy=True)

    # Property to prevent direct access to the password hash
    @property
    def password(self):
        raise AttributeError("Password is not accessible")

    # Setter to hash the password when setting it
    @password.setter
    def password(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Method to verify the password for login authentication
    def verify_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

class Recipe(db.Model):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise AssertionError("Title must be present")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise AssertionError("Instructions must be at least 50 characters long")
        return instructions
