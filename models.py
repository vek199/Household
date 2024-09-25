from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import app

db = SQLAlchemy(app)

# User table, common for Admin, Customer, and Professional
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    phone_number = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))  # Store hashed password
    role = db.Column(db.String(50))  # 'customer', 'professional', 'admin'
    is_active = db.Column(db.Boolean, default=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    customer_profile = db.relationship('CustomerProfile', backref='user', uselist=False)
    professional_profile = db.relationship('Professional', backref='user', uselist=False)
    service_requests = db.relationship('ServiceRequest', backref='customer', foreign_keys='ServiceRequest.customer_id')
    reviews_written = db.relationship('Review', backref='reviewer', foreign_keys='Review.reviewer_id')
    reviews_received = db.relationship('Review', backref='reviewee', foreign_keys='Review.reviewee_id')

    # Password hashing functionality
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Customer profile (Additional details for customers)
class CustomerProfile(db.Model):
    __tablename__ = 'customer_profile'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    address = db.Column(db.Text)
    location_pin_code = db.Column(db.String(10))
    blocked = db.Column(db.Boolean, default=False)
    preferred_services = db.Column(db.Text)  # A list of services they are interested in

# Professional table (Additional details for professionals)
class Professional(db.Model):
    __tablename__ = 'professional'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service_type = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)  # Number of years of experience
    description = db.Column(db.Text)  # A brief bio or professional description
    verified = db.Column(db.Boolean, default=False)  # Verification status (admin approval)
    blocked = db.Column(db.Boolean, default=False)
    experience_proof = db.Column(db.String(255))

    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='professional', foreign_keys='ServiceRequest.professional_id')

# Service table (Stores all available services)
class Service(db.Model):
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    time_required = db.Column(db.Integer)  # in minutes or hours
    description = db.Column(db.Text)

# Service Request table (Service requests made by customers)
class ServiceRequest(db.Model):
    __tablename__ = 'service_request'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Assuming customer is stored in 'user' table
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'))  # Professional assigned
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_completion = db.Column(db.DateTime)
    service_status = db.Column(db.String(50))  # 'requested', 'assigned', 'completed', 'closed', 'rejected'
    remarks = db.Column(db.Text)
    
    # New fields for professional tracking
    contact_number = db.Column(db.String(15))  # Customer's contact number
    location = db.Column(db.Text)  # Customer's location
    location_pin_code = db.Column(db.String(10))  # Customer's pin code

    # Relationships
    service = db.relationship('Service', backref='service_requests')
    customer = db.relationship('User', foreign_keys=[customer_id])
    professional = db.relationship('Professional', foreign_keys=[professional_id])

# Review table (Stores reviews for both customers and professionals)
class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # The user who is giving the review
    reviewee_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # The user being reviewed (customer or professional)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'))
    rating = db.Column(db.Integer)  # Should be checked to be between 1 and 5
    review = db.Column(db.Text)

    # Relationship
    service_request = db.relationship('ServiceRequest', backref='reviews')

# Block table (To block users by admin)
class Block(db.Model):
    __tablename__ = 'block'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    blocked_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # User being blocked

    # Relationships
    blocked_user = db.relationship('User', foreign_keys=[blocked_user_id])

with app.app_context():
    db.create_all()

    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        password_hash = generate_password_hash('admin')
        admin = User(username='admin', password_hash=password_hash, email='admin@admin.com', is_admin=True, role='admin')
        db.session.add(admin)
        db.session.commit()
