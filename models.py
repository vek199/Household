from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import app
from flask_migrate import Migrate

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    phone_number = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    customer_profile = db.relationship('CustomerProfile', backref='user', uselist=False)
    professional_profile = db.relationship('Professional', backref='user', uselist=False)
    service_requests_as_customer = db.relationship('ServiceRequest', backref='customer', foreign_keys='ServiceRequest.customer_id')
    service_requests_as_professional = db.relationship('ServiceRequest', backref='professional', foreign_keys='ServiceRequest.professional_id')
    reviews_written = db.relationship('Review', back_populates='reviewer', foreign_keys='Review.reviewer_id')
    reviews_received = db.relationship('Review', back_populates='reviewee', foreign_keys='Review.reviewee_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class CustomerProfile(db.Model):
    __tablename__ = 'customer_profile'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    address = db.Column(db.Text)
    location_pin_code = db.Column(db.String(10))
    blocked = db.Column(db.Boolean, default=False)
    preferred_services = db.Column(db.Text)


class Professional(db.Model):
    __tablename__ = 'professional'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service_type = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    description = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)
    blocked = db.Column(db.Boolean, default=False)
    experience_proof = db.Column(db.String(255))

    @property
    def average_rating(self):
        try:
            reviews = Review.query.filter_by(reviewee_id=self.user_id).all()
            if reviews:
                total_rating = sum(review.rating for review in reviews)
                return round(total_rating / len(reviews), 2)
            return None
        except Exception as e:
            print(f"Error calculating average rating: {e}")
            return None


class Service(db.Model):
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    time_required = db.Column(db.Integer)
    description = db.Column(db.Text)


class ServiceRequest(db.Model):
    __tablename__ = 'service_request'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    professional_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_completion = db.Column(db.DateTime)
    service_status = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    contact_number = db.Column(db.String(15))
    customer_location = db.Column(db.Text)
    customer_pin_code = db.Column(db.String(10))
    closed_by = db.Column(db.String(50))  # Can be 'customer' or 'professional'
    date_closed = db.Column(db.DateTime)

    # Relationships
    service = db.relationship('Service', backref='requests')
    reviews = db.relationship('Review', back_populates='service_request', lazy=True)


class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    service_request = db.relationship('ServiceRequest', back_populates='reviews')
    reviewer = db.relationship('User', foreign_keys=[reviewer_id])
    reviewee = db.relationship('User', foreign_keys=[reviewee_id])

    __table_args__ = (
        db.UniqueConstraint('reviewer_id', 'service_request_id', name='unique_reviewer_service_request'),
    )


class Block(db.Model):
    __tablename__ = 'block'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    blocked_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    blocked_user = db.relationship('User', foreign_keys=[blocked_user_id])


# Initialize the database tables and create an admin user if none exists
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(username='admin', email='admin@admin.com', role='admin', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
