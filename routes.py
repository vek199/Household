from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import *
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
import os
import uuid
from uuid import uuid4
from functools import wraps
from datetime import datetime
from app import app
from sqlalchemy.orm import aliased, joinedload
from sqlalchemy import func




UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}


def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):

        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        blocked_user = Block.query.filter_by(blocked_user_id=user.id).first()
        if blocked_user:
            flash('You have been blocked from using this service.')
            return redirect(url_for('blocked')) 

        return func(*args, **kwargs)
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner



@app.route('/admin/summary', methods=['GET'])
def admin_summary():
    return render_template('admin/summary.html')
    
@app.route('/api/admin/summary', methods=['GET'])
def admin_summary_api():
    # Fetch average customer ratings for professionals, handling None values
    avg_customer_ratings = db.session.query(
        Professional.user_id.label('professional_id'),
        db.func.coalesce(db.func.avg(Review.rating), 0).label('avg_rating')
    ).join(ServiceRequest, ServiceRequest.professional_id == Professional.user_id) \
     .join(Review, Review.service_request_id == ServiceRequest.id) \
     .filter(Review.reviewee_id == Professional.user_id) \
     .group_by(Professional.user_id).all()
    
    avg_customer_ratings = [
        {"professional_id": rating.professional_id, "avg_rating": rating.avg_rating or 0}
        for rating in avg_customer_ratings
    ]

    # Fetch average professional ratings for customers, handling None values
    avg_professional_ratings = db.session.query(
        User.id.label('customer_id'),
        db.func.coalesce(db.func.avg(Review.rating), 0).label('avg_rating')
    ).join(ServiceRequest, ServiceRequest.customer_id == User.id) \
     .join(Review, Review.service_request_id == ServiceRequest.id) \
     .filter(Review.reviewee_id == User.id) \
     .group_by(User.id).all()

    avg_professional_ratings = [
        {"customer_id": rating.customer_id, "avg_rating": rating.avg_rating or 0}
        for rating in avg_professional_ratings
    ]

    # Count services booked
    services_booked = db.session.query(
        Service.name,
        db.func.count(ServiceRequest.id).label('count')
    ).join(ServiceRequest, Service.id == ServiceRequest.service_id) \
     .group_by(Service.id).all()

    services_booked = [
        {"service_name": service, "count": count}
        for service, count in services_booked
    ]

    # Count service request statuses
    service_status_counts = {
        'Requested': db.session.query(db.func.count(ServiceRequest.id))
                        .filter(ServiceRequest.service_status == 'Requested').scalar(),
        'Assigned': db.session.query(db.func.count(ServiceRequest.id))
                        .filter(ServiceRequest.service_status == 'Assigned').scalar(),
        'Closed': db.session.query(db.func.count(ServiceRequest.id))
                        .filter(ServiceRequest.service_status == 'Closed').scalar(),
        'Cancelled': db.session.query(db.func.count(ServiceRequest.id))
                        .filter(ServiceRequest.service_status == 'Cancelled').scalar()
    }

    service_status_data = [
        {"status": status, "count": count or 0}
        for status, count in service_status_counts.items()
    ]

    # Return sanitized data as JSON response
    return jsonify({
        "avg_customer_ratings": avg_customer_ratings,
        "avg_professional_ratings": avg_professional_ratings,
        "services_booked": services_booked,
        "service_status_counts": service_status_data
    })




@app.route('/')
@app.route('/index')
def index():
    if 'user_id' not in session:
        services = Service.query.all()
        return render_template('index.html',services=services)  # Render the index page directly

    print('Index opened')
    print(session['user_id'])
    print(session['role'])

    if session['role'] == 'admin':
        return redirect(url_for('admin'))
    elif session['role'] == 'professional':
        return redirect(url_for('professional_dashboard'))
    else:
        return redirect(url_for('customer_dashboard'))


@app.route('/search')
@auth_required
def search():
    if 'user_id' not in session:
        return render_template('index.html')  # Render the index page directly

    print('Index opened')
    print(session['user_id'])
    print(session['role'])

    if session['role'] == 'admin':
        return redirect(url_for('admin_search'))
    elif session['role'] == 'professional':
        return redirect(url_for('professional_search'))
    else:
        return redirect(url_for('customer_search'))

@app.route('/summary')
@auth_required
def summary():
    if 'user_id' not in session:
        return render_template('index.html')  # Render the index page directly

    print('Index opened')
    print(session['user_id'])
    print(session['role'])

    if session['role'] == 'admin':
        return redirect(url_for('admin_summary'))
    elif session['role'] == 'professional':
        return redirect(url_for('professional_summary'))
    else:
        return redirect(url_for('customer_summary'))
    

@app.route('/login')
def login():
    print("Login route accessed")
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    print('login post working')
    if not username or not password:
        flash('Please fill all the fields', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User does not exist', 'danger')
        return redirect(url_for('login'))

    if not check_password_hash(user.password_hash, password):
        flash("Incorrect password", 'danger')
        return redirect(url_for('login'))

    session['user_id'] = user.id
    session['role'] = user.role
    print('Role is ', session['role'])
    flash('User successfully logged in', 'success')

    if session['role'] == 'admin':
        return redirect(url_for('admin', id=session['user_id'], role=session['role']))
    elif session['role'] == 'professional':
        return redirect(url_for('professional_dashboard', id=session['user_id'], role=session['role']))
    else:
        return redirect(url_for('index', id=session['user_id'], role=session['role']))


@app.route('/blocked')
def blocked():
    return render_template('blocked.html') 


@app.route('/logout')
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))
from flask import render_template, request, redirect, url_for, flash
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from models import db, User, CustomerProfile  # Adjust based on your app structure

@app.route('/register/customer', methods=['GET', 'POST'])
def register_customer():
    if request.method == 'POST':
        username = request.form['username']
        phone_number = request.form['phone_number']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        address = request.form['address']
        location_pin_code = request.form['location_pin_code']
        preferred_services = request.form['preferred_services']

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register_customer'))

        # Check for duplicate email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered!', 'danger')
            return redirect(url_for('register_customer'))

        try:
            # Create User
            new_user = User(
                username=username,
                phone_number=phone_number,
                email=email,
                role='customer',
                is_active=True
            )
            new_user.set_password(password)  # Assuming this sets the hashed password
            db.session.add(new_user)
            db.session.commit()

            # Create Customer Profile
            customer_profile = CustomerProfile(
                user_id=new_user.id,
                address=address,
                location_pin_code=location_pin_code,
                preferred_services=preferred_services
            )
            db.session.add(customer_profile)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            db.session.rollback()  # Rollback to maintain database consistency
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register_customer'))

    return render_template('customer/register.html')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


import os
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

print('Routes running ---- >> ', UPLOAD_FOLDER)

@app.route('/register/professional', methods=['GET', 'POST'])
def register_professional():
    if request.method == 'POST':
        username = request.form['username']
        phone_number = request.form['phone_number']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        service_type = request.form['service_type']
        experience = request.form['experience']
        description = request.form['description']
        file = request.files['experience_proof']

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register_professional'))

        # Validate file upload
        if file and allowed_file(file.filename):
            # Generate a secure filename with professional name
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            sanitized_username = secure_filename(username.replace(" ", "_"))  # Replace spaces with underscores
            unique_filename = f"{sanitized_username}_{uuid.uuid4().hex}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file_extension}"
            
            # Check if the upload folder exists, if not create it
            upload_folder = app.config['UPLOAD_FOLDER']
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            file_path = os.path.join(upload_folder, unique_filename)
            print(f"Saving file to: {file_path}")  # Debugging
            
            # Save the file, handle potential errors
            try:
                file.save(file_path)
            except Exception as e:
                flash(f"Error saving file: {e}", 'danger')
                return redirect(url_for('register_professional'))
        
            # Create User
            new_user = User(username=username, phone_number=phone_number, email=email, role='professional')
            new_user.set_password(password)

            try:
                # Add user to session and commit
                db.session.add(new_user)
                db.session.commit()  # Commit here to get the new_user.id

                # Create Professional Profile
                professional_profile = Professional(
                    user_id=new_user.id, 
                    service_type=service_type, 
                    experience=experience, 
                    description=description,
                    experience_proof=unique_filename
                )
                db.session.add(professional_profile)
                db.session.commit()  # Commit the professional profile

                flash('Registration successful!', 'success')
                return redirect(url_for('login'))

            except IntegrityError as e:
                # Rollback the session to avoid affecting the next transaction
                db.session.rollback()
                if "UNIQUE constraint failed: user.username" in str(e):
                    flash('Error: Username already exists. Please choose a different one.', 'error')
                elif "UNIQUE constraint failed: user.email" in str(e):
                    flash('Error: Email already exists. Please choose a different one.', 'error')
                else:
                    flash('An error occurred during registration. Please try again.', 'error')
                return redirect(url_for('register_professional'))

    services = Service.query.all()
    return render_template('professional/register.html', services=services)

@app.route('/admin/professional/<int:professional_id>')
@admin_required
def view_professional(professional_id):
    professional = Professional.query.get(professional_id)
    
    if professional is None:
        # Handle the case when the professional is not found
        return "Professional not found", 404
    return render_template('admin/view_professional.html', professional=professional)

@app.route('/admin/customer/<int:customer_id>')
@admin_required
def view_customer(customer_id):
    customer = CustomerProfile.query.get(customer_id)
    
    if customer is None:
        # Handle the case when the professional is not found
        return "customer not found", 404
    return render_template('admin/view_customer.html', customer=customer)



@app.route('/admin')
@admin_required
def admin():
    # Fetch all professionals from the database
    professionals = Professional.query.all()
    users = User.query.all()
    customers = CustomerProfile.query.all()
    services = Service.query.all()
    service_requests = ServiceRequest.query.all()
    non_verified_professionals = Professional.query.filter_by(verified=False).all()
    verified_professionals = Professional.query.filter_by(verified=True).all()
    reviews = Review.query.all()
    blocked_users = [block.blocked_user_id for block in Block.query.all()]
    service_requests = ServiceRequest.query.options(
        joinedload(ServiceRequest.customer),
        joinedload(ServiceRequest.professional),
        joinedload(ServiceRequest.reviews)
    ).all()

    # Prepare data with ratings
    service_requests_data = []
    for request in service_requests:
        professional_review = None
        customer_review = None

        for review in request.reviews:
            if review.reviewer_id == request.customer_id and review.reviewee_id == request.professional_id:
                professional_review = review
            elif review.reviewer_id == request.professional_id and review.reviewee_id == request.customer_id:
                customer_review = review

        service_requests_data.append({
            'id': request.id,
            'professional_username': request.professional.username if request.professional else 'Not Assigned',
            'date_of_request': request.date_of_request,
            'service_status': request.service_status,
            'customer_rating': professional_review.rating if professional_review else 'N/A',
            'professional_rating': customer_review.rating if customer_review else 'N/A',
        })
    
    # servicecategory = ServiceCategory.query.all()

    return render_template('admin/dashboard.html',service_requests=service_requests_data,reviews=reviews,blocked_users=blocked_users, professionals=professionals,non_verified_professionals=non_verified_professionals,verified_professionals=verified_professionals,users=users,customers=customers,services=services)


@app.route('/dashboard/customer')
@auth_required
def customer_dashboard():
    professionals = Professional.query.all()
    users = User.query.all()
    customers = CustomerProfile.query.all()
    services = Service.query.all()
    non_verified_professionals = Professional.query.filter_by(verified=False).all()
    verified_professionals = Professional.query.filter_by(verified=True).all()
    review=Review.query.all()
    user = User.query.get(session['user_id'])
    blocked_user = Block.query.filter_by(blocked_user_id=user.id).first()
    customer_id = session['user_id']
    service_requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()
    if blocked_user:
        flash('You have been blocked from using this service.')
        return redirect(url_for('blocked')) 
    return render_template('customer/dashboard.html',Review=review, professionals=professionals,non_verified_professionals=non_verified_professionals,verified_professionals=verified_professionals,service_requests=service_requests,user=users,customers=customers,services=services)






@app.route('/admin/search', methods=['GET'])
@auth_required
def admin_search():
    search_by = request.args.get('search_by')
    search_query = request.args.get('search_query')
    results = []
    columns = []

    if search_by == 'services':
        services = Service.query.filter(
            Service.name.ilike(f"%{search_query}%") |
            Service.description.ilike(f"%{search_query}%")
        ).all()
        columns = ["ID", "Name", "Price", "Description"]
        results = [[service.id, service.name, service.price, service.description] for service in services]

    elif search_by == 'customers':
        customers = User.query.filter(
            User.role == 'customer',
            (User.username.ilike(f"%{search_query}%") |
             User.email.ilike(f"%{search_query}%"))
        ).all()
        columns = ['ID', 'Username', 'Email', 'Phone Number']
        results = [[customer.id, customer.username, customer.email, customer.phone_number] for customer in customers]

    elif search_by == 'professionals':
        professionals = Professional.query.join(User).filter(
            User.username.ilike(f"%{search_query}%") |
            Professional.service_type.ilike(f"%{search_query}%"),
            Professional.verified.is_(True)
        ).all()
        columns = ['ID', 'Username', 'Service Type', 'Experience']
        results = [[prof.user_id, prof.user.username, prof.service_type, prof.experience] for prof in professionals]

    elif search_by == 'pending_professionals':
        pending_pros = Professional.query.join(User).filter(
            User.username.ilike(f"%{search_query}%") |
            Professional.service_type.ilike(f"%{search_query}%"),
            Professional.verified.is_(False)
        ).all()
        columns = ['ID', 'Username', 'Service Type', 'Experience']
        results = [[pro.user_id, pro.user.username, pro.service_type, pro.experience] for pro in pending_pros]

    elif search_by == 'service_requests':
    # Use aliased User to reference professional and customer separately
        professional_user = aliased(User)
        customer_user = aliased(User)

        requests = ServiceRequest.query \
            .join(Service) \
            .join(professional_user, professional_user.id == ServiceRequest.professional_id) \
            .join(customer_user, customer_user.id == ServiceRequest.customer_id) \
            .filter(
                (Service.name.ilike(f"%{search_query}%")) |
                (professional_user.username.ilike(f"%{search_query}%")) |  # Search by professional's username
                (customer_user.username.ilike(f"%{search_query}%")) |  # Search by customer's username
                (ServiceRequest.service_status.ilike(f"%{search_query}%")) |
                (ServiceRequest.customer_location.ilike(f"%{search_query}%")) |
                (ServiceRequest.customer_pin_code.ilike(f"%{search_query}%")) |
                (ServiceRequest.remarks.ilike(f"%{search_query}%"))
            ).all()

        columns = ['ID', 'Service Name', 'Professional Name', 'Customer Name', 'Requested Date', 'Status', 'Customer Location', 'Customer Pincode', 'Remarks']

        # Construct the results list, including the customer's and professional's name
        results = [[
            request.id,
            request.service.name,
            request.professional.user.username,  # Professional's username (through user relationship)
            request.customer.username,  # Customer's username (through user relationship)
            request.date_of_request,
            request.service_status,
            request.customer_location,
            request.customer_pin_code,
            request.remarks
        ] for request in requests]


    elif search_by == 'blocked':
        blocked_users = User.query.filter(
            User.is_active == False,
            (User.username.ilike(f"%{search_query}%") |
             User.email.ilike(f"%{search_query}%"))
        ).all()
        columns = ['ID', 'Username', 'Email']
        results = [[user.id, user.username, user.email] for user in blocked_users]

    return render_template('admin/search.html', results=results,search_by=search_by, search_query=search_query, columns=columns)


@app.route('/customer/search', methods=['GET'])
@auth_required
def customer_search():
    search_by = request.args.get('search_by')
    search_query = request.args.get('search_query')
    results = []
    columns = []
    if search_by == 'service_name' and search_query:
        print(Service.query.all())
        services = Service.query.filter(Service.name.ilike(f"%{search_query}%")).all()
        columns = ["ID", "Service Name", "Price", "Description"]
        results = [[service.id, service.name, service.price, service.description] for service in services]

    elif search_by == 'pincode' and search_query:
        requests = ServiceRequest.query.filter(
            ServiceRequest.customer_pin_code.ilike(f"%{search_query}%")
        ).all()
        columns = ["Request ID", "Service Name", "Requested Date", "Status", "Pincode"]
        results = [
            [request.id, request.service.name, request.date_of_request, request.service_status, request.customer_pin_code]
            for request in requests
        ]

    elif search_by == 'location' and search_query:
        requests = ServiceRequest.query.filter(
            ServiceRequest.customer_location.ilike(f"%{search_query}%")
        ).all()
        columns = ["Request ID", "Service Name", "Requested Date", "Status", "Location"]
        results = [
            [request.id, request.service.name, request.date_of_request, request.service_status, request.customer_location]
            for request in requests
        ]

    return render_template('customer/search.html', results=results, search_by=search_by, search_query=search_query, columns=columns)

@app.route('/professional/search', methods=['GET'])
def professional_search():
    search_by = request.args.get('search_by')
    search_query = request.args.get('search_query')
    results = []
    columns = []

    if search_by == 'location':
        service_requests = ServiceRequest.query.filter(
            ServiceRequest.customer_location.ilike(f"%{search_query}%")
        ).all()
        columns = ['ID', 'Service Name', 'Professional Name', 'Customer Name', 'Location', 'Service Status']
        results = [
            [
                request.id,
                request.service.name,
                request.professional.username,
                request.customer.username,
                request.customer_location,
                request.service_status
            ]
            for request in service_requests
        ]

    elif search_by == 'date':
        try:
            date_filter = datetime.strptime(search_query, "%Y-%m-%d")
            service_requests = ServiceRequest.query.filter(
                ServiceRequest.date_of_request == date_filter
            ).all()
            columns = ['ID', 'Service Name', 'Professional Name', 'Customer Name', 'Requested Date', 'Service Status']
            results = [
                [
                    request.id,
                    request.service.name,
                    request.professional.username,
                    request.customer.username,
                    request.date_of_request,
                    request.service_status
                ]
                for request in service_requests
            ]
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return redirect(url_for('professional_search'))

    elif search_by == 'pincode':
        service_requests = ServiceRequest.query.filter(
            ServiceRequest.customer_pin_code.ilike(f"%{search_query}%")
        ).all()
        columns = ['ID', 'Service Name', 'Professional Name', 'Customer Name', 'Pincode', 'Service Status']
        results = [
            [
                request.id,
                request.service.name,
                request.professional.username,
                request.customer.username,
                request.customer_pin_code,
                request.service_status
            ]
            for request in service_requests
        ]

    return render_template('professional/search.html', results=results, search_by=search_by, search_query=search_query, columns=columns)


# Route for Professional Profile
@app.route('/profile/professional/<int:user_id>')
@auth_required
def professional_profile(user_id):
    # Fetch professional user details based on user_id
    professional = Professional.query.filter_by(user_id=user_id).first()

    # Check if professional exists
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect(url_for('admin'))

    # Check if role is 'professional'
    if professional.user.role != 'professional': 
        flash('Unauthorized access.', 'danger')  
        return redirect(url_for('index'))
    
    # Render profile if checks pass
    return render_template('professional/profile.html', professional=professional)


@app.route('/profile', methods=['GET'])
@auth_required
def customer_profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))

    if user.role != 'customer':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))

    return render_template('customer/profile.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@auth_required
def edit_customer_profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))

    if user.role != 'customer':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        address = request.form.get('address', '').strip()
        location_pin_code = request.form.get('location_pin_code', '').strip()

        # Validate inputs
        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long.")
        if not email or '@' not in email or '.' not in email:
            errors.append("Please provide a valid email address.")
        if not phone_number.isdigit() or len(phone_number) != 10:
            errors.append("Phone number must be exactly 10 digits.")
        if not address or len(address) < 5:
            errors.append("Address must be at least 5 characters long.")
        if not location_pin_code.isdigit() or len(location_pin_code) != 6:
            errors.append("Pin code must be exactly 6 digits.")

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('customer/edit_profile.html', user=user)

        # Update user fields
        user.username = username
        user.email = email
        user.phone_number = phone_number

        if hasattr(user, 'customer_profile'):
            user.customer_profile.address = address
            user.customer_profile.location_pin_code = location_pin_code

        try:
            # Save changes to the database
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')

        return redirect(url_for('customer_profile'))

    return render_template('customer/edit_profile.html', user=user)
 

@app.route('/service/add')
@auth_required  # Ensure only logged-in users can add a service
def add_service():
    return render_template('admin/service/add.html')

@app.route('/service/add', methods=['POST'])
@auth_required
def add_service_post():
    name = request.form.get('name')
    price = request.form.get('price')
    time_required = request.form.get('time_required')
    description = request.form.get('description')

    # Validate the input
    if not name or not price or not time_required or not description:
        flash('Please fill in all fields.', 'warning')
        return redirect(url_for('add_service'))

    # Create a new service
    service = Service(name=name, price=price, time_required=time_required, description=description)
    db.session.add(service)
    db.session.commit()

    flash('Service added successfully!', 'success')
    return redirect(url_for('admin'))


# Route for edit service
@app.route('/service/edit/<int:service_id>', methods=['GET', 'POST'])
def edit_service_admin(service_id):
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.name = request.form['name']
        service.price = request.form['price']
        service.time_required = request.form['time_required']
        service.description = request.form['description']
        
        db.session.commit()
        flash('Service updated successfully', 'success')
        return redirect(url_for('admin'))

    return render_template('admin/service/edit.html', service=service)

# Route for delete service
@app.route('/service/delete/<int:service_id>', methods=['POST'])
def delete_service_admin(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully', 'success')
    return redirect(url_for('admin'))

# Route for Block
@app.route('/block/<int:user_id>')
def block_user(user_id):
    # Check if user is already blocked
    if not Block.query.filter_by(blocked_user_id=user_id).first():
        new_block = Block(blocked_user_id=user_id)
        db.session.add(new_block)
        db.session.commit()
        flash('User has been blocked.')
    else:
        flash('User is already blocked.')
    return redirect(url_for('admin'))

@app.route('/unblock/<int:user_id>')
def unblock_user(user_id):
    blocked_user = Block.query.filter_by(blocked_user_id=user_id).first()
    if blocked_user:
        db.session.delete(blocked_user)
        db.session.commit()
        flash('User has been unblocked.','success')
    else:
        flash('User is not blocked.')
    return redirect(url_for('admin'))

@app.route('/reviews/<int:user_id>')
def view_reviews(user_id):
    user = User.query.get(user_id)  # Get user profile
    
    # Directly filter reviews where the current user is the reviewee
    reviews = Review.query.filter_by(reviewee_id=user_id).all()
    reviews = Review.query.filter_by(reviewee_id=user_id).all()
    print(reviews)  # Output reviews for debugging

    return render_template('reviews.html', user=user, reviews=reviews)


# Route for approving a professional
@app.route('/professional/approve/<int:id>', methods=['POST'])
def approve_professional(id):
    professional = Professional.query.get_or_404(id)
    professional.verified = True
    db.session.commit()
    flash(f'Professional {professional.user.username} has been approved.', 'success')
    return redirect(url_for('admin'))  # Redirect to admin dashboard

# Route for rejecting a professional
@app.route('/professional/reject/<int:id>', methods=['POST'])
def reject_professional(id):
    professional = Professional.query.get(id)
    if not professional:
        flash('Professional not found.', 'danger')
        return redirect(url_for('admin'))

    try:
        professional_name = professional.user.username  # Store the name before deletion
        db.session.delete(professional)
        db.session.commit()
        flash(f'Professional {professional_name} has been rejected and removed.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while rejecting the professional: {str(e)}', 'danger')
    return redirect(url_for('admin'))  # Redirect to admin dashboard

# Route for deleting a professional
@app.route('/professional/delete/<int:id>', methods=['POST'])
def delete_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    db.session.delete(professional)
    db.session.commit()
    flash(f'Professional {professional.user.username} has been deleted.', 'success')
    return redirect(url_for('admin')) # Redirect to admin dashboard

@app.route('/services/<int:service_id>')
@auth_required
def list_services(service_id):
    service = Service.query.get_or_404(service_id)
    professionals = Professional.query.filter_by(service_type=service.name).all()
    customer_id = session['user_id']
    service_requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()
    user = User.query.get_or_404(customer_id)

    return render_template('customer/service.html', user=user,service=service, professionals=professionals,service_requests=service_requests)


@app.route('/book_service/<int:professional_id>/<int:service_id>', methods=['POST'])
def book_service(professional_id, service_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    customer_id = session['user_id']
    customer_profile = CustomerProfile.query.filter_by(user_id=customer_id).first()

    service_request = ServiceRequest(
        customer_id=customer_id,
        professional_id=professional_id,
        service_id=service_id,
        service_status='Requested',
        customer_location=customer_profile.address,  
        customer_pin_code=customer_profile.location_pin_code
    )
    
    db.session.add(service_request)
    db.session.commit()

    return redirect(url_for('list_services', service_id=service_id))  # Redirect back to service list



@app.route('/cancel_service/<int:request_id>', methods=['POST'])
def cancel_service(request_id):
    # Logic to cancel the service request, e.g., update status in the database
    service_request = ServiceRequest.query.get(request_id)
    service_request.service_status = 'Cancelled'
    db.session.commit()
    flash('Service request cancelled successfully.','success')
    return redirect(url_for('index'))  # Redirect back to service list

@app.route('/close_and_review/<int:request_id>', methods=['GET', 'POST'])
def close_and_review_service(request_id):
    # Ensure that only the customer can close and review the request
    if 'user_id' not in session:
            flash('Only customer can close a request')
            return redirect(url_for('login'))

    service_request = ServiceRequest.query.get(request_id)
    if not service_request:
        flash("Service request not found.", 'danger')
        return redirect(url_for('customer_dashboard'))
    
    # Check if the service request is already closed
    if service_request.service_status == "Closed":
        flash("This service request is already closed.", 'info')
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        # Handle the submission of the review form
        rating = request.form.get('rating')
        remarks = request.form.get('remarks')

        if not rating:
            flash("Please provide a rating.", 'warning')
            return redirect(url_for('close_and_review_service', request_id=request_id))

        # Update the request status to "Closed" and add the review details
        service_request.service_status = "Closed"
        service_request.date_of_completion = datetime.utcnow()
        review = Review(
            reviewer_id=session['user_id'],
            reviewee_id=service_request.professional_id,
            service_request_id=service_request.id,
            rating=int(rating),
            review=remarks
        )
        db.session.add(review)

        db.session.commit()
        flash("Service request closed and review submitted successfully.", 'success')
        return redirect(url_for('customer_dashboard'))

    # If GET request, show the review form
    return render_template('customer/review_service.html', service_request=service_request, service=service_request.service, professional=service_request.professional)

@app.route('/professional_review/<int:request_id>', methods=['GET', 'POST'])
def professional_review_customer(request_id):
    if 'user_id' not in session or session['role'] != 'professional':
        flash("Only professionals can review customers.", 'danger')
        return redirect(url_for('login'))

    service_request = ServiceRequest.query.get(request_id)
    if not service_request or service_request.service_status != "Closed":
        flash("Service request not found or not closed by the customer.", 'danger')
        return redirect(url_for('professional_dashboard'))

    if request.method == 'POST':
        rating = request.form.get('rating')
        review_text = request.form.get('review')

        if not rating:
            flash("Please provide a rating.", 'warning')
            return redirect(url_for('professional_review_customer', request_id=request_id))

        # Create review entry
        review = Review(
            reviewer_id=session['user_id'],
            reviewee_id=service_request.customer_id,
            service_request_id=service_request.id,
            rating=int(rating),
            review=review_text
        )
        db.session.add(review)
        db.session.commit()
        flash("Review submitted successfully.", 'success')
        return redirect(url_for('professional_dashboard'))

    # GET request to render the form
    customer = service_request.customer
    return render_template('professional/review_customer.html', service_request=service_request, customer=customer)

@app.route('/dashboard/professional')
def professional_dashboard():
    # Get the logged-in user's ID from the session
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Fetch the professional profile linked to the logged-in user
    professional = Professional.query.filter_by(user_id=user_id).first()
    if not professional:
        return redirect(url_for('login'))

    # Check if the user is blocked
    blocked_user = Block.query.filter_by(blocked_user_id=user_id).first()
    if blocked_user:
        flash('You have been blocked from using this service.')
        return redirect(url_for('blocked')) 

    # Calculate the average rating for the professional
    avg_rating = professional.average_rating
    if avg_rating is not None:
        print(f"Average Rating: {avg_rating}")
    else:
        print("No reviews available for this professional.")

    # Fetch service requests related to the professional
    professional_id = professional.user_id
    active_request = ServiceRequest.query.filter_by(professional_id=professional_id).filter(
        ServiceRequest.service_status.ilike('assigned')
    ).first()
    requests = ServiceRequest.query.filter_by(professional_id=professional_id).filter(
        ServiceRequest.service_status.ilike('Requested')
    ).all()
    closed_requests = ServiceRequest.query.filter_by(professional_id=professional_id).filter(
        ServiceRequest.service_status.ilike('Closed')
    ).all()

    # Debugging outputs to verify data fetching
    print(f"Professional ID: {professional_id}")
    print('Active request:', active_request)
    print('Requested services:', requests)
    print('Closed services:', closed_requests)

    # Render the dashboard template with all necessary data
    return render_template(
        'professional/dashboard.html',
        active_request=active_request,
        requests=requests,
        closed_requests=closed_requests,
        current_professional=professional,
        avg_rating=avg_rating  # Pass the average rating to the template
    )


@app.route('/accept_request/<int:request_id>', methods=['POST'])
def professional_accept_request(request_id):
    if 'user_id' not in session:
        flash("You need to be logged in to accept requests.")
        return redirect(url_for('login'))

    professional = Professional.query.filter_by(user_id=session['user_id']).first()
    if not professional:
        flash("You are not authorized to accept requests.")
        return redirect(url_for('dashboard'))

    active_request = ServiceRequest.query.filter_by(professional_id=professional.user_id, service_status='assigned').first()
    if active_request:
        flash("You already have an active service request. Complete it before accepting another.")
        return redirect(url_for('professional_dashboard'))

    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        service_request.service_status = 'assigned'
        service_request.professional_id = professional.user_id
        professional.location = service_request.customer_location
        db.session.commit()

    flash("Service request accepted successfully.", 'success')
    return redirect(url_for('professional_dashboard'))


@app.route('/admin/service_request_details/<int:service_request_id>', methods=['GET'])
def service_request_details(service_request_id):
    service_request = ServiceRequest.query.get(service_request_id)
    
    # Check if service request exists
    if not service_request:
        return "Service request not found", 404

    return render_template('admin/service_request_details.html', service_request=service_request)
from flask import jsonify



    
 
@app.route('/customer/summary')
def customer_summary():
    id = session.get('user_id')
    service_requests = ServiceRequest.query.filter_by(customer_id=id).order_by(ServiceRequest.service_status).all()
    
    status_count = {}
    for request in service_requests:
        status_count[request.service_status] = status_count.get(request.service_status, 0) + 1
    
    return render_template('customer/summary.html', service_requests=service_requests, status_count=status_count)
@app.route('/professional/summary')
def professional_summary():
    professional_id = session.get('user_id')
    if not professional_id:
        return "Professional ID not found in session."

    # Fetch reviews for the professional
    reviews = Review.query.filter_by(reviewee_id=professional_id).all()
    print(f"Reviews found: {reviews}")

    # Calculate average rating
    avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.reviewee_id == professional_id).scalar()
    avg_rating = avg_rating if avg_rating is not None else 0
    print(f"Average rating: {avg_rating}")

    # Fetch service requests for the professional
    service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
    print(f"Service Requests found: {service_requests}")

    assigned_requests = [sr for sr in service_requests if sr.service_status == 'Assigned']
    closed_requests = [sr for sr in service_requests if sr.service_status == 'Closed']
    cancelled_requests = [sr for sr in service_requests if sr.service_status == 'Cancelled']
    requested_requests = [sr for sr in service_requests if sr.service_status == 'Requested']

    service_status_counts = {
        'Assigned': len(assigned_requests),
        'Closed': len(closed_requests),
        'Cancelled': len(cancelled_requests),
        'Requested': len(requested_requests)
    }
    print(ServiceRequest.query.first())
    print(Review.query.first())
    return render_template(
        'professional/summary.html',
        reviews=reviews,
        avg_rating=avg_rating,
        service_status_counts=service_status_counts
    )

@app.route('/payment')
def payment():
    return render_template('payments.html')

@app.route('/make_payment', methods=['POST'])
def make_payment():
    return redirect(url_for('index'))
