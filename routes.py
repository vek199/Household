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


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

print('routes running ---- >> ', UPLOAD_FOLDER)


def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else: 
            flash('Please login to continue')
            return redirect(url_for('login'))
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

@app.route('/')
@app.route('/')
@app.route('/index')
def index():
    if 'user_id' not in session:
        return render_template('index.html')  # Render the index page directly

    print('index opened')
    print(session['user_id'])
    print(session['role'])
    
    if session['role'] == 'admin':
        return redirect(url_for('admin', id=session['user_id'], role=session['role']))
    elif session['role'] == 'professional':
        return redirect(url_for('professional_dashboard', id=session['user_id'], role=session['role']))
    else:
        return redirect(url_for('customer_dashboard', id=session['user_id'], role=session['role']))

    

@app.route('/login')
def login():
    print("Login route accessed")
    return render_template('login.html')

@app.route('/login',methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    print('login post working')
    if not username or not password:
        flash('Please fill all the fields','danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('user does not exist','danger')
        return redirect(url_for('login'))
    
    if not check_password_hash(user.password_hash, password):
        flash("Incorrect password",'danger')
        return redirect(url_for('login'))
    
    session['user_id'] = user.id
    session['role'] = user.role
    print('role is ', session['role'])
    flash('User Successfully logged in','success')
    if session['role']=='admin':
        return redirect(url_for('admin',id=session['user_id'],role=session['role']))
    elif session['role']=='professional':
        return redirect(url_for('professional',id=session['user_id'],role=session['role']))
    else:
        return redirect(url_for('index',id=session['user_id'],role=session['role']))


@app.route('/login')
def profile():
    print("Login route accessed")
    return render_template('login.html')

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

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

        # Create User
        new_user = User(username=username, phone_number=phone_number, email=email, role='customer')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Create Customer Profile
        customer_profile = CustomerProfile(user_id=new_user.id, address=address, 
                                           location_pin_code=location_pin_code, 
                                           preferred_services=preferred_services)
        db.session.add(customer_profile)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('customer/register.html')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


import os

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
            unique_filename = f"{uuid.uuid4().hex}_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"  # Change .png based on the actual file type
            
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
def view_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    return render_template('admin/view_professional.html', professional=professional)


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
    return render_template('admin/dashboard.html', professionals=professionals,non_verified_professionals=non_verified_professionals,verified_professionals=verified_professionals,service_requests=service_requests,users=users,customers=customers,services=services)


@app.route('/dashboard/customer')
def customer_dashboard():
    return render_template('customer/dashboard.html')


@app.route('/dashboard/professional')
def professional_dashboard():
    return 

# Route for Professional Profile
@app.route('/profile/professional/<int:user_id>')
def professional_profile(user_id):
    # Fetch professional user details based on user_id
    professional = Professional.query.filter_by(user_id=user_id).first()
    if not professional:
        return redirect(url_for('admin'))  # Handle if professional not found
    return render_template('admin/view_professional.html', professional=professional)

# Route for Customer Profile
@app.route('/profile/customer/<int:user_id>')
def customer_profile(user_id):
    # Fetch customer user details based on user_id
    customer = CustomerProfile.query.filter_by(user_id=user_id).first()
    if not customer:
        return redirect(url_for('admin'))  # Handle if customer not found
    return render_template('admin/view_customer.html', customer=customer)

@app.route('/service/add')
@auth_required  # Ensure only logged-in users can add a service
def add_service():
    return render_template('admin/add.html')

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
@app.route('/service/edit/<int:service_id>')
def edit_service(user_id):

    return ''

# Route for delete service
@app.route('/service/delete/<int:service_id>')
def delete_service(user_id):
    return ''

# Route for Block
@app.route('/delete/<int:user_id>')
def block(user_id):

    return ''

# Route for view review
@app.route('/review/<int:user_id>')
def view_reviews(user_id):
    return ''

# Route for approving a professional
@app.route('/professional/approve/<int:professional_id>')
def approve_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    professional.verified = True
    db.session.commit()
    flash(f'Professional {professional.user.username} has been approved.', 'success')
    return redirect(url_for('admin'))  # Redirect to admin dashboard

# Route for rejecting a professional
@app.route('/professional/reject/<int:professional_id>')
def reject_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    db.session.delete(professional)
    db.session.commit()
    flash(f'Professional {professional.user.username} has been rejected and removed.', 'success')
    return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard

# Route for deleting a professional
@app.route('/professional/delete/<int:professional_id>')
def delete_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    db.session.delete(professional)
    db.session.commit()
    flash(f'Professional {professional.user.username} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard






