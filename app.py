from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import re
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import numpy as np #Import numpy
from werkzeug.utils import secure_filename #Import secure_filename
import os
from datetime import datetime #Import datetime for date handling
from collections import defaultdict
from flask_migrate import Migrate
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView, expose

#################Configurations#####################
app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Or your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your mail server
app.config['MAIL_PORT'] = 587  # Or 465 for SSL
app.config['MAIL_USE_TLS'] = True  # Or False for SSL
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Replace with your email password or app password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure upload folder - CORRECT WAY
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads') #Correct way to define the upload folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Ensure the uploads folder exists

#################### Database Models###########################


#User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Added email field
    password_hash = db.Column(db.String(128), nullable=False)
    profile_image = db.Column(db.String(255), nullable=True)  # Add profile_image field
    role = db.Column(db.String(50), nullable=False)  # Add role field

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def profile_image_url(self):
        if self.profile_image:
            return url_for('static', filename='uploads/' + self.profile_image)
        return url_for('static', filename='uploads/default_profile.png')  # Default profile image

#Project
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)  # Add category field
    target_customer = db.Column(db.String(100), nullable=False)  # Add target_customer field
    country = db.Column(db.String(100), nullable=False)  # Add country field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    has_market_map = db.Column(db.Boolean, default=False)  # EXACTLY like this
    shared_users = db.relationship('User', secondary='project_user', backref='shared_projects')
    value_drivers = db.relationship('ValueDriver', cascade='all, delete-orphan', backref='project')
    products = db.relationship('Product', cascade='all, delete-orphan', backref='project')
    comments = db.relationship('Comment', cascade='all, delete-orphan', backref='project')
    comparison_results = db.relationship('ComparisonResult', cascade='all, delete-orphan', backref='project')

# Association table for shared projects with pending status
project_user = db.Table('project_user',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('status', db.String(10), default='pending')  # Add status column
)

# Value Driver
class ValueDriver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value_driver = db.Column(db.String(100), nullable=False)
    measured_by = db.Column(db.String(100))
    technical_attributes = db.Column(db.Text, nullable=True)  # Add technical_attributes field
    weighting = db.Column(db.Float, default=0.0)  # Changed to Float for more precision
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    ratings = db.relationship('Rating', cascade='all, delete-orphan', backref='value_driver')

#Product
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brand_name = db.Column(db.String(100), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float)
    currency = db.Column(db.String(3), default='gbp')  # Add currency field with default
    image_filename = db.Column(db.String(255))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    price_source = db.Column(db.String(255))  # Add price_source field
    ratings = db.relationship('Rating', cascade='all, delete-orphan', backref='product')

# Price History
class PriceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    old_price = db.Column(db.Float, nullable=False)
    new_price = db.Column(db.Float, nullable=False)
    date_changed = db.Column(db.DateTime, default=datetime.utcnow)

def allowed_file(filename):
    """
    Checks if the filename extension is allowed.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#ratings
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    value_driver_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)
    score = db.Column(db.Integer)
    date_rated = db.Column(db.DateTime, default=datetime.utcnow) #Add date rated to the database
    note = db.relationship('RatingNote', cascade='all, delete-orphan', backref='rating', uselist=False)

# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))  # Add this line!
    replies = db.relationship('Reply', cascade='all, delete-orphan', backref='comment')
    likes = db.relationship('Like', cascade='all, delete-orphan', backref='comment')

class ComparisonResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    value_driver_a_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)
    value_driver_b_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)
    winner_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)

# Like Model
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)

# Reply Model
class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)

# Rating Note Model
class RatingNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating_id = db.Column(db.Integer, db.ForeignKey('rating.id'), nullable=False)
    note = db.Column(db.Text, nullable=True)

class MarketingMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=False)

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        if current_user.role != 'admin':
            flash('You are not authorized to access the admin panel.', 'danger')
            return redirect(url_for('dashboard'))
        user_count = User.query.count()
        roles = db.session.query(User.role, db.func.count(User.role)).group_by(User.role).all()
        role_data = {role: count for role, count in roles}
        return self.render('admin/index.html', user=current_user, user_count=user_count, role_data=role_data)

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('dashboard'))

admin = Admin(app, index_view=MyAdminIndexView(), template_mode='bootstrap4')
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Project, db.session))
admin.add_view(SecureModelView(ValueDriver, db.session))
admin.add_view(SecureModelView(Product, db.session))
admin.add_view(SecureModelView(Rating, db.session))
admin.add_view(SecureModelView(Comment, db.session))
admin.add_view(SecureModelView(Reply, db.session))
admin.add_view(SecureModelView(Like, db.session))
admin.add_view(SecureModelView(RatingNote, db.session))
admin.add_view(SecureModelView(ComparisonResult, db.session))
admin.add_view(SecureModelView(MarketingMessage, db.session))

############################## Routes  #######################################################################
###########Routes For Logging a user in ##############

#Register

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')

        if not username or not email or not password or not confirm_password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use a different email address.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        #Email Validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        # Determine role
        if User.query.count() == 0:
            role = 'admin'
        else:
            role = 'standard'

        new_user = User(username=username, email=email, role=role) #Added role to user creation
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')  # Get email from form
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first() # Query by email

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger') # Updated flash message

    return render_template('login.html')

#Logout

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Forgot Password

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            msg = Message('Password Reset Request', recipients=[user.email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Your reset password link is: {link}'
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'info')
            except Exception as e:
                print(f"Error sending email: {e}") #Print error for debugging
                flash('An error occurred while sending the email. Please try again later.', 'danger')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

#Reset Password

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        user.set_password(password)
        db.session.commit()
        flash('Your password has been reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


################## Routes for Home Page ####################

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role == 'standard':
        user_projects_count = Project.query.filter_by(user_id=current_user.id).count()
        if user_projects_count >= PREMIUM_CONDITIONS['max_projects']:
            flash('You have reached the maximum number of projects for a standard account. Upgrade to a premium account to create more projects.', 'warning')

    if request.method == 'POST':
        if current_user.role == 'standard':
            user_projects_count = Project.query.filter_by(user_id=current_user.id).count()
            if user_projects_count >= PREMIUM_CONDITIONS['max_projects']:
                flash('Upgrade to a premium account to create more projects.', 'warning')
                return redirect(url_for('upgrade'))

        name = request.form.get('name')
        category = request.form.get('category')
        target_customer = request.form.get('target_customer')
        country = request.form.get('country')

        if not name or not category or not target_customer or not country:
            flash("All fields are required.", 'danger')
            return redirect(url_for('dashboard'))

        new_project = Project(
            name=name,
            category=category,
            target_customer=target_customer,
            country=country,
            user_id=current_user.id
        )
        db.session.add(new_project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('dashboard'))

    projects = Project.query.filter_by(user_id=current_user.id).all()
    shared_projects = Project.query.join(project_user).filter(
        project_user.c.user_id == current_user.id,
        project_user.c.status == 'accepted'
    ).all()
    pending_invitations = Project.query.join(project_user).filter(
        project_user.c.user_id == current_user.id,
        project_user.c.status == 'pending'
    ).all()

    pending_invitations_with_owners = [(project, User.query.get(project.user_id)) for project in pending_invitations]

    # Fetch the active marketing message
    marketing_message = MarketingMessage.query.filter_by(is_active=True).first()
    marketing_message_dict = {
        'content': marketing_message.content,
        'is_active': marketing_message.is_active
    } if marketing_message else None
    print("Marketing Message:", marketing_message_dict)  # Debugging line

    return render_template('dashboard.html', projects=projects, shared_projects=shared_projects, pending_invitations=pending_invitations_with_owners, marketing_message=marketing_message_dict)

@app.route('/upgrade', methods=['GET', 'POST'])
@login_required
def upgrade():
    if request.method == 'POST':
        current_user.role = 'premium'
        db.session.commit()
        flash('Congratulations! You have been upgraded to a premium account.', 'success')
        return redirect(url_for('welcome_premium'))
    return render_template('upgrade.html')

@app.route('/welcome_premium')
@login_required
def welcome_premium():
    return render_template('welcome_premium.html')

# Accept project invitation
@app.route('/accept_invitation/<int:project_id>', methods=['POST'])
@login_required
def accept_invitation(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user in project.shared_users:
        stmt = project_user.update().where(
            project_user.c.project_id == project_id,
            project_user.c.user_id == current_user.id
        ).values(status='accepted')
        db.session.execute(stmt)
        db.session.commit()
        flash('Project invitation accepted.', 'success')
    return redirect(url_for('dashboard'))

# Decline project invitation
@app.route('/decline_invitation/<int:project_id>', methods=['POST'])
@login_required
def decline_invitation(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user in project.shared_users:
        stmt = project_user.delete().where(
            project_user.c.project_id == project_id,
            project_user.c.user_id == current_user.id
        )
        db.session.execute(stmt)
        db.session.commit()
        flash('Project invitation declined.', 'info')
    return redirect(url_for('dashboard'))

# Edit
@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)

    if project.user_id != current_user.id:
        flash('You are not authorized to edit this project.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        project.name = request.form.get('name')
        project.category = request.form.get('category')
        project.target_customer = request.form.get('target_customer')
        project.country = request.form.get('country')
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_project.html', project=project)

# Delete
@app.route('/delete_project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    if current_user not in project.shared_users and project.user_id != current_user.id:
        flash('You are not authorized to delete this project.', 'danger')
        return redirect(url_for('dashboard'))

    if project.user_id == current_user.id:
        # If the current user is the owner, remove the project for all users
        db.session.delete(project)
    else:
        # If the current user is a shared user, just remove their access
        project.shared_users.remove(current_user)

    db.session.commit()
    flash('Project access removed successfully!', 'success')
    return redirect(url_for('dashboard'))


################## Routes for Manage Market Book ####################

#manage
@app.route('/manage/<int:project_id>')
@login_required
def manage_market_book(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    if not project.has_market_map:
        project.has_market_map = True
        db.session.commit()

    #Check if value drivers exist for the project, if they do then redirect to the correct page
    value_drivers = ValueDriver.query.filter_by(project_id = project_id).all()
    if value_drivers:
        products = Product.query.filter_by(project_id = project_id).all()
        if products:
            return redirect(url_for('market_map', project_id=project_id))
        else:
            return redirect(url_for('product_comparison', project_id=project_id))
    else:
        return redirect(url_for('value_drivers', project_id=project_id))

    # This return is now unreachable due to the redirects above.
    # It's kept here as a fallback, but should not be hit in normal operation.
    return render_template('manage_market_book.html', project=project)


###########routes for managing creating and weighting value drivers ####

# create value drivers
@app.route('/manage/<int:project_id>/value_drivers', methods=['GET', 'POST'])
@login_required
def value_drivers(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'add_value_driver' in request.form:
            value_driver = request.form.get('value_driver')
            measured_by = request.form.get('measured_by')
            if not value_driver:
                flash('Value Driver is required.', 'danger')
                return redirect(url_for('value_drivers', project_id=project_id))

            if not measured_by:
                measured_by = "0: Does not meet the value driver\n" \
                              "1: Barely meets the value driver\n" \
                              "2: Somewhat meets the value driver\n" \
                              "3: Moderately meets the value driver\n" \
                              "4: Strongly meets the value driver\n" \
                              "5: Fully meets or exceeds the value driver"

            new_value_driver = ValueDriver(value_driver=value_driver, measured_by=measured_by, project_id=project_id)
            db.session.add(new_value_driver)
            db.session.commit()
            flash('Value Driver added successfully!', 'success')
        elif 'edit_value_driver' in request.form:
            value_driver_id = request.form.get('edit_value_driver_id')
            value_driver_to_edit = ValueDriver.query.get_or_404(value_driver_id)
            value_driver_to_edit.value_driver = request.form.get('edit_value_driver')
            db.session.commit()
            flash('Value Driver updated successfully!', 'success')
        elif 'edit_measured_by' in request.form:  # New elif statement for modal edits
            measured_by_id = request.form.get('edit_measured_by_id')
            measured_by_to_edit = ValueDriver.query.get_or_404(measured_by_id)
            measured_by_to_edit.measured_by = request.form.get('edit_measured_by')
            db.session.commit()
            flash('Measured By updated successfully!', 'success')
        elif 'edit_technical_attributes' in request.form:  # Handle technical attributes
            technical_attributes_id = request.form.get('edit_technical_attributes_id')
            technical_attributes_to_edit = ValueDriver.query.get_or_404(technical_attributes_id)
            technical_attributes_to_edit.technical_attributes = request.form.get('edit_technical_attributes')
            db.session.commit()
            flash('Technical Attributes updated successfully!', 'success')
        elif 'delete_value_driver' in request.form:
            value_driver_id = request.form.get('delete_value_driver_id')
            value_driver_to_delete = ValueDriver.query.get_or_404(value_driver_id)

            # Delete ratings referencing this value driver before deleting the value driver
            Rating.query.filter_by(value_driver_id=value_driver_id).delete()

            db.session.delete(value_driver_to_delete)
            db.session.commit()
            flash('Value Driver deleted successfully!', 'success')
        elif 'reset_weightings' in request.form:  # New: Reset Weightings
            value_drivers_to_reset = ValueDriver.query.filter_by(project_id=project_id).all()
            for vd in value_drivers_to_reset:
                vd.weighting = 0.0
            # Delete associated comparison results
            ComparisonResult.query.filter_by(project_id=project_id).delete()
            db.session.commit()
            flash('Value driver weightings have been reset and comparison results deleted.', 'success')
        elif 'weight_my_drivers' in request.form:  # New button for weighting drivers
            return redirect(url_for('pairwise_comparison', project_id=project_id))
        return redirect(url_for('value_drivers', project_id=project_id))  # Redirect after all POST operations

    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()
    comparisons = {}  # Initialize comparisons as an empty dictionary

    # Fetch comparison results from the database
    comparison_results = ComparisonResult.query.filter_by(project_id=project_id).all()

    # Create a dictionary to map value driver IDs to their names
    value_drivers_dict = {vd.id: vd.value_driver for vd in value_drivers}

    return render_template('value_drivers.html', project=project, value_drivers=value_drivers, comparisons=comparisons, comparison_results=comparison_results, value_drivers_dict=value_drivers_dict)

# Compare value drivers
@app.route('/manage/<int:project_id>/compare', methods=['GET', 'POST'])
@login_required
def compare_value_drivers(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()
    num_drivers = len(value_drivers)

    if num_drivers < 2:
        flash("You need at least two value drivers to perform comparisons.", 'danger')
        return redirect(url_for('value_drivers', project_id=project_id))

    if any(vd.weighting > 0 for vd in value_drivers):  # Check if weightings have already been set
        flash("Weightings have already been set for these value drivers. Reset to perform new comparisons.", 'warning')
        return redirect(url_for('value_drivers', project_id=project_id))

    if request.method == 'POST':
        comparisons = {}
        for i in range(num_drivers):
            for j in range(i + 1, num_drivers):
                comparison_key = f"{value_drivers[i].id}-{value_drivers[j].id}"
                comparison_value = request.form.get(comparison_key)
                if comparison_value:
                    comparisons[(value_drivers[i].id, value_drivers[j].id)] = int(comparison_value) # Store as tuple keys

        matrix = np.zeros((num_drivers, num_drivers))

        for (id1, id2), value in comparisons.items():
            index1 = next((index for index, vd in enumerate(value_drivers) if vd.id == id1), None)
            index2 = next((index for index, vd in enumerate(value_drivers) if vd.id == id2), None)

            if index1 is not None and index2 is not None: # check if indexs are valid
                if value == 1:
                    matrix[index1, index2] = 1
                    winner_id = id1
                elif value == 2:
                    matrix[index2, index1] = 1
                    winner_id = id2

                # Save the comparison result to the database
                comparison_result = ComparisonResult(
                    project_id=project_id,
                    value_driver_a_id=id1,
                    value_driver_b_id=id2,
                    winner_id=winner_id
                )
                db.session.add(comparison_result)

        # Handle cases where a row is all zeros to prevent errors in mean calculation and assign weights
        for i in range(num_drivers):
            if np.sum(matrix[i]) == 0 and np.sum(matrix[:, i]) == 0:
                matrix[i, i] = 1  # Set diagonal to 1 for uncompared drivers

        weights = np.sum(matrix, axis=1)

        # Normalize weights to 100%
        total_weight = sum(weights)
        if (total_weight > 0):
            normalized_weights = [(w / total_weight) * 100 for w in weights]
        else:
            normalized_weights = [100 / num_drivers] * num_drivers

        for i, vd in enumerate(value_drivers):
            vd.weighting = normalized_weights[i]
            db.session.commit()

        return redirect(url_for('comparison_results', project_id=project_id))

    comparisons = []
    for i in range(num_drivers):
        for j in range(i + 1, num_drivers):
            comparisons.append((value_drivers[i], value_drivers[j]))

    return render_template('compare.html', project=project, value_drivers=value_drivers, comparisons=comparisons)

# Results of pairwise comparison
@app.route('/manage/<int:project_id>/results')
@login_required
def comparison_results(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))
    value_drivers = ValueDriver.query.filter_by(project_id=project_id).order_by(ValueDriver.weighting.desc()).all() #Order by weighting

    labels = [vd.value_driver for vd in value_drivers]
    weights = [vd.weighting for vd in value_drivers]

    # Ensure labels and weights are not None
    labels = labels if labels else []
    weights = weights if weights else []

    # Create the bar chart
    fig, ax = plt.subplots()
    ax.bar(labels, weights)
    ax.set_ylabel('Weighting (%)')
    ax.set_title('Value Driver Weighting Results')
    plt.xticks(rotation=45, ha='right') #Rotate x axis labels

    # Save the chart to a BytesIO object
    img = BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight') #Added bbox_inches
    img.seek(0)
    plt.close(fig)

    # Encode the image to base64
    plot_url = base64.b64encode(img.getvalue()).decode()

    return render_template('results.html', project=project, plot_url=plot_url, labels=labels, weights=weights)

@app.route('/manage/<int:project_id>/pairwise_comparison')
@login_required
def pairwise_comparison(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('pairwise_comparison.html', project=project)

###########################routes for managing comparing products ####
# Product Comparison
@app.route('/manage/<int:project_id>/product_comparison', methods=['GET', 'POST'])
@login_required
def product_comparison(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if current_user.role == 'standard':
            user_products_count = Product.query.filter_by(project_id=project_id).count()
            if user_products_count >= PREMIUM_CONDITIONS['max_products']:
                flash('Upgrade to a premium account to add more products.', 'warning')
                return redirect(url_for('upgrade'))

        if 'add_product' in request.form:
            brand_name = request.form.get('brand_name')
            product_name = request.form.get('product_name')
            price = request.form.get('price')
            currency = request.form.get('currency') #Get the currency from the form
            image = request.files.get('image')
            price_source = request.form.get('price_source')  # Get the price source from the form

            if not brand_name or not product_name:
                flash('Brand and product name are required.', 'danger')
                return redirect(url_for('product_comparison', project_id=project_id))

            filename = None
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            try:
                price = float(price) if price else None
            except ValueError:
                flash('Invalid price format.', 'danger')
                return redirect(url_for('product_comparison', project_id=project_id))

            new_product = Product(
                brand_name=brand_name,
                product_name=product_name,
                price=price,
                image_filename=filename,
                project_id=project_id,
                currency=currency,
                price_source=price_source  # Add price_source to product
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('product_comparison', project_id=project_id))
        else:
            return redirect(url_for('product_comparison', project_id=project_id))

    products = Product.query.filter_by(project_id=project_id).all()
    product_weighted_scores = {}

    for product in products:
        total_weighted_score = 0
        ratings_for_product = Rating.query.filter_by(product_id=product.id).all()
        for rating in ratings_for_product:
            total_weighted_score += rating.score * (rating.value_driver.weighting / 100)
        product_weighted_scores[product.id] = round(total_weighted_score, 2)

    return render_template('product_comparison.html', project=project, products=products, product_weighted_scores=product_weighted_scores)

#edit product
@app.route('/manage/<int:project_id>/product/<int:product_id_to_edit>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(project_id, product_id_to_edit):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    product_to_edit = Product.query.get_or_404(product_id_to_edit)
    if product_to_edit.project_id != project_id:
        flash('Product not found in this project.', 'danger')
        return redirect(url_for('product_comparison', project_id=project_id))

    if request.method == 'POST':
        product_to_edit.brand_name = request.form.get('brand_name')
        product_to_edit.product_name = request.form.get('product_name')
        product_to_edit.currency = request.form.get('currency') #Get the currency from the form
        try:
            new_price = float(request.form.get('price')) if request.form.get('price') else None
        except ValueError:
            flash('Invalid price format.', 'danger')
            return redirect(url_for('edit_product', project_id=project_id, product_id_to_edit=product_id_to_edit))

        # Save price history if price has changed
        if new_price is not None and new_price != product_to_edit.price:
            price_history = PriceHistory(
                product_id=product_to_edit.id,
                old_price=product_to_edit.price,
                new_price=new_price
            )
            db.session.add(price_history)
            product_to_edit.price = new_price

        image = request.files.get('image')
        if image:
            if allowed_file(image.filename):
                if product_to_edit.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product_to_edit.image_filename)
                    try:
                        os.remove(old_image_path)
                    except FileNotFoundError:
                        pass

                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product_to_edit.image_filename = filename
            else:
                flash("Invalid file type for image upload", 'danger')
                return redirect(url_for('edit_product', project_id=project_id, product_id_to_edit=product_id_to_edit))

        product_to_edit.price_source = request.form.get('price_source')  # Get the price source from the form
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('product_comparison', project_id=project_id))

    return render_template('edit_product.html', project=project, product=product_to_edit)

# View price history
@app.route('/manage/<int:project_id>/product/<int:product_id>/price_history')
@login_required
def price_history(project_id, product_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to view this project.', 'danger')
        return redirect(url_for('dashboard'))

    product = Product.query.get_or_404(product_id)
    price_history = PriceHistory.query.filter_by(product_id=product_id).order_by(PriceHistory.date_changed.desc()).all()

    return render_template('price_history.html', project=project, product=product, price_history=price_history)

# delete product
@app.route('/manage/<int:project_id>/product/<int:product_id_to_delete>/delete', methods=['POST'])
@login_required
def delete_product(project_id, product_id_to_delete):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    product_to_delete = Product.query.get_or_404(product_id_to_delete)
    if product_to_delete.project_id != project_id:
        flash('Product not found in this project.', 'danger')
        return redirect(url_for('product_comparison', project_id=project_id))

    # Delete associated ratings FIRST
    Rating.query.filter_by(product_id=product_id_to_delete).delete()
    db.session.commit() # Commit ratings deletion before product deletion

    # Check if the image is used by other products before deleting
    if product_to_delete.image_filename:
        other_products_with_same_image = Product.query.filter_by(image_filename=product_to_delete.image_filename).count()
        if other_products_with_same_image == 1:  # Only delete the image if no other products are using it
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product_to_delete.image_filename)
            try:
                os.remove(image_path)
            except FileNotFoundError:
                pass

    db.session.delete(product_to_delete)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('product_comparison', project_id=project_id))

#rate products
@app.route('/manage/<int:project_id>/product/<int:product_id_to_rate>/rate', methods=['GET', 'POST'])
@login_required
def rate_product(project_id, product_id_to_rate):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    product_to_rate = Product.query.get_or_404(product_id_to_rate)
    if product_to_rate.project_id != project_id:
        flash('Product not found in this project.', 'danger')
        return redirect(url_for('product_comparison', project_id=project_id))

    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()

    # Get existing ratings and notes for this product
    existing_ratings = Rating.query.filter_by(product_id=product_id_to_rate).all()
    ratings_dict = {rating.value_driver_id: rating.score for rating in existing_ratings}
    notes_dict = {rating.value_driver_id: rating.note.note if rating.note else '' for rating in existing_ratings}

    if request.method == 'POST':
        print("Form submitted")  # Debugging line
        print("Form data:", request.form)  # Debugging line
        all_ratings_valid = True

        for vd in value_drivers:
            rating_name = f'rating_{vd.id}'
            rating_value = request.form.get(rating_name)
            note_value = request.form.get(f'note_{vd.id}')

            print(f"Processing value driver {vd.id}: rating={rating_value}, note={note_value}")  # Debugging line

            try:
                rating = int(rating_value)
                if not (0 <= rating <= 5):
                    flash(f'Rating for {vd.value_driver} must be between 0 and 5.', 'danger')
                    all_ratings_valid = False
                    break
            except (ValueError, TypeError):
                flash(f'Invalid rating for {vd.value_driver}. Please enter a number.', 'danger')
                all_ratings_valid = False
                break

        if all_ratings_valid:
            for vd in value_drivers:
                rating_value = int(request.form.get(f'rating_{vd.id}'))
                note_value = request.form.get(f'note_{vd.id}')

                existing_rating = Rating.query.filter_by(
                    product_id=product_id_to_rate, value_driver_id=vd.id
                ).first()

                if existing_rating:
                    existing_rating.score = rating_value
                    existing_rating.date_rated = datetime.utcnow()
                    if existing_rating.note:
                        existing_rating.note.note = note_value
                    else:
                        new_note = RatingNote(
                            rating_id=existing_rating.id,
                            note=note_value
                        )
                        db.session.add(new_note)
                else:
                    new_rating = Rating(
                        product_id=product_id_to_rate,
                        value_driver_id=vd.id,
                        score=rating_value
                    )
                    db.session.add(new_rating)
                    db.session.flush()  # Ensure new_rating.id is available
                    new_note = RatingNote(
                        rating_id=new_rating.id,
                        note=note_value
                    )
                    db.session.add(new_note)

            db.session.commit()
            flash('Ratings and notes submitted successfully!', 'success')
            return redirect(url_for('product_comparison', project_id=project_id))

    return render_template('rate_product.html', project=project, product=product_to_rate, value_drivers=value_drivers, ratings=ratings_dict, notes=notes_dict)

@app.route('/manage/<int:project_id>/value_driver/<int:value_driver_id>/edit_scoring_guidance', methods=['POST'])
@login_required
def edit_scoring_guidance(project_id, value_driver_id):
    value_driver = ValueDriver.query.get_or_404(value_driver_id)
    if value_driver.project_id != project_id:
        flash('Value driver not found in this project.', 'danger')
        return redirect(url_for('rate_product', project_id=project_id, product_id_to_rate=request.args.get('product_id_to_rate')))

    value_driver.measured_by = request.form.get('measured_by')
    db.session.commit()
    flash('Scoring guidance updated successfully!', 'success')
    return redirect(url_for('rate_product', project_id=project_id, product_id_to_rate=request.args.get('product_id_to_rate')))

######################### View graphs  ##################################
def generate_colors(num_colors):
    colors = []
    for i in range(num_colors):
        hue = i * (360 / num_colors)
        colors.append(f"hsl({hue}, 70%, 60%)")
    return colors

@app.route('/manage/<int:project_id>/market_map', methods=['GET', 'POST'])
@login_required
def market_map(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        note = request.form.get('note')
        if note:
            new_comment = Comment(note=note, user_id=current_user.id, project_id=project_id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')
        else:
            flash('Comment cannot be empty.', 'danger')

    products = Product.query.filter_by(project_id=project_id).all()
    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()
    comments = Comment.query.filter_by(project_id=project_id).order_by(Comment.date.desc()).options(joinedload(Comment.user)).all()

    # Fetch all projects for the current user and shared projects
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    shared_projects = Project.query.join(project_user).filter(
        project_user.c.user_id == current_user.id,
        project_user.c.status == 'accepted'
    ).all()
    projects = user_projects + shared_projects

    # Group products by brand
    products_by_brand = defaultdict(list)
    for product in products:
        products_by_brand[product.brand_name].append(product)

    # Generate colors for each brand
    num_brands = len(products_by_brand)
    brand_colors = generate_colors(num_brands)

    # Create a brand-to-color mapping
    brand_color_map = {brand: brand_colors[i] for i, brand in enumerate(products_by_brand)}

    scatter_data = []
    bar_chart_data = {}

    for product in products:
        total_weighted_score = 0
        # Efficiently load related ValueDriver data
        product_ratings = Rating.query.options(joinedload(Rating.value_driver)).filter_by(product_id=product.id).all()

        product_bar_chart_data = {}
        for vd in value_drivers:
            product_bar_chart_data[vd.value_driver] = None

        if product_ratings:
            for rating in product_ratings:
                total_weighted_score += rating.score * (rating.value_driver.weighting / 100)
                product_bar_chart_data[rating.value_driver.value_driver] = rating.score

        for vd in value_drivers:
            bar_chart_data.setdefault(vd.value_driver, []).append(product_bar_chart_data[vd.value_driver])

        scatter_data.append({
            'name': product.product_name,
            'price': product.price,
            'score': total_weighted_score,
            'brand': product.brand_name,  # Add brand to scatter data
            'color': brand_color_map[product.brand_name]  # Add color to scatter data
        })

    product_names = [product.product_name for product in products]
    value_driver_names = [vd.value_driver for vd in value_drivers] # Get Value Driver Names

    return render_template('market_map.html', project=project, scatter_data=scatter_data, bar_chart_data=bar_chart_data, value_driver_names=value_driver_names, product_names=product_names, brand_color_map=brand_color_map, comments=comments, value_drivers=value_drivers, projects=projects)

@app.route('/manage/<int:project_id>/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(project_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id and current_user not in comment.project.shared_users:
        flash('You are not authorized to edit this comment.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    comment.note = request.form.get('note')
    db.session.commit()
    flash('Comment updated successfully!', 'success')
    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(project_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id != current_user.id and current_user not in comment.project.shared_users:
        flash('You are not authorized to delete this comment.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted successfully!', 'success')
    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/comment/<int:comment_id>/like', methods=['POST'])
@login_required
def like_comment(project_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user not in comment.project.shared_users and comment.project.user_id != current_user.id:
        flash('You are not authorized to like this comment.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    existing_like = Like.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    if existing_like:
        flash('You have already liked this comment.', 'info')
    else:
        new_like = Like(user_id=current_user.id, comment_id=comment_id)
        db.session.add(new_like)
        db.session.commit()
        flash('Comment liked successfully!', 'success')

    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/comment/<int:comment_id>/reply', methods=['POST'])
@login_required
def reply_comment(project_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user not in comment.project.shared_users and comment.project.user_id != current_user.id:
        flash('You are not authorized to reply to this comment.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    note = request.form.get('note')
    if note:
        new_reply = Reply(note=note, user_id=current_user.id, comment_id=comment_id)
        db.session.add(new_reply)
        db.session.commit()
        flash('Reply added successfully!', 'success')
    else:
        flash('Reply cannot be empty.', 'danger')

    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/reply/<int:reply_id>/edit', methods=['POST'])
@login_required
def edit_reply(project_id, reply_id):
    reply = Reply.query.get_or_404(reply_id)
    if reply.user_id != current_user.id and current_user not in reply.comment.project.shared_users:
        flash('You are not authorized to edit this reply.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    reply.note = request.form.get('note')
    db.session.commit()
    flash('Reply updated successfully!', 'success')
    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/reply/<int:reply_id>/delete', methods=['POST'])
@login_required
def delete_reply(project_id, reply_id):
    reply = Reply.query.get_or_404(reply_id)
    if reply.user_id != current_user.id and current_user not in reply.comment.project.shared_users:
        flash('You are not authorized to delete this reply.', 'danger')
        return redirect(url_for('market_map', project_id=project_id))

    db.session.delete(reply)
    db.session.commit()
    flash('Reply deleted successfully!', 'success')
    return redirect(url_for('market_map', project_id=project_id))

@app.route('/manage/<int:project_id>/product/<int:product_id_to_duplicate>/duplicate', methods=['POST'])
@login_required
def duplicate_product(project_id, product_id_to_duplicate):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    product_to_duplicate = Product.query.get_or_404(product_id_to_duplicate)
    if product_to_duplicate.project_id != project_id:
        flash('Product not found in this project.', 'danger')
        return redirect(url_for('product_comparison', project_id=project_id))

    new_product = Product(
        brand_name=product_to_duplicate.brand_name,
        product_name=product_to_duplicate.product_name + " (Copy)",
        price=product_to_duplicate.price,
        currency=product_to_duplicate.currency,
        image_filename=product_to_duplicate.image_filename,
        project_id=project_id,
        price_source=product_to_duplicate.price_source
    )
    db.session.add(new_product)
    db.session.commit()

    # Duplicate the ratings
    ratings_to_duplicate = Rating.query.filter_by(product_id=product_id_to_duplicate).all()
    for rating in ratings_to_duplicate:
        new_rating = Rating(
            product_id=new_product.id,
            value_driver_id=rating.value_driver_id,
            score=rating.score,
            date_rated=rating.date_rated
        )
        db.session.add(new_rating)

    db.session.commit()
    flash('Product duplicated successfully!', 'success')
    return redirect(url_for('product_comparison', project_id=project_id))

@app.route('/share_project/<int:project_id>', methods=['POST'])
@login_required
def share_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to share this project.', 'danger')
        return redirect(url_for('dashboard'))

    email = request.form.get('email')
    user_to_share = User.query.filter_by(email=email).first()

    if user_to_share:
        # Check if the user already has access to the project
        if user_to_share in project.shared_users:
            flash('This user already has access to the project.', 'warning')
        else:
            # Grant access to the project
            project.shared_users.append(user_to_share)
            db.session.commit()
            flash('Project successfully shared!', 'success')
    else:
        flash('Email address not found.', 'danger')

    return redirect(url_for('dashboard'))

# Manage Access
@app.route('/manage_access/<int:project_id>', methods=['GET', 'POST'])
def manage_access(project_id):
    project = Project.query.get_or_404(project_id)
    shared_users = project.shared_users  # Change 'users' to 'shared_users'

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            project.shared_users.append(user)  # Change 'users' to 'shared_users'
            db.session.commit()
            flash('User has been granted access.', 'success')
        else:
            flash('User not found.', 'danger')
        return redirect(url_for('manage_access', project_id=project_id))

    return render_template('manage_access.html', project=project, shared_users=shared_users)

@app.route('/manage/<int:project_id>/access/remove/<int:user_id>', methods=['POST'])
@login_required
def remove_access(project_id, user_id):
    project = Project.query.get_or_404(project_id)
    user_to_remove = User.query.get_or_404(user_id)

    if project.user_id != current_user.id:
        flash('You are not authorized to remove access for this project.', 'danger')
        return redirect(url_for('dashboard'))

    if user_to_remove in project.shared_users:
        project.shared_users.remove(user_to_remove)
        db.session.commit()
        flash('User access removed successfully!', 'success')
    else:
        flash('User does not have access to this project.', 'danger')

    return redirect(url_for('manage_access', project_id=project_id))

# Settings
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'update_account' in request.form:
            username = request.form.get('username')
            profile_image = request.files.get('profile_image')
            role = request.form.get('role')

            if username:
                current_user.username = username

            if profile_image and allowed_file(profile_image.filename):
                filename = secure_filename(profile_image.filename)
                profile_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_image = filename

            if role:
                current_user.role = role

            db.session.commit()
            flash('Account updated successfully!', 'success')
            return redirect(url_for('settings'))

        elif 'reset_password' in request.form:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_new_password = request.form.get('confirm_new_password')

            if current_password and new_password and confirm_new_password:
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect.', 'danger')
                    return redirect(url_for('settings'))
                if new_password != confirm_new_password:
                    flash('New passwords do not match.', 'danger')
                    return redirect(url_for('settings'))
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password reset successfully!', 'success')
                return redirect(url_for('settings'))

        elif 'delete_account' in request.form:
            db.session.delete(current_user)
            db.session.commit()
            flash('Account deleted successfully!', 'success')
            return redirect(url_for('register'))

    return render_template('settings.html')

# Default premium conditions
PREMIUM_CONDITIONS = {
    'max_projects': 2,
    'max_products': 6
}

@app.route('/admin/premium_conditions', methods=['GET', 'POST'])
@login_required
def premium_conditions():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        max_projects = request.form.get('max_projects')
        max_products = request.form.get('max_products')

        try:
            PREMIUM_CONDITIONS['max_projects'] = int(max_projects)
            PREMIUM_CONDITIONS['max_products'] = int(max_products)
            flash('Premium conditions updated successfully!', 'success')
        except ValueError:
            flash('Invalid input. Please enter valid numbers.', 'danger')

    return render_template('admin/premium_conditions.html', conditions=PREMIUM_CONDITIONS)

@app.route('/survey')
@login_required
def survey():
    project_id = request.args.get('project_id')
    project = Project.query.get_or_404(project_id)
    survey_url = url_for('survey_comparison', project_id=project.id, _external=True)
    return render_template('survey.html', survey_url=survey_url, project=project)

@app.route('/survey_comparison', methods=['GET', 'POST'])
def survey_comparison():
    project_id = request.args.get('project_id')
    project = Project.query.get_or_404(project_id)
    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()
    num_drivers = len(value_drivers)

    if num_drivers < 2:
        flash("You need at least two value drivers to perform comparisons.", 'danger')
        return redirect(url_for('value_drivers', project_id=project_id))

    if request.method == 'POST':
        comparisons = {}
        for i in range(num_drivers):
            for j in range(i + 1, num_drivers):
                comparison_key = f"{value_drivers[i].id}-{value_drivers[j].id}"
                comparison_value = request.form.get(comparison_key)
                if comparison_value:
                    comparisons[(value_drivers[i].id, value_drivers[j].id)] = int(comparison_value) # Store as tuple keys

        for (id1, id2), value in comparisons.items():
            winner_id = id1 if value == 1 else id2
            comparison_result = ComparisonResult(
                project_id=project_id,
                value_driver_a_id=id1,
                value_driver_b_id=id2,
                winner_id=winner_id
            )
            db.session.add(comparison_result)

        db.session.commit()
        flash('Thank you for your submission!', 'success')
        return redirect(url_for('thank_you'))

    comparisons = []
    for i in range(num_drivers):
        for j in range(i + 1, num_drivers):
            comparisons.append((value_drivers[i], value_drivers[j]))

    return render_template('survey_comparison.html', project=project, value_drivers=value_drivers, comparisons=comparisons)

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')

@app.route('/survey_results/<int:project_id>')
def survey_results(project_id):
    project = Project.query.get_or_404(project_id)
    value_drivers = ValueDriver.query.filter_by(project_id=project_id).all()

    # Initialize a dictionary to store the win counts for each value driver
    win_counts = {vd.id: 0 for vd in value_drivers}

    # Fetch all comparison results for the project
    comparison_results = ComparisonResult.query.filter_by(project_id=project_id).all()

    # Count the wins for each value driver
    for result in comparison_results:
        win_counts[result.winner_id] += 1

    # Calculate the total number of comparisons
    total_comparisons = len(comparison_results)

    # Calculate the weightings based on the win counts
    if total_comparisons > 0:
        for vd in value_drivers:
            vd.weighting = (win_counts[vd.id] / total_comparisons) * 100
            db.session.commit()

    labels = [vd.value_driver for vd in value_drivers]
    weights = [vd.weighting for vd in value_drivers]

    # Calculate the number of survey submissions
    num_submissions = total_comparisons // (len(value_drivers) * (len(value_drivers) - 1) // 2)

    return render_template('survey_results.html', project=project, labels=labels, weights=weights, num_submissions=num_submissions)

@app.template_filter('zip')
def zip_filter(a, b):
    return zip(a, b)

@app.route('/admin/marketing_message', methods=['GET', 'POST'])
@login_required
def manage_marketing_message():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    message = MarketingMessage.query.first()

    if request.method == 'POST':
        content = request.form.get('content')
        is_active = 'is_active' in request.form

        if message:
            message.content = content
            message.is_active = is_active
        else:
            message = MarketingMessage(content=content, is_active=is_active)
            db.session.add(message)

        db.session.commit()
        flash('Marketing message updated successfully!', 'success')
        return redirect(url_for('manage_marketing_message'))

    return render_template('admin/marketing_message.html', message=message)

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/terms')
def terms():
    return render_template('termsandconditions.html')

@app.route('/termsofuse')
def termsofuse():
    return render_template('termsofuse.html')

# Delete price history entry
@app.route('/manage/<int:project_id>/product/<int:product_id>/price_history/<int:history_id>/delete', methods=['POST'])
@login_required
def delete_price_history(project_id, product_id, history_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id and current_user not in project.shared_users:
        flash('You are not authorized to manage this project.', 'danger')
        return redirect(url_for('dashboard'))

    price_history_entry = PriceHistory.query.get_or_404(history_id)
    if price_history_entry.product_id != product_id:
        flash('Price history entry not found for this product.', 'danger')
        return redirect(url_for('price_history', project_id=project_id, product_id=product_id))

    db.session.delete(price_history_entry)
    db.session.commit()
    flash('Price history entry deleted successfully!', 'success')
    return redirect(url_for('price_history', project_id=project_id, product_id=product_id))

# Price Movement Indicators
@app.route('/price_movement_indicators', methods=['GET', 'POST'])
@login_required
def price_movement_indicators():
    brand_filter = request.args.get('brand')
    product_name_filter = request.args.get('product_name')

    subquery = db.session.query(
        PriceHistory.product_id,
        db.func.max(PriceHistory.date_changed).label('latest_date')
    ).group_by(PriceHistory.product_id).subquery()

    query = db.session.query(Product, PriceHistory).join(
        subquery,
        (PriceHistory.product_id == subquery.c.product_id) & (PriceHistory.date_changed == subquery.c.latest_date)
    ).join(Product, Product.id == PriceHistory.product_id)

    if brand_filter:
        query = query.filter(Product.brand_name.ilike(f'%{brand_filter}%'))
    if product_name_filter:
        query = query.filter(Product.product_name.ilike(f'%{product_name_filter}%'))

    products_with_latest_price_change = query.all()

    return render_template('price_movement_indicators.html', products_with_latest_price_change=products_with_latest_price_change, brand_filter=brand_filter, product_name_filter=product_name_filter)

####################################Initiate App ############################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all() #Creates the database if it doesn't exist
    app.run(debug=True)
