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

#Project
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    has_market_map = db.Column(db.Boolean, default=False)  # EXACTLY like this
    shared_users = db.relationship('User', secondary='project_user', backref='shared_projects')

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
    weighting = db.Column(db.Float, default=0.0)  # Changed to Float for more precision
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

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

    product = db.relationship('Product', backref=db.backref('ratings', lazy=True))
    value_driver = db.relationship('ValueDriver', backref=db.backref('ratings', lazy=True))

# Comment Model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    project = db.relationship('Project', backref=db.backref('comments', lazy=True))

class ComparisonResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    value_driver_a_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)
    value_driver_b_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)
    winner_id = db.Column(db.Integer, db.ForeignKey('value_driver.id'), nullable=False)

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

        if not username or not email or not password or not confirm_password or not role:
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
@app.route('/dashboard', methods=['GET', 'POST'])  # Crucial: Add methods=['GET', 'POST']
@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if not name:
            flash("Project name is required.", 'danger')
            return redirect(url_for('dashboard'))

        new_project = Project(name=name, description=description, user_id=current_user.id)
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

    return render_template('dashboard.html', projects=projects, shared_projects=shared_projects, pending_invitations=pending_invitations_with_owners)

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
        project.description = request.form.get('description')
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
        if total_weight > 0:
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

    return render_template('results.html', project=project, plot_url=plot_url)

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
            product_to_edit.price = float(request.form.get('price')) if request.form.get('price') else None
        except ValueError:
            flash('Invalid price format.', 'danger')
            return redirect(url_for('edit_product', project_id=project_id, product_id_to_edit=product_id_to_edit))

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

    # Get existing ratings for this product
    existing_ratings = Rating.query.filter_by(product_id=product_id_to_rate).all()
    ratings_dict = {rating.value_driver_id: rating.score for rating in existing_ratings}

    if request.method == 'POST':
        all_ratings_valid = True

        for vd in value_drivers:
            rating_name = f'rating_{vd.id}'
            rating_value = request.form.get(rating_name)

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

                existing_rating = Rating.query.filter_by(
                    product_id=product_id_to_rate, value_driver_id=vd.id
                ).first()

                if existing_rating:
                    existing_rating.score = rating_value
                    existing_rating.date_rated = datetime.utcnow()
                else:
                    new_rating = Rating(
                        product_id=product_id_to_rate,
                        value_driver_id=vd.id,
                        score=rating_value
                    )
                    db.session.add(new_rating)

            db.session.commit()
            flash('Ratings submitted successfully!', 'success')
            return redirect(url_for('product_comparison', project_id=project_id))

    return render_template('rate_product.html', project=project, product=product_to_rate, value_drivers=value_drivers, ratings=ratings_dict)

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
    comments = Comment.query.filter_by(project_id=project_id).order_by(Comment.date.desc()).all()

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

    return render_template('market_map.html', project=project, scatter_data=scatter_data, bar_chart_data=bar_chart_data, value_driver_names=value_driver_names, product_names=product_names, brand_color_map=brand_color_map, comments=comments, value_drivers=value_drivers)

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
@app.route('/manage/<int:project_id>/access', methods=['GET', 'POST'])
@login_required
def manage_access(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('You are not authorized to manage access for this project.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user_to_share = User.query.filter_by(email=email).first()

        if user_to_share:
            if user_to_share in project.shared_users:
                flash('This user already has access to the project.', 'warning')
            else:
                project.shared_users.append(user_to_share)
                db.session.commit()
                flash('User successfully invited!', 'success')
        else:
            flash('Email address not found.', 'danger')

    shared_users = project.shared_users

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

####################################Initiate App ############################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all() #Creates the database if it doesn't exist
    app.run(debug=True)
