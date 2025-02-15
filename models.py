from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Define the Project model first
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    target_customer = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    has_market_map = db.Column(db.Boolean, default=False)
    shared_users = db.relationship('User', secondary='project_user', backref='shared_projects')
    value_drivers = db.relationship('ValueDriver', cascade='all, delete-orphan', backref='project')
    products = db.relationship('Product', cascade='all, delete-orphan', backref='project')
    comments = db.relationship('Comment', cascade='all, delete-orphan', backref='project')
    comparison_results = db.relationship('ComparisonResult', cascade='all, delete-orphan', backref='project')

# Define the AdditionalQuestionResponse model after the Project model
class AdditionalQuestionResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    question_text = db.Column(db.String(255), nullable=False)
    response = db.Column(db.String(255), nullable=False)
