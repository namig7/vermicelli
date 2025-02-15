import os
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps
import logging
import re  # for URL validation
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

load_dotenv()

app = Flask(__name__)

# JWT and session configuration
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SESSION_TYPE'] = os.environ.get("SESSION_TYPE", 'filesystem')
Session(app)

# Database configuration
DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite").lower()  # By default, uses SQLite
DB_NAME = os.environ.get("DB", "verdb")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "postgres")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")

# Construct SQLAlchemy URI
if DB_ENGINE == "sqlite":
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}.db"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

users_str = os.environ.get("USERS", "")
users = {}
for pair in users_str.split(";"):
    pair = pair.strip()
    if pair:
        username, pwd = pair.split(":", 1)
        users[username] = pwd

jwt = JWTManager(app)

def login_required(f):
    """Checks if a user is logged in (via session) to access specific routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login with session-based authentication."""
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username] == password:
            session['username'] = username
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs out the user by clearing the session."""
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

def test_database_connection():
    """Verifies if the database connection can be successfully established."""
    with app.app_context():
        try:
            db.session.execute(text('SELECT 1'))
            print("Connection to the database is successfully established")
        except Exception as e:
            print("Error in connection to the database:", str(e))

# Many-to-many association table for Projects and Applications
project_applications = db.Table(
    'project_applications',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('application_id', db.Integer, db.ForeignKey('application.id'), primary_key=True)
)

class Application(db.Model):
    """Represents an application entity."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    versions = db.relationship('Version', backref='application', lazy=True, cascade="all, delete-orphan")
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    link = db.Column(db.String(256))
    label = db.Column(db.String(128))

    projects = db.relationship('Project', secondary=project_applications, back_populates='applications')

class Version(db.Model):
    """Represents a version of an application."""
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id', ondelete='CASCADE'), nullable=False)
    number = db.Column(db.String(20), nullable=False)  # e.g. "1.2.3"
    version_type = db.Column(db.String(20))
    change_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

class Project(db.Model):
    """Represents a project entity."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    source_link = db.Column(db.String(255))
    status = db.Column(db.String(50), nullable=False, default='Draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    applications = db.relationship('Application', secondary=project_applications, back_populates='projects')

### Helper: basic URL validation
def is_valid_url(url: str) -> bool:
    """
    Allows empty or None as 'valid' if optional,
    otherwise checks if it starts with http:// or https://
    """
    if not url:
        return True  # if we want to allow empty
    pattern = r'^https?://'
    return bool(re.match(pattern, url.strip()))

### HTML page routes (render templates)
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/applications')
@login_required
def applications_page():
    return render_template('index.html', initial_page='applications')

@app.route('/projects')
@login_required
def projects_page():
    return render_template('index.html', initial_page='projects')

@app.route('/content/applications')
@login_required
def applications_content():
    return render_template('applications.html')

@app.route('/content/projects')
@login_required
def projects_content():
    return render_template('projects.html')

@app.route('/content/application_details/<int:app_id>')
@login_required
def application_details_content(app_id):
    app_obj = Application.query.get_or_404(app_id)
    latest_version = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).first()
    project_name = app_obj.projects[0].name if app_obj.projects else None
    project_id = app_obj.projects[0].id if app_obj.projects else None

    return render_template(
        'application_details.html',
        app=app_obj,
        latest_version=latest_version,
        project_name=project_name,
        project_id=project_id
    )

@app.route('/application/<int:app_id>/details')
@login_required
def application_details_page(app_id):
    app_obj = Application.query.get_or_404(app_id)
    project_name = app_obj.projects[0].name if app_obj.projects else None
    latest_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
    if latest_version:
        latest_version.change_date = latest_version.change_date.strftime('%m/%d/%Y, %I:%M:%S %p')
    return render_template(
        'application_details.html',
        app=app_obj,
        project_name=project_name,
        latest_version=latest_version
    )

@app.route('/application/<int:app_id>', methods=['GET'])
@login_required
def show_application_page(app_id):
    return render_template('index.html', initial_page='application_details', app_id=app_id)

### JSON API routes
@app.route('/api/application/<int:app_id>', methods=['GET'])
@login_required
def get_application(app_id):
    app_obj = Application.query.get_or_404(app_id)
    app_data = {
        'id': app_obj.id,
        'name': app_obj.name,
        'link': app_obj.link,
        'label': app_obj.label,
        'project_id': app_obj.projects[0].id if app_obj.projects else None
    }
    return jsonify(app_data)

@app.route('/get_applications_data', methods=['GET'])
@login_required
def fetch_applications_data():
    search_query = request.args.get('search', '', type=str)
    query = Application.query

    if search_query:
        search_query_lower = search_query.lower()
        query = query.outerjoin(project_applications).outerjoin(Project).filter(
            or_(
                func.lower(Application.name).like(f'%{search_query_lower}%'),
                func.lower(Application.label).like(f'%{search_query_lower}%'),
                func.lower(Project.name).like(f'%{search_query_lower}%')
            )
        )

    applications = query.order_by(Application.id).all()
    apps_data = []
    for app_obj in applications:
        last_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
        version_info = last_version.number if last_version else 'No versions available'
        change_date = last_version.change_date.strftime('%m/%d/%Y, %I:%M:%S %p') if last_version else 'N/A'
        apps_data.append({
            'id': app_obj.id,
            'name': app_obj.name,
            'version_info': version_info,
            'change_date': change_date
        })
    return jsonify(apps_data)

@app.route('/app/<int:app_id>/versions', methods=['GET'])
@login_required
def get_app_versions(app_id):
    versions = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).all()
    versions_data = []
    for version in versions:
        versions_data.append({
            'number': version.number,
            'change_date': version.change_date.isoformat(),
            'notes': version.notes or ''
        })
    return jsonify(versions_data)

@app.route('/edit_application/<int:app_id>', methods=['POST'])
@login_required
def edit_application(app_id):
    data = request.get_json()
    app_obj = Application.query.get_or_404(app_id)

    app_obj.name = data.get('name').strip()
    app_obj.link = data.get('link').strip()
    project_id = data.get('project_id')

    if project_id:
        project = Project.query.get(project_id)
        app_obj.projects = [project] if project else []
    else:
        app_obj.projects = []

    if not app_obj.name:
        return jsonify({'error': 'Application name cannot be empty'}), 400

    try:
        db.session.commit()
        return jsonify({'message': 'Application updated successfully'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Application name must be unique'}), 400
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({'error': 'Database error'}), 500

@app.route('/create_application', methods=['POST'])
@login_required
def create_application():
    # Not specifically asked for link validation here,
    # but you can add if needed similarly to the project approach.
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        project_ids = data.get('project_ids', [])
        link = data.get('link', '').strip()
        label = data.get('label', '').strip()

        if not name:
            return jsonify({'error': 'Application name cannot be empty.'}), 400

        existing_app = Application.query.filter(func.lower(Application.name) == name.lower()).first()
        if existing_app:
            return jsonify({'error': 'Application name already exists. Please choose another name.'}), 400

        projects = Project.query.filter(Project.id.in_(project_ids)).all() if project_ids else []
        new_app = Application(name=name, link=link, label=label)
        new_app.projects.extend(projects)

        db.session.add(new_app)
        db.session.flush()

        initial_version = Version(application_id=new_app.id, number='0.0.0', change_date=datetime.utcnow())
        db.session.add(initial_version)
        db.session.commit()

        return jsonify({
            'message': 'Application created successfully',
            'id': new_app.id,
            'name': new_app.name,
            'link': new_app.link,
            'label': new_app.label,
            'created_at': new_app.created_at.isoformat(),
            'last_version_number': initial_version.number,
            'last_version_date': initial_version.change_date.isoformat()
        }), 201
    except IntegrityError as e:
        db.session.rollback()
        logging.error(f"Integrity error on creating application: {str(e)}")
        return jsonify({'error': 'This name already exists. Please use a different name.'}), 400
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"Database error on creating application: {str(e)}")
        return jsonify({'error': 'Database error. Please try again later.'}), 500
    except Exception as e:
        db.session.rollback()
        logging.error(f"Unexpected error on creating application: {str(e)}")
        return jsonify({'error': 'Server error: ' + str(e)}), 500

@app.route('/delete_application/<int:app_id>', methods=['DELETE'])
@login_required
def delete_application(app_id):
    app_to_delete = Application.query.get_or_404(app_id)
    try:
        db.session.delete(app_to_delete)
        db.session.commit()
        return jsonify({'message': 'Application deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting application {app_id}: {str(e)}")
        return jsonify({'error': 'Error deleting application'}), 500

@app.route('/get_projects', methods=['GET'])
@login_required
def get_projects():
    projects = Project.query.all()
    projects_data = [{'id': p.id, 'name': p.name} for p in projects]
    return jsonify(projects_data)

@app.route('/app/<int:application_id>/update_version', methods=['POST'])
@jwt_required()
def update_version(application_id):
    try:
        version_part = request.json.get('version_part')
        if version_part not in ['major', 'minor', 'patch']:
            return jsonify({'error': 'Invalid version part'}), 400

        latest_version = Version.query.filter_by(application_id=application_id).order_by(Version.change_date.desc()).first()
        if latest_version is None:
            return jsonify({'error': 'No versions found for this application'}), 404

        major, minor, patch = map(int, latest_version.number.split('.'))
        if version_part == 'major':
            major += 1
            minor = 0
            patch = 0
        elif version_part == 'minor':
            minor += 1
            patch = 0
        elif version_part == 'patch':
            patch += 1

        new_version_number = f"{major}.{minor}.{patch}"
        new_version = Version(application_id=application_id, number=new_version_number)
        db.session.add(new_version)
        db.session.commit()

        return jsonify({'new_version': new_version_number})
    except Exception as e:
        logging.error(f"Error updating version for application {application_id}: {str(e)}")
        return jsonify({'error': 'Server error while updating version'}), 500

### Project JSON API routes
@app.route('/get_projects_data', methods=['GET'])
@login_required
def get_projects_data():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 5

    if search_query:
        projects_query = Project.query.filter(Project.name.ilike(f'%{search_query}%')).order_by(Project.created_at.desc())
    else:
        projects_query = Project.query.order_by(Project.start_date.desc())

    pagination = projects_query.paginate(page=page, per_page=per_page, error_out=False)
    projects = pagination.items

    projects_data = []
    for project in projects:
        projects_data.append({
            'id': project.id,
            'name': project.name,
            'start_date': project.start_date.strftime('%Y-%m-%d'),
            'status': project.status,
        })

    return jsonify({
        'projects': projects_data,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'prev_num': pagination.prev_num,
        'next_num': pagination.next_num,
        'page': pagination.page,
        'total_pages': pagination.pages,
    })

@app.route('/create_project', methods=['POST'])
@login_required
def create_project():
    """Creates a new project with optional associated applications, now with link validation."""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        source_link = data.get('source_link', '').strip()
        status = data.get('status', 'Draft').strip()
        applications_ids = data.get('applications', [])

        # Validate required name
        if not name:
            return jsonify({'error': 'Project name is required'}), 400

        # Validate uniqueness of project name
        existing_project = Project.query.filter(func.lower(Project.name) == name.lower()).first()
        if existing_project:
            return jsonify({'error': 'Project name already exists. Please choose another name.'}), 400

        # Validate link (if not empty, must start with http:// or https://)
        if not is_valid_url(source_link):
            return jsonify({'error': 'Invalid link. Must start with http:// or https://'}), 400

        new_project = Project(name=name, description=description, source_link=source_link, status=status)
        applications = Application.query.filter(Application.id.in_(applications_ids)).all()
        new_project.applications.extend(applications)

        db.session.add(new_project)
        db.session.commit()

        return jsonify({'message': 'Project created successfully'}), 201
    except Exception as e:
        logging.error(f"Error creating project: {str(e)}")
        return jsonify({'error': 'Server error while creating project'}), 500

@app.route('/delete_project/<int:project_id>', methods=['DELETE'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    try:
        db.session.delete(project)
        db.session.commit()
        return jsonify({'message': 'Project deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting project {project_id}: {str(e)}")
        return jsonify({'error': 'Error deleting project'}), 500

@app.route('/project/<int:project_id>', methods=['GET'])
@login_required
def get_project_details(project_id):
    project = Project.query.get_or_404(project_id)
    return jsonify({
        'name': project.name,
        'description': project.description,
        'source_link': project.source_link,
        'created_at': project.created_at.strftime('%Y-%m-%d'),
        'status': project.status,
        'applications': [{'id': app.id, 'name': app.name} for app in project.applications]
    })

@app.route('/search_applications')
@login_required
def search_applications():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    applications = Application.query.filter(Application.name.ilike(f'%{query}%')).all()
    result = [{'id': app.id, 'name': app.name} for app in applications]
    return jsonify(result)

@app.route('/edit_project/<int:project_id>', methods=['POST'])
@login_required
def edit_project(project_id):
    """Edits a project's basic fields (including link validation) WITHOUT closing modal automatically."""
    project = Project.query.get_or_404(project_id)
    data = request.get_json()

    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    source_link = data.get('source_link', '').strip()
    status = data.get('status', '').strip()

    if not name:
        return jsonify({'error': 'Project name cannot be empty'}), 400

    # uniqueness check
    existing_project = Project.query.filter(
        func.lower(Project.name) == name.lower(),
        Project.id != project_id
    ).first()
    if existing_project:
        return jsonify({'error': 'Project name must be unique'}), 400

    # Validate link
    if not is_valid_url(source_link):
        return jsonify({'error': 'Invalid link. Must start with http:// or https://'}), 400

    project.name = name
    project.description = description
    project.source_link = source_link
    project.status = status or project.status

    try:
        db.session.commit()
        return jsonify({'message': 'Project updated successfully'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating project {project_id}: {str(e)}")
        return jsonify({'error': 'Database error'}), 500

### Additional routes
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/about')
@login_required
def about_page():
    return render_template('index.html', initial_page='about')

@app.route('/content/about')
@login_required
def about_content():
    return render_template('about.html')

@app.route('/guide')
@login_required
def guide_page():
    return render_template('index.html', initial_page='guide')

@app.route('/content/guide')
@login_required
def guide_content():
    return render_template('guide.html')

if __name__ == '__main__':
    test_database_connection()
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8000)