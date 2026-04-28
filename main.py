import os
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps
import logging
import re  # for URL validation
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash

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

users_str = os.environ.get("USERS", "")
users = {}
for pair in users_str.split(";"):
    pair = pair.strip()
    if pair:
        username, pwd = pair.split(":", 1)
        users[username] = pwd

jwt = JWTManager(app)

PLATFORM_ADMIN = 'admin'
PLATFORM_SUPER_ADMIN = PLATFORM_ADMIN
PLATFORM_USER = 'user'
PLATFORM_ROLES = (PLATFORM_ADMIN, PLATFORM_USER)
PLATFORM_ROLE_LABELS = {
    PLATFORM_ADMIN: 'Admin',
    PLATFORM_USER: 'User',
}

PROJECT_ADMIN = 'project_admin'
PROJECT_USER = 'project_user'
PROJECT_ROLES = (PROJECT_ADMIN, PROJECT_USER)
PROJECT_ROLE_LABELS = {
    PROJECT_ADMIN: 'Manager',
    PROJECT_USER: 'Operator',
}

ACCESS_NO_ACCESS = 'no_access'
ACCESS_VIEW_ONLY = 'view_only'
ACCESS_READ_WRITE = 'read_write'
PROJECT_ACCESS_LEVELS = (ACCESS_VIEW_ONLY, ACCESS_READ_WRITE)
APPLICATION_ACCESS_LEVELS = (ACCESS_NO_ACCESS, ACCESS_VIEW_ONLY, ACCESS_READ_WRITE)
DEFAULT_TIMEZONE = 'UTC'
PREFERRED_TIMEZONES = (
    'UTC',
    'Asia/Baku',
    'Europe/London',
    'Europe/Berlin',
    'Europe/Paris',
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Asia/Dubai',
    'Asia/Tokyo',
)


def is_valid_timezone(timezone_name):
    if not timezone_name:
        return False
    if timezone_name in get_timezone_options():
        return True
    try:
        ZoneInfo(timezone_name)
        return True
    except ZoneInfoNotFoundError:
        return False


def get_timezone_options():
    try:
        options = sorted(set(available_timezones()).union(PREFERRED_TIMEZONES))
    except Exception:
        options = sorted(PREFERRED_TIMEZONES)
    preferred = [timezone_name for timezone_name in PREFERRED_TIMEZONES if timezone_name in options]
    return preferred + [timezone_name for timezone_name in options if timezone_name not in preferred]


def get_user_timezone(user=None):
    user = user or get_current_user()
    timezone_name = user.timezone if user and user.timezone else DEFAULT_TIMEZONE
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return ZoneInfo(DEFAULT_TIMEZONE)


def to_user_datetime(value, user=None):
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=ZoneInfo(DEFAULT_TIMEZONE))
    return value.astimezone(get_user_timezone(user))


def format_datetime_for_user(value, user=None, fmt='%Y-%m-%d %H:%M %Z'):
    local_value = to_user_datetime(value, user)
    return local_value.strftime(fmt) if local_value else 'N/A'


def format_date_for_user(value, user=None):
    return format_datetime_for_user(value, user, '%Y-%m-%d')


def json_error(message, status_code=403):
    return jsonify({'error': message}), status_code


def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def has_platform_role(user, *roles):
    return bool(user and user.platform_role in roles)


def admin_count():
    return User.query.filter_by(platform_role=PLATFORM_ADMIN).count()


def is_last_admin(user):
    return bool(user and user.platform_role == PLATFORM_ADMIN and admin_count() <= 1)


def ensure_not_last_admin_change(user, new_role=None, delete=False):
    if not is_last_admin(user):
        return True, None
    if delete:
        return False, 'The last remaining admin cannot be deleted.'
    if new_role and new_role != PLATFORM_ADMIN:
        return False, 'The last remaining admin cannot be demoted.'
    return True, None


def get_project_membership(user, project_id):
    if not user or not project_id:
        return None
    return ProjectMembership.query.filter_by(user_id=user.id, project_id=project_id).first()


def is_project_admin(user, project_id):
    membership = get_project_membership(user, project_id)
    return bool(membership and membership.project_role == PROJECT_ADMIN)


def has_any_project_admin_membership(user):
    if not user:
        return False
    return ProjectMembership.query.filter_by(user_id=user.id, project_role=PROJECT_ADMIN).first() is not None


def has_project_access(user, project_id, minimum_access=ACCESS_VIEW_ONLY):
    if has_platform_role(user, PLATFORM_SUPER_ADMIN):
        return True
    membership = get_project_membership(user, project_id)
    if not membership:
        return False
    if minimum_access == ACCESS_VIEW_ONLY:
        return True
    return membership.access_level == ACCESS_READ_WRITE


def has_project_read_write_membership(user, project_id):
    membership = get_project_membership(user, project_id)
    return bool(membership and membership.access_level == ACCESS_READ_WRITE)


def project_role_label(project_role):
    return PROJECT_ROLE_LABELS.get(project_role, project_role or 'No Role')


def project_role_code(project_role):
    if project_role == PROJECT_ADMIN:
        return 'Manager'
    if project_role == PROJECT_USER:
        return 'Operator'
    return 'No Access'


def project_role_for_user(user, project_id):
    if has_platform_role(user, PLATFORM_ADMIN):
        return PLATFORM_ADMIN
    membership = get_project_membership(user, project_id)
    return membership.project_role if membership else None


def project_role_display_label(user, project_id):
    role = project_role_for_user(user, project_id)
    if role == PLATFORM_ADMIN:
        return 'Admin'
    return project_role_label(role)


def project_role_display_code(user, project_id):
    role = project_role_for_user(user, project_id)
    if role == PLATFORM_ADMIN:
        return 'Admin'
    return project_role_code(role)


def get_application_membership(user, application_id):
    if not user or not application_id:
        return None
    return ApplicationMembership.query.filter_by(user_id=user.id, application_id=application_id).first()


def application_project_ids(app_obj):
    return [project.id for project in app_obj.projects]


def has_any_project_read_write_membership(user):
    if has_platform_role(user, PLATFORM_ADMIN):
        return True
    if not user:
        return False
    return any(membership.access_level == ACCESS_READ_WRITE for membership in user.project_memberships)


def project_access_level_for_user(user, project_id):
    if has_platform_role(user, PLATFORM_ADMIN):
        return ACCESS_READ_WRITE
    membership = get_project_membership(user, project_id)
    return membership.access_level if membership else None


def access_label(access_level):
    if access_level == ACCESS_READ_WRITE:
        return 'Read Write'
    if access_level == ACCESS_VIEW_ONLY:
        return 'Read-Only'
    if access_level == ACCESS_NO_ACCESS:
        return 'No Access'
    return 'No Access'


def access_code(access_level):
    if access_level == ACCESS_READ_WRITE:
        return 'RW'
    if access_level == ACCESS_VIEW_ONLY:
        return 'RO'
    if access_level == ACCESS_NO_ACCESS:
        return 'No Access'
    return ''


def can_manage_access_page(user):
    return has_platform_role(user, PLATFORM_ADMIN) or has_any_project_admin_membership(user)


def can_manage_users_page(user):
    return has_platform_role(user, PLATFORM_ADMIN)


def can_manage_user(actor, target, new_platform_role=None):
    if not actor or not target:
        return False
    requested_role = new_platform_role or target.platform_role
    if requested_role not in PLATFORM_ROLES:
        return False
    if actor.id == target.id and actor.platform_role != PLATFORM_ADMIN:
        return False
    return actor.platform_role == PLATFORM_ADMIN


def can_create_user(actor, platform_role):
    if platform_role not in PLATFORM_ROLES:
        return False
    return has_platform_role(actor, PLATFORM_ADMIN)


def can_manage_project_membership(actor, project_id, target_user=None):
    if has_platform_role(actor, PLATFORM_ADMIN):
        return True
    if is_project_admin(actor, project_id):
        return not target_user or target_user.platform_role == PLATFORM_USER
    return False


def can_manage_application_membership(actor, app_obj, target_user=None, project_id=None):
    if not actor or not app_obj:
        return False
    if project_id:
        return can_manage_project_membership(actor, project_id, target_user)
    return any(can_manage_project_membership(actor, project.id, target_user) for project in app_obj.projects)


def accessible_project_ids(user):
    if has_platform_role(user, PLATFORM_ADMIN):
        return None
    if not user:
        return []
    return [membership.project_id for membership in user.project_memberships]


def can_view_application(user, app_obj):
    return application_access_level_for_user(user, app_obj) in (ACCESS_VIEW_ONLY, ACCESS_READ_WRITE)


def can_write_application(user, app_obj):
    return application_access_level_for_user(user, app_obj) == ACCESS_READ_WRITE


def application_access_level_for_user(user, app_obj):
    if has_platform_role(user, PLATFORM_ADMIN):
        return ACCESS_READ_WRITE
    if any(is_project_admin(user, project.id) for project in app_obj.projects):
        return ACCESS_READ_WRITE
    application_membership = get_application_membership(user, app_obj.id)
    if application_membership:
        return application_membership.access_level
    if any(get_project_membership(user, project.id) for project in app_obj.projects):
        return ACCESS_NO_ACCESS
    return None


def can_create_application_for_projects(user, project_ids):
    if has_platform_role(user, PLATFORM_ADMIN):
        return True
    if not project_ids:
        return False
    return all(has_project_read_write_membership(user, project_id) for project_id in project_ids)


def can_create_project_resource(user):
    return bool(user and (user.platform_role == PLATFORM_ADMIN or user.can_create_projects))


def can_manage_project_resource(user, project_id):
    return has_platform_role(user, PLATFORM_ADMIN) or is_project_admin(user, project_id)


def load_user_for_jwt_identity(identity):
    return User.query.filter_by(username=identity).first()


def require_platform_role(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not has_platform_role(user, *roles):
                return json_error('You do not have permission to perform this action.', 403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required(f):
    """Checks if a user is logged in (via session) to access specific routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current = get_current_user()
        if 'user_id' in session and current and current.is_active:
            return f(*args, **kwargs)
        if 'user_id' in session and current and not current.is_active:
            session.clear()
            if request.path.startswith('/api/') or request.is_json:
                return json_error('This account is disabled.', 403)
            flash('This account is disabled.')
            return redirect(url_for('login'))
        if 'username' in session and session.get('username') in users:
            return f(*args, **kwargs)
        session.clear()
        if request.path.startswith('/api/') or request.is_json:
            return json_error('Please log in to access this resource.', 401)
        if admin_count() == 0:
            return redirect(url_for('register'))
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Public bootstrap registration for the first admin only."""
    registration_open = admin_count() == 0
    if request.method == 'GET':
        return render_template('register.html', registration_open=registration_open)

    if not registration_open:
        return json_error('Public admin registration is closed.', 403)

    username = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    password = request.form.get('password', '')
    password_confirmation = request.form.get('password_confirmation', '')

    if not username or not password:
        flash('Username and password are required.')
        return render_template('register.html', registration_open=True), 400
    if password != password_confirmation:
        flash('Password confirmation does not match.')
        return render_template('register.html', registration_open=True), 400
    if User.query.filter(func.lower(User.username) == username.lower()).first():
        flash('Username already exists.')
        return render_template('register.html', registration_open=True), 400

    first_user = User(
        username=username,
        full_name=full_name,
        timezone=DEFAULT_TIMEZONE,
        platform_role=PLATFORM_ADMIN
    )
    first_user.set_password(password)
    db.session.add(first_user)
    db.session.commit()

    session.clear()
    session['user_id'] = first_user.id
    session['username'] = first_user.username
    session['platform_role'] = first_user.platform_role
    flash('Admin registered successfully.')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login with session-based authentication."""
    if 'user_id' in session and get_current_user():
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            session.clear()
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            session['platform_role'] = user.platform_role
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        elif user and user.check_password(password) and not user.is_active:
            flash('This account is disabled.')
            return redirect(url_for('login'))
        elif username in users and users[username] == password:
            session.clear()
            session['username'] = username
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html', registration_open=admin_count() == 0)

@app.route('/logout')
def logout():
    """Logs out the user by clearing the session."""
    session.clear()
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

class User(db.Model):
    """Represents an authenticated user and their platform role."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120))
    timezone = db.Column(db.String(64), nullable=False, default=DEFAULT_TIMEZONE)
    email = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    can_create_projects = db.Column(db.Boolean, nullable=False, default=False)
    last_login_at = db.Column(db.DateTime)
    password_hash = db.Column(db.String(255), nullable=False)
    platform_role = db.Column(db.String(50), nullable=False, default=PLATFORM_USER, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project_memberships = db.relationship('ProjectMembership', back_populates='user', cascade='all, delete-orphan')
    application_memberships = db.relationship('ApplicationMembership', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ProjectMembership(db.Model):
    """Links users to projects with project-scoped role and access level."""
    __tablename__ = 'project_memberships'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'project_id', name='uq_project_membership_user_project'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=False)
    project_role = db.Column(db.String(50), nullable=False, default=PROJECT_USER)
    access_level = db.Column(db.String(50), nullable=False, default=ACCESS_VIEW_ONLY)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='project_memberships')
    project = db.relationship('Project', back_populates='memberships')


class ApplicationMembership(db.Model):
    """Application-specific access override for a user."""
    __tablename__ = 'application_memberships'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'application_id', name='uq_application_membership_user_application'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id', ondelete='CASCADE'), nullable=False)
    access_level = db.Column(db.String(50), nullable=False, default=ACCESS_VIEW_ONLY)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='application_memberships')
    application = db.relationship('Application', back_populates='memberships')


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
    memberships = db.relationship('ApplicationMembership', back_populates='application', cascade='all, delete-orphan')

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
    memberships = db.relationship('ProjectMembership', back_populates='project', cascade='all, delete-orphan')

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
    user = get_current_user()
    return render_template('index.html', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/applications')
@login_required
def applications_page():
    user = get_current_user()
    return render_template('index.html', initial_page='applications', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/projects')
@login_required
def projects_page():
    user = get_current_user()
    return render_template('index.html', initial_page='projects', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/users')
@login_required
def users_page():
    user = get_current_user()
    if not can_manage_users_page(user):
        return json_error('You do not have permission to access user management.', 403)
    return render_template('index.html', initial_page='users', current_user=user, can_manage_access=True, can_manage_users=True)

@app.route('/settings')
@login_required
def settings_page():
    user = get_current_user()
    return render_template('index.html', initial_page='settings', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/content/applications')
@login_required
def applications_content():
    return render_template('applications.html', can_create_application=has_any_project_read_write_membership(get_current_user()))

@app.route('/content/projects')
@login_required
def projects_content():
    return render_template('projects.html', can_create_project=can_create_project_resource(get_current_user()))

@app.route('/content/application_details/<int:app_id>')
@login_required
def application_details_content(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return json_error('You do not have access to this application.', 403)
    latest_version = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).first()
    latest_version_display = format_datetime_for_user(latest_version.change_date) if latest_version else None
    project_name = app_obj.projects[0].name if app_obj.projects else None
    project_id = app_obj.projects[0].id if app_obj.projects else None
    app_access_level = application_access_level_for_user(current, app_obj)

    return render_template(
        'application_details.html',
        app=app_obj,
        latest_version=latest_version,
        latest_version_display=latest_version_display,
        project_name=project_name,
        project_id=project_id,
        can_edit_application=can_write_application(current, app_obj),
        access_level_label=access_label(app_access_level)
    )

@app.route('/application/<int:app_id>/details')
@login_required
def application_details_page(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return json_error('You do not have access to this application.', 403)
    project_name = app_obj.projects[0].name if app_obj.projects else None
    project_id = app_obj.projects[0].id if app_obj.projects else None
    latest_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
    latest_version_display = format_datetime_for_user(latest_version.change_date) if latest_version else None
    app_access_level = application_access_level_for_user(current, app_obj)
    return render_template(
        'application_details.html',
        app=app_obj,
        project_name=project_name,
        project_id=project_id,
        latest_version=latest_version,
        latest_version_display=latest_version_display,
        can_edit_application=can_write_application(current, app_obj),
        access_level_label=access_label(app_access_level)
    )

@app.route('/application/<int:app_id>', methods=['GET'])
@login_required
def show_application_page(app_id):
    user = get_current_user()
    return render_template('index.html', initial_page='application_details', app_id=app_id, current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

### JSON API routes
@app.route('/api/application/<int:app_id>', methods=['GET'])
@login_required
def get_application(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return json_error('You do not have access to this application.', 403)
    app_access_level = application_access_level_for_user(current, app_obj)
    project = app_obj.projects[0] if app_obj.projects else None
    app_data = {
        'id': app_obj.id,
        'name': app_obj.name,
        'link': app_obj.link,
        'label': app_obj.label,
        'project_id': project.id if project else None,
        'project_name': project.name if project else 'No project',
        'access_level': app_access_level,
        'access_label': access_label(app_access_level),
        'access_code': access_code(app_access_level),
        'can_edit': can_write_application(current, app_obj),
        'can_change_project': has_platform_role(current, PLATFORM_ADMIN)
    }
    return jsonify(app_data)

@app.route('/get_applications_data', methods=['GET'])
@login_required
def fetch_applications_data():
    search_query = request.args.get('search', '', type=str)
    ids_param = request.args.get('ids', '', type=str).strip()
    user = get_current_user()
    query = Application.query

    requested_ids = []
    if ids_param:
        requested_ids = [int(value) for value in ids_param.split(',') if value.strip().isdigit()]
        if requested_ids:
            query = query.filter(Application.id.in_(requested_ids))

    project_ids = accessible_project_ids(user)
    if project_ids is not None:
        application_ids = [
            membership.application_id
            for membership in user.application_memberships
        ] if user else []
        if not project_ids and not application_ids:
            return jsonify([])
        project_application_ids = db.session.query(project_applications.c.application_id).filter(
            project_applications.c.project_id.in_(project_ids)
        ) if project_ids else []
        query = query.filter(or_(
            Application.id.in_(project_application_ids),
            Application.id.in_(application_ids)
        )).distinct()

    if search_query:
        search_query_lower = search_query.lower()
        query = query.outerjoin(project_applications).outerjoin(Project).filter(
            or_(
                func.lower(Application.name).like(f'%{search_query_lower}%'),
                func.lower(Application.label).like(f'%{search_query_lower}%'),
                func.lower(Project.name).like(f'%{search_query_lower}%')
            )
        )

    applications = [
        app_obj for app_obj in query.order_by(Application.id).all()
        if can_view_application(user, app_obj)
    ]
    apps_data = []
    for app_obj in applications:
        last_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
        version_info = last_version.number if last_version else 'No versions available'
        change_date = format_datetime_for_user(last_version.change_date, user) if last_version else 'N/A'
        app_access_level = application_access_level_for_user(user, app_obj)
        apps_data.append({
            'id': app_obj.id,
            'name': app_obj.name,
            'version_info': version_info,
            'change_date': change_date,
            'access_level': app_access_level,
            'access_label': access_label(app_access_level),
            'access_code': access_code(app_access_level),
            'can_edit': can_write_application(user, app_obj)
        })
    return jsonify(apps_data)

@app.route('/app/<int:app_id>/versions', methods=['GET'])
@login_required
def get_app_versions(app_id):
    app_obj = Application.query.get_or_404(app_id)
    if not can_view_application(get_current_user(), app_obj):
        return json_error('You do not have access to this application.', 403)
    versions = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).all()
    versions_data = []
    for version in versions:
        versions_data.append({
            'number': version.number,
            'change_date': format_datetime_for_user(version.change_date),
            'notes': version.notes or ''
        })
    return jsonify(versions_data)

@app.route('/edit_application/<int:app_id>', methods=['POST'])
@login_required
def edit_application(app_id):
    data = request.get_json()
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_write_application(current, app_obj):
        return json_error('You do not have permission to update this application.', 403)

    app_obj.name = data.get('name').strip()
    app_obj.link = data.get('link', '').strip()
    app_obj.label = data.get('label', '').strip()
    current_project_id = app_obj.projects[0].id if app_obj.projects else None
    if 'project_id' in data:
        project_id = data.get('project_id')
        requested_project_id = int(project_id) if project_id else None
        if not has_platform_role(current, PLATFORM_ADMIN) and requested_project_id != current_project_id:
            return json_error('You do not have permission to change the application project.', 403)
        if project_id and not has_project_access(current, requested_project_id, ACCESS_READ_WRITE):
            return json_error('You do not have write access to the selected project.', 403)

        if has_platform_role(current, PLATFORM_ADMIN) and project_id:
            project = Project.query.get(requested_project_id)
            app_obj.projects = [project] if project else []
        elif has_platform_role(current, PLATFORM_ADMIN):
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
        project_ids = [int(project_id) for project_id in data.get('project_ids', []) if project_id]
        if not can_create_application_for_projects(get_current_user(), project_ids):
            return jsonify({'error': 'You do not have permission to create applications for these projects.'}), 403
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
    if not can_write_application(get_current_user(), app_to_delete):
        return json_error('You do not have permission to delete this application.', 403)
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
    user = get_current_user()
    access = request.args.get('access', '').strip()
    project_ids = accessible_project_ids(user)
    query = Project.query
    if access == ACCESS_READ_WRITE and not has_platform_role(user, PLATFORM_ADMIN):
        project_ids = [
            membership.project_id
            for membership in user.project_memberships
            if membership.access_level == ACCESS_READ_WRITE
        ] if user else []
        if not project_ids:
            return jsonify([])
        query = query.filter(Project.id.in_(project_ids))
    elif project_ids is not None:
        if not project_ids:
            return jsonify([])
        query = query.filter(Project.id.in_(project_ids))
    projects = query.order_by(Project.name).all()
    projects_data = [{'id': p.id, 'name': p.name} for p in projects]
    return jsonify(projects_data)

@app.route('/app/<int:application_id>/update_version', methods=['POST'])
@jwt_required()
def update_version(application_id):
    try:
        jwt_user = load_user_for_jwt_identity(get_jwt_identity())
        app_obj = Application.query.get_or_404(application_id)
        if not can_write_application(jwt_user, app_obj):
            return jsonify({'error': 'You do not have permission to update this application.'}), 403
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
    ids_param = request.args.get('ids', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 5

    user = get_current_user()
    project_ids = accessible_project_ids(user)
    requested_ids = [int(value) for value in ids_param.split(',') if value.strip().isdigit()] if ids_param else []
    if search_query:
        projects_query = Project.query.filter(Project.name.ilike(f'%{search_query}%')).order_by(Project.created_at.desc())
    else:
        projects_query = Project.query.order_by(Project.start_date.desc())
    if requested_ids:
        projects_query = projects_query.filter(Project.id.in_(requested_ids))
    if project_ids is not None:
        if not project_ids:
            return jsonify({
                'projects': [],
                'has_prev': False,
                'has_next': False,
                'prev_num': None,
                'next_num': None,
                'page': 1,
                'total_pages': 0,
            })
        projects_query = projects_query.filter(Project.id.in_(project_ids))

    pagination = projects_query.paginate(page=page, per_page=per_page, error_out=False)
    projects = pagination.items

    projects_data = []
    for project in projects:
        project_access_level = project_access_level_for_user(user, project.id)
        projects_data.append({
            'id': project.id,
            'name': project.name,
            'start_date': format_date_for_user(project.start_date, user),
            'status': project.status,
            'access_level': project_access_level,
            'access_label': access_label(project_access_level),
            'access_code': access_code(project_access_level),
            'project_role_label': project_role_display_label(user, project.id),
            'project_role_code': project_role_display_code(user, project.id),
            'can_edit': can_manage_project_resource(user, project.id),
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
    current = get_current_user()
    if not can_create_project_resource(current):
        return json_error('You do not have permission to create projects.', 403)
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
        db.session.flush()
        if current and current.platform_role == PLATFORM_USER:
            db.session.add(ProjectMembership(
                user_id=current.id,
                project_id=new_project.id,
                project_role=PROJECT_ADMIN,
                access_level=ACCESS_READ_WRITE,
            ))
        db.session.commit()

        return jsonify({'message': 'Project created successfully'}), 201
    except Exception as e:
        logging.error(f"Error creating project: {str(e)}")
        return jsonify({'error': 'Server error while creating project'}), 500

@app.route('/delete_project/<int:project_id>', methods=['DELETE'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project_resource(get_current_user(), project_id):
        return json_error('You do not have permission to delete this project.', 403)
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
    current = get_current_user()
    if not has_project_access(current, project_id, ACCESS_VIEW_ONLY):
        return json_error('You do not have access to this project.', 403)
    project_access_level = project_access_level_for_user(current, project_id)
    return jsonify({
        'name': project.name,
        'description': project.description,
        'source_link': project.source_link,
        'created_at': format_date_for_user(project.created_at),
        'status': project.status,
        'access_level': project_access_level,
        'access_label': access_label(project_access_level),
        'access_code': access_code(project_access_level),
        'project_role_label': project_role_display_label(current, project_id),
        'project_role_code': project_role_display_code(current, project_id),
        'can_edit': can_manage_project_resource(current, project_id),
        'applications': [
            {
                'id': app.id,
                'name': app.name,
                'access_level': application_access_level_for_user(current, app),
                'access_label': access_label(application_access_level_for_user(current, app)),
                'access_code': access_code(application_access_level_for_user(current, app)),
                'can_view': can_view_application(current, app),
            }
            for app in project.applications
            if is_project_admin(current, project_id) or has_platform_role(current, PLATFORM_ADMIN) or can_view_application(current, app)
        ]
    })

@app.route('/search_applications')
@login_required
def search_applications():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    applications_query = Application.query.filter(Application.name.ilike(f'%{query}%'))
    project_ids = accessible_project_ids(get_current_user())
    if project_ids is not None:
        if not project_ids:
            return jsonify([])
        applications_query = applications_query.join(project_applications).filter(project_applications.c.project_id.in_(project_ids)).distinct()
    applications = applications_query.all()
    result = [{'id': app.id, 'name': app.name} for app in applications]
    return jsonify(result)

@app.route('/edit_project/<int:project_id>', methods=['POST'])
@login_required
def edit_project(project_id):
    """Edits a project's basic fields (including link validation) WITHOUT closing modal automatically."""
    project = Project.query.get_or_404(project_id)
    if not can_manage_project_resource(get_current_user(), project_id):
        return json_error('You do not have permission to update this project.', 403)
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

### User and project membership routes
def serialize_user(user):
    return {
        'id': user.id,
        'username': user.username,
        'full_name': user.full_name or '',
        'email': user.email or '',
        'timezone': user.timezone or DEFAULT_TIMEZONE,
        'platform_role': user.platform_role,
        'platform_role_label': PLATFORM_ROLE_LABELS.get(user.platform_role, user.platform_role),
        'is_active': bool(user.is_active),
        'can_create_projects': bool(user.can_create_projects),
        'status': 'Active' if user.is_active else 'Disabled',
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'created_at_display': format_datetime_for_user(user.created_at, fmt='%Y-%m-%d %H:%M') if user.created_at else 'N/A',
        'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
        'last_login_display': format_datetime_for_user(user.last_login_at, fmt='%Y-%m-%d %H:%M') if user.last_login_at else 'Never'
    }


def serialize_user_details(user):
    data = serialize_user(user)
    explicit_application_access = {
        membership.application_id: membership
        for membership in user.application_memberships
        if membership.application is not None
    }
    applications = {}
    project_map = {}

    for membership in user.project_memberships:
        if membership.project is None:
            continue
        project_map[membership.project_id] = {
            'id': membership.project_id,
            'name': membership.project.name,
            'project_role': membership.project_role,
            'project_role_label': project_role_label(membership.project_role),
            'project_role_code': project_role_code(membership.project_role),
            'access_level': membership.access_level,
            'access_code': project_role_code(membership.project_role),
            'access_label': project_role_label(membership.project_role),
            'sort_updated_at': (membership.updated_at or membership.created_at or datetime.min).isoformat(),
            'applications': []
        }
        for app_obj in membership.project.applications:
            explicit_membership = explicit_application_access.get(app_obj.id)
            app_access = (
                explicit_membership.access_level
                if explicit_membership is not None
                else ACCESS_READ_WRITE if membership.project_role == PROJECT_ADMIN else ACCESS_NO_ACCESS
            )
            app_data = {
                'id': app_obj.id,
                'name': app_obj.name,
                'project_id': membership.project_id,
                'project_name': membership.project.name,
                'access_level': app_access,
                'access_code': access_code(app_access),
                'access_label': access_label(app_access),
                'sort_updated_at': (
                    (explicit_membership.updated_at or explicit_membership.created_at)
                    if explicit_membership is not None
                    else (app_obj.updated_at or app_obj.created_at or membership.updated_at or membership.created_at or datetime.min)
                ).isoformat()
            }
            applications[app_obj.id] = app_data
            project_map[membership.project_id]['applications'].append(app_data)

    for membership in user.application_memberships:
        if membership.application is None:
            continue
        project = membership.application.projects[0] if membership.application.projects else None
        if project is None:
            continue
        project_id = project.id if project else None
        project_name = project.name if project else 'No project'
        app_data = {
            'id': membership.application_id,
            'name': membership.application.name,
            'project_id': project_id,
            'project_name': project_name,
            'access_level': membership.access_level,
            'access_code': access_code(membership.access_level),
            'access_label': access_label(membership.access_level),
            'sort_updated_at': (membership.updated_at or membership.created_at or datetime.min).isoformat()
        }
        applications[membership.application_id] = app_data
        if project_id is not None and project_id in project_map:
            existing_items = {
                item['id']: item
                for item in project_map[project_id]['applications']
            }
            existing_items[membership.application_id] = app_data
            project_map[project_id]['applications'] = list(existing_items.values())
        elif project_id is not None:
            project_map[project_id] = {
                'id': project_id,
                'name': project_name,
                'project_role': None,
                'project_role_label': 'No Project Membership',
                'project_role_code': 'No Access',
                'access_level': None,
                'access_code': 'No Access',
                'access_label': 'No Project Membership',
                'sort_updated_at': (membership.updated_at or membership.created_at or datetime.min).isoformat(),
                'applications': [app_data]
            }

    data['assigned_applications'] = sorted(
        applications.values(),
        key=lambda item: item.get('sort_updated_at') or '',
        reverse=True
    )
    assigned_projects = sorted(
        project_map.values(),
        key=lambda item: item.get('sort_updated_at') or '',
        reverse=True
    )
    for project in assigned_projects:
        project['applications'] = sorted(
            project['applications'],
            key=lambda item: item.get('sort_updated_at') or '',
            reverse=True
        )
    data['assigned_projects'] = assigned_projects
    return data


def serialize_membership(membership):
    return {
        'id': membership.id,
        'user_id': membership.user_id,
        'username': membership.user.username,
        'full_name': membership.user.full_name or '',
        'project_id': membership.project_id,
        'project_name': membership.project.name,
        'project_role': membership.project_role,
        'project_role_label': project_role_label(membership.project_role),
        'access_level': membership.access_level
    }


def serialize_application_membership(membership):
    project = membership.application.projects[0] if membership.application.projects else None
    return {
        'id': membership.id,
        'user_id': membership.user_id,
        'username': membership.user.username,
        'application_id': membership.application_id,
        'application_name': membership.application.name,
        'project_id': project.id if project else None,
        'project_name': project.name if project else 'No project',
        'access_level': membership.access_level,
        'access_code': access_code(membership.access_level),
        'access_label': access_label(membership.access_level)
    }


@app.route('/content/settings')
@login_required
def settings_content():
    return render_template('settings.html', timezone_options=get_timezone_options())


@app.route('/api/me', methods=['GET'])
@login_required
def get_me():
    user = get_current_user()
    if not user:
        return json_error('Settings are available only for database users.', 403)
    return jsonify(serialize_user_details(user))


@app.route('/api/me', methods=['PUT'])
@login_required
def update_me():
    user = get_current_user()
    if not user:
        return json_error('Settings are available only for database users.', 403)

    data = request.get_json() or {}
    email = data.get('email', user.email or '').strip()
    full_name = data.get('full_name', user.full_name or '').strip()
    timezone_name = data.get('timezone', user.timezone or DEFAULT_TIMEZONE).strip()

    if not is_valid_timezone(timezone_name):
        return json_error('Invalid time zone.', 400)

    user.email = email
    user.full_name = full_name
    user.timezone = timezone_name
    db.session.commit()
    return jsonify(serialize_user_details(user))


@app.route('/api/me/password', methods=['POST'])
@login_required
def update_my_password():
    user = get_current_user()
    if not user:
        return json_error('Settings are available only for database users.', 403)

    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    password_confirmation = data.get('password_confirmation', '')

    if not current_password or not new_password:
        return json_error('Current password and new password are required.', 400)
    if not user.check_password(current_password):
        return json_error('Current password is incorrect.', 400)
    if new_password != password_confirmation:
        return json_error('Password confirmation does not match.', 400)

    user.set_password(new_password)
    db.session.commit()
    return jsonify({'message': 'Password updated successfully'})


@app.route('/content/users')
@login_required
def users_content():
    if not can_manage_users_page(get_current_user()):
        return json_error('You do not have permission to access user management.', 403)
    return render_template(
        'users.html',
        platform_roles=PLATFORM_ROLES,
        platform_role_labels=PLATFORM_ROLE_LABELS,
        project_roles=PROJECT_ROLES,
        project_access_levels=PROJECT_ACCESS_LEVELS
    )


@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    current = get_current_user()
    if has_platform_role(current, PLATFORM_ADMIN):
        query = User.query
    elif has_any_project_admin_membership(current):
        query = User.query.filter_by(platform_role=PLATFORM_USER)
    else:
        return json_error('You do not have permission to list users.', 403)
    return jsonify([serialize_user(user) for user in query.order_by(User.username).all()])


@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    current = get_current_user()
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    full_name = data.get('full_name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    password_confirmation = data.get('password_confirmation', '')
    platform_role = data.get('platform_role', PLATFORM_USER).strip() or PLATFORM_USER
    can_create_projects = bool(data.get('can_create_projects', False))

    if not can_create_user(current, platform_role):
        return json_error('You do not have permission to create this user role.', 403)
    if not username or not password:
        return json_error('Username and password are required.', 400)
    if password != password_confirmation:
        return json_error('Password confirmation does not match.', 400)
    if User.query.filter(func.lower(User.username) == username.lower()).first():
        return json_error('Username already exists.', 400)

    new_user = User(
        username=username,
        full_name=full_name,
        email=email,
        platform_role=platform_role,
        can_create_projects=can_create_projects if platform_role == PLATFORM_USER else False,
    )
    new_user.timezone = DEFAULT_TIMEZONE
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(serialize_user(new_user)), 201


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    current = get_current_user()
    target = User.query.get_or_404(user_id)
    data = request.get_json() or {}
    new_platform_role = data.get('platform_role', target.platform_role).strip() or target.platform_role

    if not can_manage_user(current, target, new_platform_role):
        return json_error('You do not have permission to update this user.', 403)
    if current and current.id == target.id and new_platform_role != target.platform_role:
        return json_error('You cannot change your own platform role.', 400)

    ok, message = ensure_not_last_admin_change(target, new_platform_role)
    if not ok:
        return json_error(message, 400)

    username = data.get('username', target.username).strip()
    full_name = data.get('full_name', target.full_name or '').strip()
    email = data.get('email', target.email or '').strip()
    timezone_name = data.get('timezone', target.timezone or DEFAULT_TIMEZONE).strip()
    can_create_projects = bool(data.get('can_create_projects', target.can_create_projects))
    password = data.get('password', '')
    password_confirmation = data.get('password_confirmation', '')

    if not username:
        return json_error('Username is required.', 400)
    if not is_valid_timezone(timezone_name):
        return json_error('Invalid time zone.', 400)
    duplicate = User.query.filter(func.lower(User.username) == username.lower(), User.id != user_id).first()
    if duplicate:
        return json_error('Username already exists.', 400)
    if password or password_confirmation:
        if password != password_confirmation:
            return json_error('Password confirmation does not match.', 400)
        target.set_password(password)

    target.username = username
    target.full_name = full_name
    target.email = email
    target.timezone = timezone_name
    target.platform_role = new_platform_role
    target.can_create_projects = can_create_projects if new_platform_role == PLATFORM_USER else False
    db.session.commit()
    return jsonify(serialize_user(target))


@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user_details(user_id):
    current = get_current_user()
    target = User.query.get_or_404(user_id)
    if not can_manage_user(current, target, target.platform_role) and not can_manage_users_page(current):
        return json_error('You do not have permission to view this user.', 403)
    return jsonify(serialize_user_details(target))


@app.route('/api/users/<int:user_id>/status', methods=['PUT'])
@login_required
def update_user_status(user_id):
    current = get_current_user()
    target = User.query.get_or_404(user_id)
    data = request.get_json() or {}
    is_active = bool(data.get('is_active', True))

    if not can_manage_user(current, target):
        return json_error('You do not have permission to update this user.', 403)
    if current and current.id == target.id and not is_active:
        return json_error('You cannot disable your own account.', 400)
    if not is_active and is_last_admin(target):
        return json_error('The last remaining admin cannot be disabled.', 400)

    target.is_active = is_active
    db.session.commit()
    if session.get('user_id') == user_id and not is_active:
        session.clear()
    return jsonify(serialize_user(target))


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    current = get_current_user()
    target = User.query.get_or_404(user_id)

    if not can_manage_user(current, target):
        return json_error('You do not have permission to delete this user.', 403)
    if current and current.id == target.id:
        return json_error('You cannot delete your own account.', 400)
    ok, message = ensure_not_last_admin_change(target, delete=True)
    if not ok:
        return json_error(message, 400)

    db.session.delete(target)
    db.session.commit()
    if session.get('user_id') == user_id:
        session.clear()
    return jsonify({'message': 'User deleted successfully'})


@app.route('/api/project_memberships', methods=['GET'])
@login_required
def list_project_memberships():
    current = get_current_user()
    project_id = request.args.get('project_id', type=int)
    query = ProjectMembership.query.join(Project).join(User)

    if project_id:
        if not can_manage_project_membership(current, project_id):
            return json_error('You do not have permission to view these memberships.', 403)
        query = query.filter(ProjectMembership.project_id == project_id)
    elif has_platform_role(current, PLATFORM_ADMIN):
        pass
    elif has_any_project_admin_membership(current):
        admin_project_ids = [
            membership.project_id
            for membership in current.project_memberships
            if membership.project_role == PROJECT_ADMIN
        ]
        query = query.filter(ProjectMembership.project_id.in_(admin_project_ids))
    else:
        return json_error('You do not have permission to view memberships.', 403)

    memberships = query.order_by(Project.name, User.username).all()
    return jsonify([serialize_membership(membership) for membership in memberships])


@app.route('/api/project_memberships', methods=['POST'])
@login_required
def create_project_membership():
    current = get_current_user()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    project_id = data.get('project_id')
    project_role = data.get('project_role', PROJECT_USER)
    target_user = User.query.get_or_404(user_id)
    Project.query.get_or_404(project_id)
    if target_user.platform_role == PLATFORM_ADMIN:
        return json_error('Admin accounts already have platform-wide access.', 400)
    if project_role not in PROJECT_ROLES:
        return json_error('Invalid project role.', 400)
    if not can_manage_project_membership(current, project_id, target_user):
        return json_error('You do not have permission to create this membership.', 403)
    if ProjectMembership.query.filter_by(user_id=user_id, project_id=project_id).first():
        return json_error('User is already assigned to this project.', 400)

    access_level = ACCESS_READ_WRITE if project_role == PROJECT_ADMIN else ACCESS_VIEW_ONLY

    membership = ProjectMembership(
        user_id=user_id,
        project_id=project_id,
        project_role=project_role,
        access_level=access_level
    )
    db.session.add(membership)
    db.session.commit()
    return jsonify(serialize_membership(membership)), 201


@app.route('/api/project_memberships/<int:membership_id>', methods=['PUT'])
@login_required
def update_project_membership(membership_id):
    current = get_current_user()
    membership = ProjectMembership.query.get_or_404(membership_id)
    data = request.get_json() or {}
    project_role = data.get('project_role', membership.project_role)
    if membership.user.platform_role == PLATFORM_ADMIN:
        return json_error('Admin accounts already have platform-wide access.', 400)

    if project_role not in PROJECT_ROLES:
        return json_error('Invalid project role.', 400)
    if not can_manage_project_membership(current, membership.project_id, membership.user):
        return json_error('You do not have permission to update this membership.', 403)

    membership.project_role = project_role
    membership.access_level = ACCESS_READ_WRITE if project_role == PROJECT_ADMIN else ACCESS_VIEW_ONLY
    db.session.commit()
    return jsonify(serialize_membership(membership))


@app.route('/api/project_memberships/<int:membership_id>', methods=['DELETE'])
@login_required
def delete_project_membership(membership_id):
    current = get_current_user()
    membership = ProjectMembership.query.get_or_404(membership_id)
    if not can_manage_project_membership(current, membership.project_id, membership.user):
        return json_error('You do not have permission to delete this membership.', 403)

    db.session.delete(membership)
    db.session.commit()
    return jsonify({'message': 'Membership deleted successfully'})


@app.route('/api/application_memberships', methods=['GET', 'POST'])
@login_required
def list_application_memberships():
    if request.method == 'POST':
        return create_application_membership()

    current = get_current_user()
    project_id = request.args.get('project_id', type=int)
    query = ApplicationMembership.query.join(Application).join(User)

    if project_id:
        if not can_manage_project_membership(current, project_id):
            return json_error('You do not have permission to view these application memberships.', 403)
        query = query.join(project_applications, project_applications.c.application_id == Application.id)
        query = query.filter(project_applications.c.project_id == project_id)
    elif has_platform_role(current, PLATFORM_ADMIN):
        pass
    elif has_any_project_admin_membership(current):
        admin_project_ids = [
            membership.project_id
            for membership in current.project_memberships
            if membership.project_role == PROJECT_ADMIN
        ]
        if not admin_project_ids:
            return jsonify([])
        query = query.join(project_applications, project_applications.c.application_id == Application.id)
        query = query.filter(project_applications.c.project_id.in_(admin_project_ids))
    else:
        return json_error('You do not have permission to view application memberships.', 403)

    memberships = query.order_by(Application.name, User.username).all()
    return jsonify([serialize_application_membership(membership) for membership in memberships])


def create_application_membership():
    current = get_current_user()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    application_id = data.get('application_id')
    project_id = data.get('project_id')
    access_level = data.get('access_level', ACCESS_VIEW_ONLY)

    target_user = User.query.get_or_404(user_id)
    app_obj = Application.query.get_or_404(application_id)
    if target_user.platform_role == PLATFORM_ADMIN:
        return json_error('Admin accounts already have platform-wide access.', 400)
    if access_level not in APPLICATION_ACCESS_LEVELS:
        return json_error('Invalid application access level.', 400)
    if project_id:
        project = Project.query.get_or_404(project_id)
        if app_obj not in project.applications:
            return json_error('Application must belong to the selected project.', 400)
    if not can_manage_application_membership(current, app_obj, target_user, project_id):
        return json_error('You do not have permission to create this application membership.', 403)
    if ApplicationMembership.query.filter_by(user_id=user_id, application_id=application_id).first():
        return json_error('User is already assigned to this application.', 400)

    membership = ApplicationMembership(
        user_id=user_id,
        application_id=application_id,
        access_level=access_level
    )
    db.session.add(membership)
    db.session.commit()
    return jsonify(serialize_application_membership(membership)), 201


@app.route('/api/application_memberships/<int:membership_id>', methods=['PUT'])
@login_required
def update_application_membership(membership_id):
    current = get_current_user()
    membership = ApplicationMembership.query.get_or_404(membership_id)
    data = request.get_json() or {}
    project_id = data.get('project_id')
    access_level = data.get('access_level', membership.access_level)

    if membership.user.platform_role == PLATFORM_ADMIN:
        return json_error('Admin accounts already have platform-wide access.', 400)
    if access_level not in APPLICATION_ACCESS_LEVELS:
        return json_error('Invalid application access level.', 400)
    if project_id:
        project = Project.query.get_or_404(project_id)
        if membership.application not in project.applications:
            return json_error('Application must belong to the selected project.', 400)
    if not can_manage_application_membership(current, membership.application, membership.user, project_id):
        return json_error('You do not have permission to update this application membership.', 403)

    membership.access_level = access_level
    db.session.commit()
    return jsonify(serialize_application_membership(membership))


@app.route('/api/application_memberships/<int:membership_id>', methods=['DELETE'])
@login_required
def delete_application_membership(membership_id):
    current = get_current_user()
    membership = ApplicationMembership.query.get_or_404(membership_id)
    if not can_manage_application_membership(current, membership.application, membership.user):
        return json_error('You do not have permission to delete this application membership.', 403)

    db.session.delete(membership)
    db.session.commit()
    return jsonify({'message': 'Application membership deleted successfully'})


@app.route('/api/application_memberships/bulk', methods=['POST'])
@login_required
def bulk_update_application_memberships():
    current = get_current_user()
    data = request.get_json() or {}
    project_id = data.get('project_id')
    project_role = data.get('project_role', PROJECT_USER)
    user_ids = data.get('user_ids', [])
    applications = data.get('applications', [])

    project = Project.query.get_or_404(project_id)
    if project_role not in PROJECT_ROLES:
        return json_error('Invalid project role.', 400)
    if not isinstance(user_ids, list) or not user_ids:
        return json_error('Select at least one user.', 400)
    if not isinstance(applications, list):
        return json_error('Invalid applications payload.', 400)

    project_application_ids = {app_obj.id for app_obj in project.applications}
    requested_application_ids = {int(item.get('application_id')) for item in applications if item.get('application_id')}
    if not requested_application_ids.issubset(project_application_ids):
        return json_error('Applications must belong to the selected project.', 400)

    access_by_application = {}
    for item in applications:
        application_id = item.get('application_id')
        if not application_id:
            continue
        access_level = item.get('access_level', ACCESS_VIEW_ONLY)
        if access_level not in APPLICATION_ACCESS_LEVELS:
            return json_error('Invalid application access level.', 400)
        access_by_application[int(application_id)] = access_level

    updated = []
    for user_id in user_ids:
        target_user = User.query.get_or_404(user_id)
        if not can_manage_project_membership(current, project_id, target_user):
            return json_error('You do not have permission to assign one or more selected users.', 403)
        if target_user.platform_role == PLATFORM_ADMIN:
            return json_error('Admin accounts already have platform-wide access.', 400)

        target_project_role = project_role
        membership_project_access = ACCESS_VIEW_ONLY
        if target_project_role == PROJECT_ADMIN:
            membership_project_access = ACCESS_READ_WRITE

        project_membership = ProjectMembership.query.filter_by(user_id=user_id, project_id=project_id).first()
        if project_membership:
            project_membership.project_role = target_project_role
            project_membership.access_level = membership_project_access
        else:
            project_membership = ProjectMembership(
                user_id=user_id,
                project_id=project_id,
                project_role=target_project_role,
                access_level=membership_project_access
            )
            db.session.add(project_membership)

        project_application_ids = {app_obj.id for app_obj in project.applications}
        effective_access_by_application = dict(access_by_application)
        if target_project_role == PROJECT_ADMIN:
            effective_access_by_application = {application_id: ACCESS_READ_WRITE for application_id in project_application_ids}
        else:
            for application_id in project_application_ids:
                effective_access_by_application.setdefault(application_id, ACCESS_NO_ACCESS)

        for application_id, access_level in effective_access_by_application.items():
            app_membership = ApplicationMembership.query.filter_by(
                user_id=user_id,
                application_id=application_id
            ).first()
            if app_membership:
                app_membership.access_level = access_level
            else:
                app_membership = ApplicationMembership(
                    user_id=user_id,
                    application_id=application_id,
                    access_level=access_level
                )
                db.session.add(app_membership)
            updated.append(app_membership)

    db.session.commit()
    return jsonify({
        'message': 'Application access updated successfully.',
        'memberships': [serialize_application_membership(membership) for membership in updated]
    })

### Additional routes
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password) and user.is_active:
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    elif user and user.check_password(password) and not user.is_active:
        return jsonify({"error": "This account is disabled"}), 403
    elif username in users and users[username] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/about')
@login_required
def about_page():
    user = get_current_user()
    return render_template('index.html', initial_page='about', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/content/about')
@login_required
def about_content():
    return render_template('about.html')

@app.route('/guide')
@login_required
def guide_page():
    user = get_current_user()
    return render_template('index.html', initial_page='guide', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))

@app.route('/content/guide')
@login_required
def guide_content():
    return render_template('guide.html')

if __name__ == '__main__':
    test_database_connection()
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8000)
