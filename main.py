import os
import json
import base64
import csv
import hashlib
import hmac
import io
import math
import secrets
from dotenv import load_dotenv
from datetime import datetime, timezone
from functools import wraps
import logging
import re  # for URL validation
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, func, inspect, or_, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / '.env'

# JWT and session configuration
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY") or secrets.token_urlsafe(48)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(48)
app.config['SESSION_TYPE'] = os.environ.get("SESSION_TYPE", 'filesystem')
Session(app)

# Database configuration
DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite").lower()  # By default, uses SQLite
DB_NAME = os.environ.get("DB", "verdb")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "postgres")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_SSLMODE = os.environ.get("DB_SSLMODE", "")

# Construct SQLAlchemy URI
if DB_ENGINE == "sqlite":
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}.db"
else:
    ssl_query = f"?sslmode={DB_SSLMODE}" if DB_SSLMODE else ""
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}{ssl_query}"

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
DEPLOYMENT_TYPES = (
    'production',
    'development',
    'staging',
    'testing',
    'qa',
    'preview',
    'other',
)
DEFAULT_TIMEZONE = 'UTC'
DEFAULT_DATETIME_FORMAT = 'iso_24'
DEFAULT_RELEASE_NOTES = 'No release notes available.'
VERSIONING_SEMVER = 'semver'
VERSIONING_SEMVER_PRERELEASE = 'semver_prerelease'
VERSIONING_SEMVER_BUILD = 'semver_build'
VERSIONING_SEMVER_PRERELEASE_BUILD = 'semver_pre_build'
VERSIONING_TYPES = (
    VERSIONING_SEMVER,
    VERSIONING_SEMVER_PRERELEASE,
    VERSIONING_SEMVER_BUILD,
    VERSIONING_SEMVER_PRERELEASE_BUILD,
)
VERSIONING_INITIAL_DEFAULTS = {
    VERSIONING_SEMVER: '0.0.0',
    VERSIONING_SEMVER_PRERELEASE: '0.0.0',
    VERSIONING_SEMVER_BUILD: '0.0.0.0',
    VERSIONING_SEMVER_PRERELEASE_BUILD: '0.0.0.0',
}
DATETIME_FORMAT_OPTIONS = {
    'iso_24': {
        'label': '2026-04-28 14:30',
        'datetime': '%Y-%m-%d %H:%M',
        'date': '%Y-%m-%d',
    },
    'us_12': {
        'label': 'Apr 28, 2026 2:30 PM',
        'datetime': '%b %d, %Y %-I:%M %p',
        'date': '%b %d, %Y',
    },
    'us_numeric_12': {
        'label': '04/28/2026 2:30 PM',
        'datetime': '%m/%d/%Y %-I:%M %p',
        'date': '%m/%d/%Y',
    },
    'eu_24': {
        'label': '28 Apr 2026 14:30',
        'datetime': '%d %b %Y %H:%M',
        'date': '%d %b %Y',
    },
    'eu_numeric_24': {
        'label': '28/04/2026 14:30',
        'datetime': '%d/%m/%Y %H:%M',
        'date': '%d/%m/%Y',
    },
    'weekday_24': {
        'label': 'Tue, Apr 28, 2026 14:30',
        'datetime': '%a, %b %d, %Y %H:%M',
        'date': '%a, %b %d, %Y',
    },
}
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


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


_USER_SCHEMA_READY = False
_REPOSITORY_BRANCH_SCHEMA_READY = False
_PROJECT_SCHEMA_READY = False
_DATABASE_SCHEMA_READY_URI = None
BACKUP_FORMAT = 'vermicelli-backup'
BACKUP_VERSION = 1
ENCRYPTED_BACKUP_FORMAT = 'vermicelli-encrypted-backup'
BACKUP_ENCRYPTION_ALGORITHM = 'pbkdf2-hmac-sha256+hmac-sha256-stream'
BACKUP_KDF_ITERATIONS = 200000
SETUP_ENV_KEYS = (
    'SECRET_KEY',
    'JWT_SECRET_KEY',
    'SESSION_TYPE',
    'USERS',
    'DB_ENGINE',
    'DB',
    'DB_USER',
    'DB_PASSWORD',
    'DB_HOST',
    'DB_PORT',
    'DB_SSLMODE',
    'POSTGRES_DB',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD',
)
SETUP_PLACEHOLDER_SECRETS = {'', 'change_me', 'change_me_too', 'test'}


def normalize_datetime_format(format_key):
    return format_key if format_key in DATETIME_FORMAT_OPTIONS else DEFAULT_DATETIME_FORMAT


def get_datetime_format_options():
    return [
        {
            'value': value,
            'label': config['label'],
        }
        for value, config in DATETIME_FORMAT_OPTIONS.items()
    ]


def is_valid_datetime_format(format_key):
    return format_key in DATETIME_FORMAT_OPTIONS


def get_user_datetime_format(user=None):
    user = user or get_current_user()
    return normalize_datetime_format(
        getattr(user, 'datetime_format', DEFAULT_DATETIME_FORMAT)
        if user and getattr(user, 'datetime_format', None)
        else DEFAULT_DATETIME_FORMAT
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


def format_datetime_for_user(value, user=None, fmt=None):
    local_value = to_user_datetime(value, user)
    if not local_value:
        return 'N/A'
    format_key = get_user_datetime_format(user)
    return local_value.strftime(fmt or DATETIME_FORMAT_OPTIONS[format_key]['datetime'])


def format_date_for_user(value, user=None):
    format_key = get_user_datetime_format(user)
    return format_datetime_for_user(value, user, DATETIME_FORMAT_OPTIONS[format_key]['date'])


def ensure_user_schema():
    """Adds lightweight preference columns for existing local databases."""
    global _USER_SCHEMA_READY
    if _USER_SCHEMA_READY:
        return
    try:
        inspector = inspect(db.engine)
        if 'users' not in inspector.get_table_names():
            return
        existing_columns = {column['name'] for column in inspector.get_columns('users')}
        if 'datetime_format' not in existing_columns:
            db.session.execute(text(
                f"ALTER TABLE users ADD COLUMN datetime_format VARCHAR(32) NOT NULL DEFAULT '{DEFAULT_DATETIME_FORMAT}'"
            ))
            db.session.commit()
        _USER_SCHEMA_READY = True
    except Exception as error:
        db.session.rollback()
        logging.warning("Could not verify user preference schema: %s", error)


def ensure_repository_branch_schema():
    """Adds cached repository metadata columns for existing databases."""
    global _REPOSITORY_BRANCH_SCHEMA_READY
    if _REPOSITORY_BRANCH_SCHEMA_READY:
        return
    try:
        inspector = inspect(db.engine)
        if 'application_repository_branches' not in inspector.get_table_names():
            return
        existing_columns = {column['name'] for column in inspector.get_columns('application_repository_branches')}
        datetime_column_type = 'TIMESTAMP' if db.engine.dialect.name == 'postgresql' else 'DATETIME'
        column_definitions = {
            'branch_url': 'VARCHAR(512)',
            'commit_note': 'TEXT',
            'last_commit_at': datetime_column_type,
            'branch_status': "VARCHAR(50) NOT NULL DEFAULT 'active'",
            'build_status': "VARCHAR(50) NOT NULL DEFAULT 'unknown'",
        }
        for column_name, column_definition in column_definitions.items():
            if column_name not in existing_columns:
                db.session.execute(text(
                    f"ALTER TABLE application_repository_branches ADD COLUMN {column_name} {column_definition}"
                ))
        db.session.commit()
        _REPOSITORY_BRANCH_SCHEMA_READY = True
    except Exception as error:
        db.session.rollback()
        logging.warning("Could not verify repository metadata schema: %s", error)


def ensure_project_schema():
    """Adds project metadata columns for existing local databases."""
    global _PROJECT_SCHEMA_READY
    if _PROJECT_SCHEMA_READY:
        return
    try:
        inspector = inspect(db.engine)
        if 'project' not in inspector.get_table_names():
            return
        existing_columns = {column['name'] for column in inspector.get_columns('project')}
        datetime_column_type = 'TIMESTAMP' if db.engine.dialect.name == 'postgresql' else 'DATETIME'
        if 'updated_at' not in existing_columns:
            db.session.execute(text(
                f"ALTER TABLE project ADD COLUMN updated_at {datetime_column_type}"
            ))
            db.session.execute(text(
                "UPDATE project SET updated_at = COALESCE(created_at, start_date)"
            ))
            db.session.commit()
        _PROJECT_SCHEMA_READY = True
    except Exception as error:
        db.session.rollback()
        logging.warning("Could not verify project metadata schema: %s", error)


def ensure_database_schema():
    """Creates missing tables once for the active database URI."""
    global _DATABASE_SCHEMA_READY_URI
    current_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
    if _DATABASE_SCHEMA_READY_URI == current_uri:
        return
    try:
        db.create_all()
        _DATABASE_SCHEMA_READY_URI = current_uri
    except Exception as error:
        db.session.rollback()
        logging.warning("Could not create database schema: %s", error)


@app.before_request
def ensure_runtime_schema():
    ensure_database_schema()
    ensure_user_schema()
    ensure_repository_branch_schema()
    ensure_project_schema()


def json_error(message, status_code=403):
    return jsonify({'error': message}), status_code


ERROR_PAGE_MESSAGES = {
    400: {
        'title': 'Bad Request',
        'eyebrow': 'Request issue',
        'message': 'The request could not be processed. Check the details and try again.',
    },
    401: {
        'title': 'Sign In Required',
        'eyebrow': 'Authentication needed',
        'message': 'Please sign in before opening this page.',
    },
    403: {
        'title': 'Access Denied',
        'eyebrow': 'Permission needed',
        'message': 'Your account does not have permission to access this area.',
    },
    404: {
        'title': 'Page Not Found',
        'eyebrow': 'Missing page',
        'message': 'The page you are looking for does not exist or may have moved.',
    },
    405: {
        'title': 'Method Not Allowed',
        'eyebrow': 'Unsupported action',
        'message': 'This page does not support the action used by your browser.',
    },
    500: {
        'title': 'Server Error',
        'eyebrow': 'Something went wrong',
        'message': 'The server hit an unexpected problem. Try again in a moment.',
    },
}


def request_wants_json():
    if request.path.startswith('/api/'):
        return True
    if request.is_json:
        return True
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def current_user_for_error_page():
    try:
        return get_current_user()
    except Exception:
        return None


def registration_open_for_error_page():
    try:
        return admin_count() == 0
    except Exception:
        return False


def error_page_response(status_code, description=None, title=None, eyebrow=None):
    defaults = ERROR_PAGE_MESSAGES.get(status_code, {
        'title': 'Request Error',
        'eyebrow': 'Unexpected response',
        'message': 'The request could not be completed.',
    })
    message = description or defaults['message']
    if request_wants_json():
        return json_error(message, status_code)

    current = current_user_for_error_page()
    registration_open = registration_open_for_error_page()
    primary_url = url_for('index') if current else url_for('login')
    primary_label = 'Dashboard' if current else 'Sign In'
    if not current and registration_open:
        primary_url = url_for('register')
        primary_label = 'Set Up Vermicelli'

    return render_template(
        'error.html',
        status_code=status_code,
        title=title or defaults['title'],
        eyebrow=eyebrow or defaults['eyebrow'],
        message=message,
        primary_url=primary_url,
        primary_label=primary_label,
        secondary_url=url_for('logout') if current else None,
        secondary_label='Sign Out' if current else None,
        current_user=current,
    ), status_code


@app.errorhandler(400)
def handle_bad_request(error):
    return error_page_response(400, getattr(error, 'description', None))


@app.errorhandler(401)
def handle_unauthorized(error):
    return error_page_response(401, getattr(error, 'description', None))


@app.errorhandler(403)
def handle_forbidden(error):
    return error_page_response(403, getattr(error, 'description', None))


@app.errorhandler(404)
def handle_not_found(error):
    return error_page_response(404)


@app.errorhandler(405)
def handle_method_not_allowed(error):
    return error_page_response(405)


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return error_page_response(error.code or 500, error.description, title=error.name)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    db.session.rollback()
    logging.exception("Unhandled application error")
    return error_page_response(500)


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


def setup_is_available(require_empty_data=False):
    if admin_count() > 0:
        return False
    if require_empty_data and database_has_any_data():
        return False
    return True


def truthy_request_value(value):
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on', 'require', 'enabled'}


def setup_database_config_from_request(payload):
    engine = str(
        payload.get('setup_database_engine')
        or payload.get('db_engine')
        or payload.get('database_engine')
        or 'sqlite'
    ).strip().lower()

    if engine == 'sqlite':
        return {
            'DB_ENGINE': 'sqlite',
            'DB': str(payload.get('sqlite_database') or DB_NAME or 'verdb').strip() or 'verdb',
        }, None

    if engine not in {'postgres', 'postgresql'}:
        return None, 'Choose SQLite or PostgreSQL.'

    port = str(payload.get('postgres_port') or DB_PORT or '5432').strip() or '5432'
    try:
        int(port)
    except ValueError:
        return None, 'PostgreSQL port must be a number.'

    return {
        'DB_ENGINE': 'postgres',
        'DB_HOST': str(payload.get('postgres_host') or DB_HOST or 'localhost').strip() or 'localhost',
        'DB_PORT': port,
        'DB': str(payload.get('postgres_database') or DB_NAME or 'verdb').strip() or 'verdb',
        'DB_USER': str(payload.get('postgres_username') or DB_USER or 'postgres').strip() or 'postgres',
        'DB_PASSWORD': str(payload.get('postgres_password') or DB_PASSWORD or ''),
        'DB_SSLMODE': 'require' if truthy_request_value(payload.get('postgres_ssl')) else 'disable',
    }, None


def database_uri_from_setup_config(config):
    engine = config.get('DB_ENGINE', 'sqlite')
    if engine == 'sqlite':
        return f"sqlite:///{config.get('DB') or 'verdb'}.db"
    query = {}
    sslmode = config.get('DB_SSLMODE')
    if sslmode:
        query['sslmode'] = sslmode
    return str(URL.create(
        'postgresql',
        username=config.get('DB_USER') or 'postgres',
        password=config.get('DB_PASSWORD') or None,
        host=config.get('DB_HOST') or 'localhost',
        port=int(config.get('DB_PORT') or 5432),
        database=config.get('DB') or 'verdb',
        query=query,
    ))


def test_setup_database_connection(config):
    if config.get('DB_ENGINE') == 'sqlite':
        return True, None
    uri = database_uri_from_setup_config(config)
    engine = create_engine(uri, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        return True, None
    except Exception as error:
        return False, str(error)
    finally:
        engine.dispose()


def generated_setup_env_values(database_config):
    values = {
        'SECRET_KEY': secrets.token_urlsafe(48),
        'JWT_SECRET_KEY': secrets.token_urlsafe(48),
        'SESSION_TYPE': 'filesystem',
        'USERS': '',
    }
    values.update(database_config)
    if values.get('DB_ENGINE') == 'postgres':
        values.setdefault('POSTGRES_DB', values.get('DB', 'verdb'))
        values.setdefault('POSTGRES_USER', values.get('DB_USER', 'postgres'))
        values.setdefault('POSTGRES_PASSWORD', values.get('DB_PASSWORD', 'postgres'))
    return values


def env_value(value):
    value = '' if value is None else str(value)
    if re.fullmatch(r'[A-Za-z0-9_./:@+-]*', value):
        return value
    return json.dumps(value)


def write_setup_env(values):
    if app.config.get('TESTING') or app.config.get('DISABLE_SETUP_ENV_WRITE'):
        return

    existing_lines = ENV_PATH.read_text(encoding='utf-8').splitlines() if ENV_PATH.exists() else []
    remaining_values = dict(values)
    output_lines = []
    key_pattern = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=')

    for line in existing_lines:
        match = key_pattern.match(line)
        key = match.group(1) if match else None
        if key in remaining_values:
            output_lines.append(f'{key}={env_value(remaining_values.pop(key))}')
        else:
            output_lines.append(line)

    if remaining_values:
        if output_lines and output_lines[-1].strip():
            output_lines.append('')
        output_lines.append('# Generated by Vermicelli initial setup')
        for key in SETUP_ENV_KEYS:
            if key in remaining_values:
                output_lines.append(f'{key}={env_value(remaining_values.pop(key))}')
        for key, value in remaining_values.items():
            output_lines.append(f'{key}={env_value(value)}')

    ENV_PATH.write_text('\n'.join(output_lines).rstrip() + '\n', encoding='utf-8')


def apply_setup_runtime_config(values):
    app.secret_key = values.get('SECRET_KEY') or app.secret_key
    app.config['JWT_SECRET_KEY'] = values.get('JWT_SECRET_KEY') or app.config.get('JWT_SECRET_KEY')
    app.config['SESSION_TYPE'] = values.get('SESSION_TYPE') or app.config.get('SESSION_TYPE', 'filesystem')
    users.clear()

    if app.config.get('TESTING') and not app.config.get('ALLOW_SETUP_DATABASE_RECONFIGURE'):
        return

    database_config = {key: value for key, value in values.items() if key.startswith('DB_') or key == 'DB'}
    if not database_config:
        return

    global _USER_SCHEMA_READY, _REPOSITORY_BRANCH_SCHEMA_READY, _PROJECT_SCHEMA_READY, _DATABASE_SCHEMA_READY_URI
    database_uri = database_uri_from_setup_config(database_config)
    db.session.remove()
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config.setdefault('SQLALCHEMY_BINDS', {})
    app.config.setdefault('SQLALCHEMY_ENGINE_OPTIONS', {})

    engines = db._app_engines.setdefault(app, {})
    for engine in engines.values():
        engine.dispose()
    engines.clear()

    engine_options = db._engine_options.copy()
    engine_options.update(app.config['SQLALCHEMY_ENGINE_OPTIONS'])
    engine_options['url'] = database_uri
    echo = app.config.setdefault('SQLALCHEMY_ECHO', False)
    engine_options.setdefault('echo', echo)
    engine_options.setdefault('echo_pool', echo)
    db._make_metadata(None)
    db._apply_driver_defaults(engine_options, app)
    engines[None] = db._make_engine(None, engine_options, app)
    _USER_SCHEMA_READY = False
    _REPOSITORY_BRANCH_SCHEMA_READY = False
    _PROJECT_SCHEMA_READY = False
    _DATABASE_SCHEMA_READY_URI = None


def complete_initial_setup_config(database_config):
    values = generated_setup_env_values(database_config)
    apply_setup_runtime_config(values)
    write_setup_env(values)
    ensure_database_schema()
    ensure_user_schema()
    return values


def validate_backup_payload(payload):
    data, error = get_backup_data(payload)
    if error:
        return None, error
    error = validate_backup_data(data)
    if error:
        return None, error
    return data, None


def backup_validation_summary(data):
    return {
        'users': len(data.get('users', [])),
        'projects': len(data.get('projects', [])),
        'applications': len(data.get('applications', [])),
        'versions': len(data.get('versions', [])),
        'repository_branches': len(data.get('application_repository_branches', [])),
    }


def application_labels(label_value):
    return [
        label.strip()
        for label in re.split(r'[,;]', label_value or '')
        if label.strip()
    ]


def release_notes_from_payload(payload):
    payload = payload or {}
    git_payload = payload.get('git') if isinstance(payload.get('git'), dict) else {}
    for source in (payload, git_payload):
        for key in (
            'release_notes',
            'releasenotes',
            'releaseNotes',
            'git_release_notes',
            'notes',
            'changelog',
            'commit_message',
            'CI_COMMIT_MESSAGE',
            'GITHUB_EVENT_HEAD_COMMIT_MESSAGE',
            'GITEA_COMMIT_MESSAGE',
        ):
            value = source.get(key)
            if value:
                return str(value).strip()
    return DEFAULT_RELEASE_NOTES


def normalize_versioning_type(value):
    versioning_type = (value or VERSIONING_SEMVER).strip()
    return versioning_type if versioning_type in VERSIONING_TYPES else VERSIONING_SEMVER


def versioning_uses_prerelease(value):
    return normalize_versioning_type(value) in (
        VERSIONING_SEMVER_PRERELEASE,
        VERSIONING_SEMVER_PRERELEASE_BUILD,
    )


def versioning_uses_build(value):
    return normalize_versioning_type(value) in (
        VERSIONING_SEMVER_BUILD,
        VERSIONING_SEMVER_PRERELEASE_BUILD,
    )


def versioning_type_from_options(enable_prerelease=False, enable_build=False):
    if enable_prerelease and enable_build:
        return VERSIONING_SEMVER_PRERELEASE_BUILD
    if enable_prerelease:
        return VERSIONING_SEMVER_PRERELEASE
    if enable_build:
        return VERSIONING_SEMVER_BUILD
    return VERSIONING_SEMVER


def versioning_type_label(value):
    versioning_type = normalize_versioning_type(value)
    labels = {
        VERSIONING_SEMVER: 'Semantic Versioning (Major.Minor.Patch)',
        VERSIONING_SEMVER_PRERELEASE: 'Semantic Versioning + Pre-release Label',
        VERSIONING_SEMVER_BUILD: 'Semantic Versioning + Build Number',
        VERSIONING_SEMVER_PRERELEASE_BUILD: 'Semantic Versioning + Pre-release Label + Build Number',
    }
    return labels[versioning_type]


def versioning_type_short_label(value):
    versioning_type = normalize_versioning_type(value)
    labels = {
        VERSIONING_SEMVER: 'SemVer',
        VERSIONING_SEMVER_PRERELEASE: 'SemVer + Pre-release',
        VERSIONING_SEMVER_BUILD: 'SemVer Build',
        VERSIONING_SEMVER_PRERELEASE_BUILD: 'SemVer Pre-release Build',
    }
    return labels[versioning_type]


def prerelease_identifier_from_version(version_number):
    if not version_number or '-' not in version_number:
        return ''
    return version_number.split('-', 1)[1]


def validate_prerelease_identifier(identifier):
    value = (identifier or '').strip()
    if not value:
        return value, None
    if not re.match(r'^[A-Za-z][A-Za-z0-9]*$', value):
        return None, 'Pre-release Label must start with a letter and contain only letters and numbers.'
    return value, None


def validate_initial_version(versioning_type, version_number):
    value = (version_number or VERSIONING_INITIAL_DEFAULTS[versioning_type]).strip()
    if versioning_type == VERSIONING_SEMVER:
        pattern = r'^\d+\.\d+\.\d+$'
        message = 'Initial version must use Major.Minor.Patch, for example 0.0.0.'
    elif versioning_type == VERSIONING_SEMVER_PRERELEASE:
        pattern = r'^\d+\.\d+\.\d+(?:-[A-Za-z][A-Za-z0-9]*)?$'
        message = 'Initial version must use Major.Minor.Patch or Major.Minor.Patch-id, for example 0.0.0 or 4.1.2-rc1.'
    elif versioning_type == VERSIONING_SEMVER_BUILD:
        pattern = r'^\d+\.\d+\.\d+\.\d+$'
        message = 'Initial version must use Major.Minor.Patch.Build, for example 0.0.0.0.'
    else:
        pattern = r'^\d+\.\d+\.\d+\.\d+(?:-[A-Za-z][A-Za-z0-9]*)?$'
        message = 'Initial version must use Major.Minor.Patch.Build or Major.Minor.Patch.Build-id, for example 0.0.0.0 or 3.2.1.45-rc1.'
    if not re.match(pattern, value):
        return None, message
    return value, None


def split_semver_prerelease(version_number):
    core, _, prerelease = version_number.partition('-')
    return core, prerelease


def parse_version_number(version_number):
    core, prerelease = split_semver_prerelease(version_number or '')
    parts = core.split('.')
    if len(parts) not in (3, 4):
        raise ValueError('Latest version is not a supported semantic version.')
    try:
        major, minor, patch = [int(part) for part in parts[:3]]
        build = int(parts[3]) if len(parts) == 4 else None
    except ValueError as exc:
        raise ValueError('Latest version contains a non-numeric version segment.') from exc
    return major, minor, patch, build, prerelease


def format_version_number(major, minor, patch, build, prerelease, versioning_type):
    if versioning_uses_build(versioning_type):
        build_value = 0 if build is None else int(build)
        version_number = f"{major}.{minor}.{patch}.{build_value}"
    else:
        version_number = f"{major}.{minor}.{patch}"
    if versioning_uses_prerelease(versioning_type) and prerelease:
        version_number = f"{version_number}-{prerelease}"
    return version_number


def version_build_number(version_number):
    try:
        _, _, _, build, _ = parse_version_number(version_number)
        return build
    except ValueError:
        return None


def normalize_initial_version_for_options(versioning_type, initial_version, prerelease_identifier=None):
    initial_version_number, version_error = validate_initial_version(versioning_type, initial_version)
    if version_error:
        return None, version_error
    prerelease_value, prerelease_error = validate_prerelease_identifier(prerelease_identifier)
    if prerelease_error:
        return None, prerelease_error
    if versioning_uses_prerelease(versioning_type) and prerelease_value and '-' not in initial_version_number:
        initial_version_number = f"{initial_version_number}-{prerelease_value}"
    if versioning_uses_prerelease(versioning_type) and not prerelease_identifier_from_version(initial_version_number):
        return None, 'Pre-release Label is required when Pre-release Label is enabled.'
    return initial_version_number, None


def increment_version_number(latest_number, versioning_type, version_part, prerelease=None):
    major, minor, patch, build, existing_prerelease = parse_version_number(latest_number)
    if version_part == 'major':
        major += 1
        minor = 0
        patch = 0
    elif version_part == 'minor':
        minor += 1
        patch = 0
    elif version_part == 'patch':
        patch += 1

    if versioning_uses_build(versioning_type):
        build = (build or 0) + 1

    prerelease_value = ''
    if versioning_uses_prerelease(versioning_type):
        prerelease_value = (prerelease or existing_prerelease or '').strip()
        if prerelease_value:
            prerelease_value, prerelease_error = validate_prerelease_identifier(prerelease_value)
            if prerelease_error:
                raise ValueError(prerelease_error)
        if not prerelease_value:
            raise ValueError('Pre-release Label is required for this application versioning mode.')
    return format_version_number(major, minor, patch, build, prerelease_value, versioning_type)


def serialize_version(version, current_user):
    versioning_type = normalize_versioning_type(version.version_type)
    return {
        'number': version.number,
        'change_date': format_datetime_for_user(version.change_date, current_user),
        'notes': version.notes or '',
        'version_type': versioning_type,
        'version_type_label': versioning_type_label(versioning_type),
        'version_type_short_label': versioning_type_short_label(versioning_type),
        'prerelease_identifier': prerelease_identifier_from_version(version.number),
        'uses_prerelease': versioning_uses_prerelease(versioning_type),
        'uses_build': versioning_uses_build(versioning_type),
        'build_number': version_build_number(version.number),
    }


def application_version_context(app_id, current_user):
    latest_version = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).first()
    initial_version = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.asc(), Version.id.asc()).first()
    version_count = Version.query.filter_by(application_id=app_id).count()
    versioning_type = normalize_versioning_type(latest_version.version_type if latest_version else None)
    return {
        'latest_version': latest_version,
        'latest_version_display': format_datetime_for_user(latest_version.change_date, current_user) if latest_version else None,
        'latest_version_notes': latest_version.notes if latest_version and latest_version.notes else '',
        'latest_version_type': versioning_type,
        'latest_version_type_label': versioning_type_label(versioning_type),
        'latest_version_type_short_label': versioning_type_short_label(versioning_type),
        'latest_prerelease_identifier': prerelease_identifier_from_version(latest_version.number if latest_version else ''),
        'latest_uses_prerelease': versioning_uses_prerelease(versioning_type),
        'latest_uses_build': versioning_uses_build(versioning_type),
        'latest_build_number': version_build_number(latest_version.number if latest_version else ''),
        'initial_version_number': initial_version.number if initial_version else VERSIONING_INITIAL_DEFAULTS[versioning_type],
        'version_count': version_count,
    }


def commit_title(commit_note):
    title = str(commit_note or '').splitlines()[0].strip()
    if len(title) > 30:
        return title[:30].rstrip() + '...'
    return title

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Public bootstrap registration for the first admin only."""
    registration_open = admin_count() == 0
    if request.method == 'GET':
        return render_template('register.html', registration_open=registration_open)

    if not registration_open:
        return json_error('Public admin registration is closed.', 403)

    def setup_form_error(message):
        if request.headers.get('X-Setup-Wizard') == 'true':
            return json_error(message, 400)
        flash(message)
        return render_template('register.html', registration_open=True), 400

    username = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    password_confirmation = request.form.get('password_confirmation', '')
    database_config, database_error = setup_database_config_from_request(request.form)

    if not username or not password:
        return setup_form_error('Username and password are required.')
    if password != password_confirmation:
        return setup_form_error('Password confirmation does not match.')
    if database_error:
        return setup_form_error(database_error)
    if database_config.get('DB_ENGINE') == 'postgres':
        ok, error = test_setup_database_connection(database_config)
        if not ok:
            return setup_form_error(f'Could not connect to PostgreSQL: {error}')

    try:
        complete_initial_setup_config(database_config)
    except Exception as error:
        logging.exception("Initial setup failed")
        return setup_form_error(f'Initial setup failed: {error}')

    if database_has_any_data():
        return setup_form_error('The selected database already contains data. Restore or setup can only run on an empty database.')
    if User.query.filter(func.lower(User.username) == username.lower()).first():
        return setup_form_error('Username already exists.')

    first_user = User(
        username=username,
        full_name=full_name,
        email=email,
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
    flash('You are all set up.')
    if request.headers.get('X-Setup-Wizard') == 'true':
        return jsonify({'message': 'You are all set up.', 'redirect_url': url_for('index')})
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
    datetime_format = db.Column(db.String(32), nullable=False, default=DEFAULT_DATETIME_FORMAT)
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
    repository_branches = db.relationship('ApplicationRepositoryBranch', back_populates='application', cascade='all, delete-orphan')
    deployments = db.relationship('ApplicationDeployment', back_populates='application', cascade='all, delete-orphan')


class ApplicationRepositoryBranch(db.Model):
    """Cached repository branch metadata for an application link."""
    __tablename__ = 'application_repository_branches'
    __table_args__ = (
        db.UniqueConstraint('application_id', 'branch_name', name='uq_application_repository_branch'),
    )

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id', ondelete='CASCADE'), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    branch_name = db.Column(db.String(255), nullable=False)
    branch_url = db.Column(db.String(512))
    commit_sha = db.Column(db.String(128))
    commit_note = db.Column(db.Text)
    last_commit_at = db.Column(db.DateTime)
    branch_status = db.Column(db.String(50), nullable=False, default='active')
    build_status = db.Column(db.String(50), nullable=False, default='unknown')
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    last_checked_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    application = db.relationship('Application', back_populates='repository_branches')

class ApplicationDeployment(db.Model):
    """Configured deployment endpoint checks for an application."""
    __tablename__ = 'application_deployments'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    deployment_type = db.Column(db.String(50), nullable=False, default='production')
    base_url = db.Column(db.String(512), nullable=False)
    base_status_code = db.Column(db.Integer)
    base_response = db.Column(db.Text)
    version_status_code = db.Column(db.Integer)
    version_response = db.Column(db.Text)
    health_status_code = db.Column(db.Integer)
    health_response = db.Column(db.Text)
    health_status = db.Column(db.String(50), nullable=False, default='unknown')
    last_checked_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    application = db.relationship('Application', back_populates='deployments')

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
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    applications = db.relationship('Application', secondary=project_applications, back_populates='projects')
    memberships = db.relationship('ProjectMembership', back_populates='project', cascade='all, delete-orphan')


class ChangeLog(db.Model):
    """System-wide audit log for user-visible data changes."""
    __tablename__ = 'change_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    entity_type = db.Column(db.String(80), nullable=False, index=True)
    entity_id = db.Column(db.Integer)
    entity_name = db.Column(db.String(255))
    details = db.Column(db.Text)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    actor_username = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    actor = db.relationship('User')


def log_change(action, entity_type, entity_id=None, entity_name='', details='', actor=None):
    actor = actor if actor is not None else get_current_user()
    db.session.add(ChangeLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=str(entity_name or '')[:255],
        details=str(details or ''),
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else 'system',
    ))


def serialize_change_log(entry, display_user=None):
    return {
        'id': entry.id,
        'action': entry.action,
        'entity_type': entry.entity_type,
        'entity_id': entry.entity_id,
        'entity_name': entry.entity_name or '',
        'details': entry.details or '',
        'actor_username': entry.actor_username or 'system',
        'created_at': entry.created_at.isoformat() if entry.created_at else None,
        'created_at_display': format_datetime_for_user(entry.created_at, display_user) if entry.created_at else 'N/A',
    }


def touch_project(project):
    if project is not None:
        project.updated_at = datetime.utcnow()


def touch_projects(projects):
    for project in projects or []:
        touch_project(project)

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


def normalized_repository_path(path):
    path = unquote(path or '').strip('/')
    if path.endswith('.git'):
        path = path[:-4]
    return path


def repository_headers(provider):
    headers = {
        'Accept': 'application/json',
        'User-Agent': 'Vermicelli repository metadata sync',
    }
    if provider == 'github' and os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    elif provider == 'gitlab' and os.environ.get('GITLAB_TOKEN'):
        headers['PRIVATE-TOKEN'] = os.environ['GITLAB_TOKEN']
    elif provider == 'gitea' and os.environ.get('GITEA_TOKEN'):
        headers['Authorization'] = f"token {os.environ['GITEA_TOKEN']}"
    return headers


def fetch_repository_json(url, provider):
    request_obj = Request(url, headers=repository_headers(provider))
    with urlopen(request_obj, timeout=8) as response:
        return json.loads(response.read().decode('utf-8'))


def parse_repository_datetime(value):
    if not value:
        return None
    try:
        normalized_value = str(value)
        if normalized_value.endswith('Z'):
            normalized_value = normalized_value[:-1] + '+00:00'
        parsed_value = datetime.fromisoformat(normalized_value)
        if parsed_value.tzinfo is not None:
            parsed_value = parsed_value.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed_value
    except ValueError:
        return None


def repository_branch_status(branch, default_branch):
    if branch.get('default') or (branch.get('name') and branch.get('name') == default_branch):
        return 'default'
    if branch.get('protected'):
        return 'protected'
    return 'active'


def repository_build_status_label(build_status):
    labels = {
        'success': 'Passing',
        'failure': 'Failing',
        'error': 'Error',
        'pending': 'Pending',
        'unknown': 'Unknown',
    }
    return labels.get(build_status or 'unknown', str(build_status).replace('_', ' ').title())


def github_commit_build_status(api_base, commit_sha):
    if not commit_sha:
        return 'unknown'
    try:
        status_data = fetch_repository_json(f'{api_base}/commits/{quote(commit_sha, safe="")}/status', 'github')
        return status_data.get('state') or 'unknown'
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return 'unknown'


def repository_branch_url(parsed_url, provider, path, branch_name):
    encoded_branch = quote(branch_name, safe='')
    if provider == 'github':
        return f'{parsed_url.scheme}://{parsed_url.netloc}/{path}/tree/{encoded_branch}'
    if provider == 'gitlab':
        return f'{parsed_url.scheme}://{parsed_url.netloc}/{path}/-/tree/{encoded_branch}'
    return f'{parsed_url.scheme}://{parsed_url.netloc}/{path}/src/branch/{encoded_branch}'


def github_repository_branches(parsed_url, path, checked_at):
    parts = path.split('/')
    if len(parts) < 2:
        return []
    owner, repo = parts[0], parts[1]
    api_base = f'https://api.github.com/repos/{quote(owner)}/{quote(repo)}'
    repo_data = fetch_repository_json(api_base, 'github')
    default_branch = repo_data.get('default_branch')
    branches = fetch_repository_json(f'{api_base}/branches?per_page=100', 'github')
    results = []
    for branch in branches:
        branch_name = branch.get('name')
        if not branch_name:
            continue
        commit_sha = (branch.get('commit') or {}).get('sha') or ''
        commit_data = fetch_repository_json(f'{api_base}/commits/{quote(commit_sha, safe="")}', 'github') if commit_sha else {}
        commit_details = commit_data.get('commit') or {}
        committer = commit_details.get('committer') or {}
        author = commit_details.get('author') or {}
        results.append({
            'provider': 'github',
            'branch_name': branch_name,
            'branch_url': repository_branch_url(parsed_url, 'github', path, branch_name),
            'commit_sha': commit_sha,
            'commit_note': commit_details.get('message') or '',
            'last_commit_at': parse_repository_datetime(committer.get('date') or author.get('date')),
            'branch_status': repository_branch_status(branch, default_branch),
            'build_status': github_commit_build_status(api_base, commit_sha),
            'is_default': branch_name == default_branch,
            'last_checked_at': checked_at,
        })
    return results


def gitlab_repository_branches(parsed_url, path, checked_at):
    api_base = f'{parsed_url.scheme}://{parsed_url.netloc}/api/v4'
    project_id = quote(path, safe='')
    branches = fetch_repository_json(f'{api_base}/projects/{project_id}/repository/branches?per_page=100', 'gitlab')
    results = []
    for branch in branches:
        branch_name = branch.get('name')
        if not branch_name:
            continue
        commit_data = branch.get('commit') or {}
        results.append({
            'provider': 'gitlab',
            'branch_name': branch_name,
            'branch_url': repository_branch_url(parsed_url, 'gitlab', path, branch_name),
            'commit_sha': commit_data.get('id') or '',
            'commit_note': commit_data.get('message') or commit_data.get('title') or '',
            'last_commit_at': parse_repository_datetime(commit_data.get('committed_date') or commit_data.get('authored_date')),
            'branch_status': repository_branch_status(branch, None),
            'build_status': 'unknown',
            'is_default': bool(branch.get('default')),
            'last_checked_at': checked_at,
        })
    return results


def gitea_repository_branches(parsed_url, path, checked_at):
    parts = path.split('/')
    if len(parts) < 2:
        return []
    owner, repo = parts[0], parts[1]
    api_base = f'{parsed_url.scheme}://{parsed_url.netloc}/api/v1/repos/{quote(owner)}/{quote(repo)}'
    repo_data = fetch_repository_json(api_base, 'gitea')
    default_branch = repo_data.get('default_branch')
    branches = fetch_repository_json(f'{api_base}/branches?limit=100', 'gitea')
    results = []
    for branch in branches:
        branch_name = branch.get('name')
        if not branch_name:
            continue
        commit_data = branch.get('commit') or {}
        commit_details = commit_data.get('commit') or commit_data
        committer = commit_details.get('committer') or {}
        author = commit_details.get('author') or {}
        results.append({
            'provider': 'gitea',
            'branch_name': branch_name,
            'branch_url': repository_branch_url(parsed_url, 'gitea', path, branch_name),
            'commit_sha': commit_data.get('id') or commit_data.get('sha') or '',
            'commit_note': commit_details.get('message') or '',
            'last_commit_at': parse_repository_datetime(
                commit_data.get('timestamp') or commit_details.get('created') or committer.get('date') or author.get('date')
            ),
            'branch_status': repository_branch_status(branch, default_branch),
            'build_status': 'unknown',
            'is_default': branch_name == default_branch,
            'last_checked_at': checked_at,
        })
    return results


def fetch_repository_branches(repository_url):
    parsed_url = urlparse(repository_url or '')
    path = normalized_repository_path(parsed_url.path)
    if not parsed_url.scheme or not parsed_url.netloc or not path:
        return []

    checked_at = utc_now()
    host = parsed_url.netloc.lower()
    if host == 'github.com':
        return github_repository_branches(parsed_url, path, checked_at)
    if 'gitlab' in host:
        return gitlab_repository_branches(parsed_url, path, checked_at)
    return gitea_repository_branches(parsed_url, path, checked_at)


def sync_application_repository_branches(app_obj):
    if not app_obj.link:
        if app_obj.id is not None:
            ApplicationRepositoryBranch.query.filter_by(application_id=app_obj.id).delete(synchronize_session='fetch')
            db.session.flush()
            db.session.expire(app_obj, ['repository_branches'])
        else:
            app_obj.repository_branches.clear()
        return True, None

    try:
        branches = fetch_repository_branches(app_obj.link)
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
        logging.warning("Could not fetch repository metadata for application %s: %s", app_obj.id, error)
        return False, str(error)

    if app_obj.id is not None:
        ApplicationRepositoryBranch.query.filter_by(application_id=app_obj.id).delete(synchronize_session='fetch')
        db.session.flush()
        db.session.expire(app_obj, ['repository_branches'])
    else:
        app_obj.repository_branches.clear()

    seen_branch_names = set()
    for branch in branches:
        branch_name = branch['branch_name']
        if branch_name in seen_branch_names:
            continue
        seen_branch_names.add(branch_name)
        app_obj.repository_branches.append(ApplicationRepositoryBranch(
            provider=branch['provider'],
            branch_name=branch_name,
            branch_url=branch.get('branch_url') or '',
            commit_sha=branch['commit_sha'],
            commit_note=branch.get('commit_note') or '',
            last_commit_at=branch.get('last_commit_at'),
            branch_status=branch['branch_status'],
            build_status=branch.get('build_status') or 'unknown',
            is_default=branch['is_default'],
            last_checked_at=branch['last_checked_at'],
        ))
    return True, None


def serialize_repository_branch(branch, user=None):
    return {
        'provider': branch.provider,
        'branch_name': branch.branch_name,
        'branch_url': branch.branch_url or '',
        'commit_sha': branch.commit_sha or '',
        'short_commit_sha': (branch.commit_sha or '')[:12],
        'commit_note': commit_title(branch.commit_note),
        'full_commit_note': branch.commit_note or '',
        'last_commit_at': branch.last_commit_at.isoformat() if branch.last_commit_at else None,
        'last_commit_display': format_datetime_for_user(branch.last_commit_at, user) if branch.last_commit_at else 'N/A',
        'branch_status': branch.branch_status or 'active',
        'build_status': branch.build_status or 'unknown',
        'build_status_label': repository_build_status_label(branch.build_status),
        'is_default': bool(branch.is_default),
        'last_checked_at': branch.last_checked_at.isoformat() if branch.last_checked_at else None,
        'last_checked_display': format_datetime_for_user(branch.last_checked_at, user) if branch.last_checked_at else 'N/A',
    }


def deployment_type_label(deployment_type):
    labels = {
        'production': 'Production',
        'development': 'Development',
        'staging': 'Staging',
        'testing': 'Testing',
        'qa': 'QA',
        'preview': 'Preview',
        'other': 'Other',
    }
    return labels.get(deployment_type, labels['other'])


def normalize_deployment_type(deployment_type):
    return deployment_type if deployment_type in DEPLOYMENT_TYPES else 'other'


def normalize_deployment_url(url):
    return (url or '').strip().rstrip('/')


def deployment_check_url(base_url, path=''):
    base = normalize_deployment_url(base_url)
    if not path:
        return base
    return f'{base}/{path.lstrip("/")}'


def truncate_deployment_response(value, limit=6000):
    value = value or ''
    if len(value) <= limit:
        return value
    return value[:limit] + '\n... response truncated ...'


def parse_deployment_json(value):
    try:
        return json.loads(value) if value else None
    except json.JSONDecodeError:
        return None


def deployment_health_status(status_code, response_text):
    parsed = parse_deployment_json(response_text)
    if isinstance(parsed, dict):
        status_value = str(parsed.get('status') or parsed.get('health') or '').lower()
        if status_value in ('ok', 'healthy', 'up', 'pass', 'passing'):
            return 'healthy'
        if status_value:
            return 'unhealthy'
    if status_code and 200 <= status_code < 300:
        return 'reachable'
    return 'unhealthy'


def deployment_type_from_version_response(response_text, current_type):
    parsed = parse_deployment_json(response_text)
    if isinstance(parsed, dict):
        candidate = (
            parsed.get('environment')
            or parsed.get('deployment_type')
            or parsed.get('deploymentType')
            or parsed.get('type')
        )
        normalized = normalize_deployment_type(str(candidate or '').strip().lower())
        if normalized != 'other':
            return normalized
    return current_type or 'other'


def fetch_deployment_endpoint(url):
    request_obj = Request(url, headers={'User-Agent': 'Vermicelli deployment check'})
    try:
        with urlopen(request_obj, timeout=8) as response:
            body = response.read(65536).decode('utf-8', errors='replace')
            return response.getcode(), truncate_deployment_response(body), None
    except HTTPError as error:
        body = error.read(65536).decode('utf-8', errors='replace')
        return error.code, truncate_deployment_response(body), None
    except (URLError, TimeoutError, ValueError) as error:
        return None, '', str(error)


def check_application_deployment(deployment):
    checked_at = utc_now()
    endpoints = {
        'base': deployment_check_url(deployment.base_url),
        'version': deployment_check_url(deployment.base_url, 'version'),
        'health': deployment_check_url(deployment.base_url, 'health'),
    }
    results = {}
    errors = []
    for key, url in endpoints.items():
        status_code, response_text, error = fetch_deployment_endpoint(url)
        results[key] = {
            'url': url,
            'status_code': status_code,
            'response': response_text,
            'error': error,
        }
        if error:
            errors.append(f'{key}: {error}')

    deployment.base_status_code = results['base']['status_code']
    deployment.base_response = results['base']['response'] or results['base']['error'] or ''
    deployment.version_status_code = results['version']['status_code']
    deployment.version_response = results['version']['response'] or results['version']['error'] or ''
    deployment.health_status_code = results['health']['status_code']
    deployment.health_response = results['health']['response'] or results['health']['error'] or ''
    deployment.health_status = deployment_health_status(deployment.health_status_code, deployment.health_response)
    deployment.deployment_type = deployment_type_from_version_response(
        deployment.version_response,
        deployment.deployment_type,
    )
    deployment.last_checked_at = checked_at
    return not errors, '; '.join(errors) if errors else None


def serialize_deployment_response(response_text):
    parsed = parse_deployment_json(response_text)
    return {
        'raw': response_text or '',
        'json': parsed if isinstance(parsed, (dict, list)) else None,
    }


def serialize_application_deployment(deployment, user=None):
    return {
        'id': deployment.id,
        'application_id': deployment.application_id,
        'name': deployment.name,
        'deployment_type': deployment.deployment_type,
        'deployment_type_label': deployment_type_label(deployment.deployment_type),
        'base_url': deployment.base_url,
        'base_check_url': deployment_check_url(deployment.base_url),
        'version_check_url': deployment_check_url(deployment.base_url, 'version'),
        'health_check_url': deployment_check_url(deployment.base_url, 'health'),
        'base_status_code': deployment.base_status_code,
        'version_status_code': deployment.version_status_code,
        'health_status_code': deployment.health_status_code,
        'health_status': deployment.health_status or 'unknown',
        'health_status_label': (deployment.health_status or 'unknown').replace('_', ' ').title(),
        'base_response': serialize_deployment_response(deployment.base_response),
        'version_response': serialize_deployment_response(deployment.version_response),
        'health_response': serialize_deployment_response(deployment.health_response),
        'last_checked_at': deployment.last_checked_at.isoformat() if deployment.last_checked_at else None,
        'last_checked_display': format_datetime_for_user(deployment.last_checked_at, user) if deployment.last_checked_at else 'Never checked',
    }


def backup_datetime(value):
    return value.isoformat() if value else None


def backup_b64encode(value):
    return base64.b64encode(value).decode('ascii')


def backup_b64decode(value):
    return base64.b64decode(str(value).encode('ascii'), validate=True)


def canonical_backup_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def derive_backup_keys(password, salt, iterations):
    key_material = hashlib.pbkdf2_hmac(
        'sha256',
        str(password).encode('utf-8'),
        salt,
        iterations,
        dklen=64
    )
    return key_material[:32], key_material[32:]


def hmac_stream_xor(data, key, nonce):
    output = bytearray()
    counter = 0
    for index in range(0, len(data), 32):
        counter_bytes = counter.to_bytes(8, 'big')
        block_key = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        block = data[index:index + 32]
        output.extend(byte ^ block_key[offset] for offset, byte in enumerate(block))
        counter += 1
    return bytes(output)


def encrypt_backup_payload(payload, password):
    if not password:
        return None, 'Backup encryption password is required.'

    salt = os.urandom(16)
    nonce = os.urandom(16)
    encryption_key, mac_key = derive_backup_keys(password, salt, BACKUP_KDF_ITERATIONS)
    ciphertext = hmac_stream_xor(canonical_backup_bytes(payload), encryption_key, nonce)
    encrypted_payload = {
        'format': ENCRYPTED_BACKUP_FORMAT,
        'version': BACKUP_VERSION,
        'algorithm': BACKUP_ENCRYPTION_ALGORITHM,
        'kdf': 'pbkdf2-hmac-sha256',
        'iterations': BACKUP_KDF_ITERATIONS,
        'salt': backup_b64encode(salt),
        'nonce': backup_b64encode(nonce),
        'ciphertext': backup_b64encode(ciphertext),
    }
    encrypted_payload['tag'] = backup_b64encode(
        hmac.new(mac_key, canonical_backup_bytes(encrypted_payload), hashlib.sha256).digest()
    )
    return encrypted_payload, None


def decrypt_backup_payload(encrypted_payload, password):
    if not password:
        return None, 'Backup encryption password is required.'
    if not isinstance(encrypted_payload, dict):
        return None, 'Backup file must contain a JSON object.'
    if encrypted_payload.get('format') != ENCRYPTED_BACKUP_FORMAT:
        return None, 'Backup file must be an encrypted Vermicelli backup.'
    if encrypted_payload.get('version') != BACKUP_VERSION:
        return None, 'This encrypted backup version is not supported.'
    if encrypted_payload.get('algorithm') != BACKUP_ENCRYPTION_ALGORITHM:
        return None, 'This encrypted backup algorithm is not supported.'
    if encrypted_payload.get('kdf') != 'pbkdf2-hmac-sha256':
        return None, 'This encrypted backup key derivation method is not supported.'

    try:
        iterations = int(encrypted_payload.get('iterations', 0))
        salt = backup_b64decode(encrypted_payload.get('salt', ''))
        nonce = backup_b64decode(encrypted_payload.get('nonce', ''))
        ciphertext = backup_b64decode(encrypted_payload.get('ciphertext', ''))
        supplied_tag = backup_b64decode(encrypted_payload.get('tag', ''))
    except (TypeError, ValueError):
        return None, 'Encrypted backup file is malformed.'

    if iterations <= 0 or not salt or not nonce or not ciphertext or not supplied_tag:
        return None, 'Encrypted backup file is malformed.'

    encryption_key, mac_key = derive_backup_keys(password, salt, iterations)
    authenticated_payload = {
        key: encrypted_payload[key]
        for key in ('format', 'version', 'algorithm', 'kdf', 'iterations', 'salt', 'nonce', 'ciphertext')
        if key in encrypted_payload
    }
    expected_tag = hmac.new(mac_key, canonical_backup_bytes(authenticated_payload), hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, supplied_tag):
        return None, 'Backup password is incorrect or the backup file is corrupted.'

    plaintext = hmac_stream_xor(ciphertext, encryption_key, nonce)
    try:
        return json.loads(plaintext.decode('utf-8')), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, 'Backup password is incorrect or the backup file is corrupted.'


def parse_backup_datetime(value):
    if not value:
        return None
    try:
        normalized_value = str(value)
        if normalized_value.endswith('Z'):
            normalized_value = normalized_value[:-1] + '+00:00'
        parsed = datetime.fromisoformat(normalized_value)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(ZoneInfo(DEFAULT_TIMEZONE)).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def database_has_any_data():
    model_counts = [
        User.query.count(),
        Project.query.count(),
        Application.query.count(),
        Version.query.count(),
        ApplicationRepositoryBranch.query.count(),
        ProjectMembership.query.count(),
        ApplicationMembership.query.count(),
    ]
    association_count = db.session.query(project_applications).count()
    return any(count > 0 for count in model_counts) or association_count > 0


def serialize_backup_payload():
    return {
        'format': BACKUP_FORMAT,
        'version': BACKUP_VERSION,
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'data': {
            'users': [
                {
                    'id': user.id,
                    'username': user.username,
                    'full_name': user.full_name or '',
                    'timezone': user.timezone or DEFAULT_TIMEZONE,
                    'datetime_format': normalize_datetime_format(getattr(user, 'datetime_format', DEFAULT_DATETIME_FORMAT)),
                    'email': user.email or '',
                    'is_active': bool(user.is_active),
                    'can_create_projects': bool(user.can_create_projects),
                    'last_login_at': backup_datetime(user.last_login_at),
                    'password_hash': user.password_hash,
                    'platform_role': user.platform_role,
                    'created_at': backup_datetime(user.created_at),
                    'updated_at': backup_datetime(user.updated_at),
                }
                for user in User.query.order_by(User.id).all()
            ],
            'projects': [
                {
                    'id': project.id,
                    'name': project.name,
                    'description': project.description or '',
                    'source_link': project.source_link or '',
                    'status': project.status,
                    'created_at': backup_datetime(project.created_at),
                    'updated_at': backup_datetime(project.updated_at),
                    'start_date': backup_datetime(project.start_date),
                }
                for project in Project.query.order_by(Project.id).all()
            ],
            'applications': [
                {
                    'id': app_obj.id,
                    'name': app_obj.name,
                    'created_at': backup_datetime(app_obj.created_at),
                    'updated_at': backup_datetime(app_obj.updated_at),
                    'link': app_obj.link or '',
                    'label': app_obj.label or '',
                }
                for app_obj in Application.query.order_by(Application.id).all()
            ],
            'versions': [
                {
                    'id': version.id,
                    'application_id': version.application_id,
                    'number': version.number,
                    'version_type': version.version_type or '',
                    'change_date': backup_datetime(version.change_date),
                    'notes': version.notes or '',
                }
                for version in Version.query.order_by(Version.id).all()
            ],
            'application_repository_branches': [
                {
                    'id': branch.id,
                    'application_id': branch.application_id,
                    'provider': branch.provider,
                    'branch_name': branch.branch_name,
                    'branch_url': branch.branch_url or '',
                    'commit_sha': branch.commit_sha or '',
                    'commit_note': branch.commit_note or '',
                    'last_commit_at': backup_datetime(branch.last_commit_at),
                    'branch_status': branch.branch_status or 'active',
                    'build_status': branch.build_status or 'unknown',
                    'is_default': bool(branch.is_default),
                    'last_checked_at': backup_datetime(branch.last_checked_at),
                }
                for branch in ApplicationRepositoryBranch.query.order_by(ApplicationRepositoryBranch.id).all()
            ],
            'application_deployments': [
                {
                    'id': deployment.id,
                    'application_id': deployment.application_id,
                    'name': deployment.name,
                    'deployment_type': deployment.deployment_type,
                    'base_url': deployment.base_url,
                    'base_status_code': deployment.base_status_code,
                    'base_response': deployment.base_response or '',
                    'version_status_code': deployment.version_status_code,
                    'version_response': deployment.version_response or '',
                    'health_status_code': deployment.health_status_code,
                    'health_response': deployment.health_response or '',
                    'health_status': deployment.health_status or 'unknown',
                    'last_checked_at': backup_datetime(deployment.last_checked_at),
                    'created_at': backup_datetime(deployment.created_at),
                    'updated_at': backup_datetime(deployment.updated_at),
                }
                for deployment in ApplicationDeployment.query.order_by(ApplicationDeployment.id).all()
            ],
            'project_applications': [
                {
                    'project_id': row.project_id,
                    'application_id': row.application_id,
                }
                for row in db.session.query(project_applications).order_by(
                    project_applications.c.project_id,
                    project_applications.c.application_id
                ).all()
            ],
            'project_memberships': [
                {
                    'id': membership.id,
                    'user_id': membership.user_id,
                    'project_id': membership.project_id,
                    'project_role': membership.project_role,
                    'access_level': membership.access_level,
                    'created_at': backup_datetime(membership.created_at),
                    'updated_at': backup_datetime(membership.updated_at),
                }
                for membership in ProjectMembership.query.order_by(ProjectMembership.id).all()
            ],
            'application_memberships': [
                {
                    'id': membership.id,
                    'user_id': membership.user_id,
                    'application_id': membership.application_id,
                    'access_level': membership.access_level,
                    'created_at': backup_datetime(membership.created_at),
                    'updated_at': backup_datetime(membership.updated_at),
                }
                for membership in ApplicationMembership.query.order_by(ApplicationMembership.id).all()
            ],
            'change_logs': [
                {
                    'id': entry.id,
                    'action': entry.action,
                    'entity_type': entry.entity_type,
                    'entity_id': entry.entity_id,
                    'entity_name': entry.entity_name or '',
                    'details': entry.details or '',
                    'actor_user_id': entry.actor_user_id,
                    'actor_username': entry.actor_username or 'system',
                    'created_at': backup_datetime(entry.created_at),
                }
                for entry in ChangeLog.query.order_by(ChangeLog.id).all()
            ],
        }
    }


def backup_payload_from_request():
    if 'backup' in request.files:
        raw_payload = request.files['backup'].read()
    elif request.is_json:
        payload = request.get_json(silent=True)
        return payload, None if payload is not None else 'Backup JSON is required.'
    else:
        raw_payload = request.get_data()

    if not raw_payload:
        return None, 'Backup file is required.'

    try:
        return json.loads(raw_payload.decode('utf-8')), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, 'Backup file must be valid JSON.'


def encrypted_backup_payload_from_request():
    if request.is_json:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict) and isinstance(payload.get('backup'), dict):
            return payload['backup'], None
        if isinstance(payload, dict) and payload.get('format') == ENCRYPTED_BACKUP_FORMAT:
            return payload, None
        return None, 'Encrypted backup JSON is required.'
    return backup_payload_from_request()


def backup_request_value(name):
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        return payload.get(name, '')
    return request.form.get(name, '')


def get_backup_data(payload):
    if not isinstance(payload, dict):
        return None, 'Backup file must contain a JSON object.'
    if payload.get('format') != BACKUP_FORMAT:
        return None, 'This is not a Vermicelli backup file.'
    if payload.get('version') != BACKUP_VERSION:
        return None, 'This backup version is not supported.'
    data = payload.get('data')
    if not isinstance(data, dict):
        return None, 'Backup data is missing.'
    expected_sections = (
        'users',
        'projects',
        'applications',
        'versions',
        'application_repository_branches',
        'application_deployments',
        'project_applications',
        'project_memberships',
        'application_memberships',
        'change_logs',
    )
    for section in expected_sections:
        if section not in data:
            data[section] = []
        if not isinstance(data[section], list):
            return None, f'Backup section {section} must be a list.'
    return data, None


def backup_section_ids(rows, section_name):
    ids = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), int):
            return None, f'Backup section {section_name} contains an invalid id.'
        ids.append(row['id'])
    if len(ids) != len(set(ids)):
        return None, f'Backup section {section_name} contains duplicate ids.'
    return set(ids), None


def validate_backup_data(data):
    user_ids, error = backup_section_ids(data['users'], 'users')
    if error:
        return error
    project_ids, error = backup_section_ids(data['projects'], 'projects')
    if error:
        return error
    application_ids, error = backup_section_ids(data['applications'], 'applications')
    if error:
        return error
    _, error = backup_section_ids(data['versions'], 'versions')
    if error:
        return error
    _, error = backup_section_ids(data['application_repository_branches'], 'application_repository_branches')
    if error:
        return error
    _, error = backup_section_ids(data['application_deployments'], 'application_deployments')
    if error:
        return error
    _, error = backup_section_ids(data['project_memberships'], 'project_memberships')
    if error:
        return error
    _, error = backup_section_ids(data['application_memberships'], 'application_memberships')
    if error:
        return error
    _, error = backup_section_ids(data['change_logs'], 'change_logs')
    if error:
        return error

    if not data['users']:
        return 'Backup must contain at least one admin user.'
    if not any(user.get('platform_role') == PLATFORM_ADMIN for user in data['users']):
        return 'Backup must contain at least one admin user.'
    for user in data['users']:
        if not user.get('username') or not user.get('password_hash'):
            return 'Backup contains an invalid user record.'
        if user.get('platform_role') not in PLATFORM_ROLES:
            return 'Backup contains an unsupported user role.'

    for version in data['versions']:
        if version.get('application_id') not in application_ids:
            return 'Backup contains a version for an unknown application.'
    for branch in data['application_repository_branches']:
        if branch.get('application_id') not in application_ids:
            return 'Backup contains repository metadata for an unknown application.'
    for deployment in data['application_deployments']:
        if deployment.get('application_id') not in application_ids:
            return 'Backup contains deployment checks for an unknown application.'
    for link in data['project_applications']:
        if link.get('project_id') not in project_ids or link.get('application_id') not in application_ids:
            return 'Backup contains an invalid project/application link.'
    for membership in data['project_memberships']:
        if membership.get('user_id') not in user_ids or membership.get('project_id') not in project_ids:
            return 'Backup contains an invalid project membership.'
    for membership in data['application_memberships']:
        if membership.get('user_id') not in user_ids or membership.get('application_id') not in application_ids:
            return 'Backup contains an invalid application membership.'

    return None


def clear_application_data():
    ChangeLog.query.delete(synchronize_session=False)
    db.session.execute(project_applications.delete())
    ApplicationMembership.query.delete(synchronize_session=False)
    ProjectMembership.query.delete(synchronize_session=False)
    ApplicationDeployment.query.delete(synchronize_session=False)
    ApplicationRepositoryBranch.query.delete(synchronize_session=False)
    Version.query.delete(synchronize_session=False)
    Application.query.delete(synchronize_session=False)
    Project.query.delete(synchronize_session=False)
    User.query.delete(synchronize_session=False)
    db.session.flush()
    db.session.expunge_all()


def reset_primary_key_sequences():
    if db.engine.dialect.name != 'postgresql':
        return
    for table_name in ('users', 'project', 'application', 'version', 'application_repository_branches', 'application_deployments', 'project_memberships', 'application_memberships', 'change_logs'):
        quoted_table_name = f'"{table_name}"'
        db.session.execute(text(
            f"SELECT setval(pg_get_serial_sequence('{quoted_table_name}', 'id'), "
            f"COALESCE((SELECT MAX(id) FROM {quoted_table_name}), 1), "
            f"(SELECT COUNT(*) FROM {quoted_table_name}) > 0)"
        ))


def import_backup_payload(payload):
    data, error = get_backup_data(payload)
    if error:
        return False, error

    error = validate_backup_data(data)
    if error:
        return False, error

    try:
        clear_application_data()

        for row in data['users']:
            db.session.add(User(
                id=row['id'],
                username=str(row.get('username', '')).strip(),
                full_name=row.get('full_name') or '',
                timezone=row.get('timezone') or DEFAULT_TIMEZONE,
                datetime_format=normalize_datetime_format(row.get('datetime_format') or DEFAULT_DATETIME_FORMAT),
                email=row.get('email') or '',
                is_active=bool(row.get('is_active', True)),
                can_create_projects=bool(row.get('can_create_projects', False)),
                last_login_at=parse_backup_datetime(row.get('last_login_at')),
                password_hash=row.get('password_hash'),
                platform_role=row.get('platform_role') if row.get('platform_role') in PLATFORM_ROLES else PLATFORM_USER,
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or datetime.utcnow(),
            ))

        for row in data['projects']:
            db.session.add(Project(
                id=row['id'],
                name=str(row.get('name', '')).strip(),
                description=row.get('description') or '',
                source_link=row.get('source_link') or '',
                status=row.get('status') or 'Draft',
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                start_date=parse_backup_datetime(row.get('start_date')) or datetime.utcnow(),
            ))

        for row in data['applications']:
            db.session.add(Application(
                id=row['id'],
                name=str(row.get('name', '')).strip(),
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or datetime.utcnow(),
                link=row.get('link') or '',
                label=row.get('label') or '',
            ))

        db.session.flush()

        if data['project_applications']:
            db.session.execute(project_applications.insert(), [
                {
                    'project_id': row['project_id'],
                    'application_id': row['application_id'],
                }
                for row in data['project_applications']
            ])

        for row in data['versions']:
            db.session.add(Version(
                id=row['id'],
                application_id=row['application_id'],
                number=row.get('number') or '0.0.0',
                version_type=row.get('version_type') or '',
                change_date=parse_backup_datetime(row.get('change_date')) or datetime.utcnow(),
                notes=row.get('notes') or '',
            ))

        for row in data['application_repository_branches']:
            db.session.add(ApplicationRepositoryBranch(
                id=row['id'],
                application_id=row['application_id'],
                provider=row.get('provider') or 'unknown',
                branch_name=row.get('branch_name') or '',
                branch_url=row.get('branch_url') or '',
                commit_sha=row.get('commit_sha') or '',
                commit_note=row.get('commit_note') or '',
                last_commit_at=parse_backup_datetime(row.get('last_commit_at')),
                branch_status=row.get('branch_status') or 'active',
                build_status=row.get('build_status') or 'unknown',
                is_default=bool(row.get('is_default', False)),
                last_checked_at=parse_backup_datetime(row.get('last_checked_at')) or datetime.utcnow(),
            ))

        for row in data['application_deployments']:
            db.session.add(ApplicationDeployment(
                id=row['id'],
                application_id=row['application_id'],
                name=row.get('name') or 'Deployment',
                deployment_type=normalize_deployment_type(row.get('deployment_type')),
                base_url=normalize_deployment_url(row.get('base_url')),
                base_status_code=row.get('base_status_code'),
                base_response=row.get('base_response') or '',
                version_status_code=row.get('version_status_code'),
                version_response=row.get('version_response') or '',
                health_status_code=row.get('health_status_code'),
                health_response=row.get('health_response') or '',
                health_status=row.get('health_status') or 'unknown',
                last_checked_at=parse_backup_datetime(row.get('last_checked_at')),
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or datetime.utcnow(),
            ))

        for row in data['project_memberships']:
            db.session.add(ProjectMembership(
                id=row['id'],
                user_id=row['user_id'],
                project_id=row['project_id'],
                project_role=row.get('project_role') if row.get('project_role') in PROJECT_ROLES else PROJECT_USER,
                access_level=row.get('access_level') if row.get('access_level') in PROJECT_ACCESS_LEVELS else ACCESS_VIEW_ONLY,
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or datetime.utcnow(),
            ))

        for row in data['application_memberships']:
            db.session.add(ApplicationMembership(
                id=row['id'],
                user_id=row['user_id'],
                application_id=row['application_id'],
                access_level=row.get('access_level') if row.get('access_level') in APPLICATION_ACCESS_LEVELS else ACCESS_VIEW_ONLY,
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
                updated_at=parse_backup_datetime(row.get('updated_at')) or datetime.utcnow(),
            ))

        for row in data['change_logs']:
            db.session.add(ChangeLog(
                id=row['id'],
                action=row.get('action') or 'changed',
                entity_type=row.get('entity_type') or 'system',
                entity_id=row.get('entity_id'),
                entity_name=row.get('entity_name') or '',
                details=row.get('details') or '',
                actor_user_id=row.get('actor_user_id') if row.get('actor_user_id') in {user['id'] for user in data['users']} else None,
                actor_username=row.get('actor_username') or 'system',
                created_at=parse_backup_datetime(row.get('created_at')) or datetime.utcnow(),
            ))

        db.session.flush()
        reset_primary_key_sequences()
        db.session.commit()
        return True, None
    except (IntegrityError, SQLAlchemyError) as error:
        db.session.rollback()
        logging.error("Backup import failed: %s", error)
        return False, 'Backup could not be imported because it conflicts with the database schema.'
    except Exception as error:
        db.session.rollback()
        logging.error("Backup import failed: %s", error)
        return False, 'Backup could not be imported.'


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
        return error_page_response(403, 'You do not have permission to access user management.')
    return render_template('index.html', initial_page='users', current_user=user, can_manage_access=True, can_manage_users=True)

@app.route('/settings')
@login_required
def settings_page():
    user = get_current_user()
    return render_template('index.html', initial_page='settings', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))


@app.route('/system-settings')
@login_required
def system_settings_page():
    user = get_current_user()
    if not has_platform_role(user, PLATFORM_ADMIN):
        return error_page_response(403, 'You do not have permission to access system settings.')
    return render_template('index.html', initial_page='system-settings', current_user=user, can_manage_access=can_manage_access_page(user), can_manage_users=can_manage_users_page(user))


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
    version_context = application_version_context(app_id, current)
    project_name = app_obj.projects[0].name if app_obj.projects else None
    project_id = app_obj.projects[0].id if app_obj.projects else None
    app_access_level = application_access_level_for_user(current, app_obj)

    return render_template(
        'application_details.html',
        app=app_obj,
        **version_context,
        app_labels=application_labels(app_obj.label),
        repository_branches=[
            serialize_repository_branch(branch, current)
            for branch in sorted(app_obj.repository_branches, key=lambda item: (not item.is_default, item.branch_name.lower()))
        ],
        deployments=[
            serialize_application_deployment(deployment, current)
            for deployment in sorted(app_obj.deployments, key=lambda item: (item.deployment_type, item.name.lower()))
        ],
        deployment_types=[
            {'value': deployment_type, 'label': deployment_type_label(deployment_type)}
            for deployment_type in DEPLOYMENT_TYPES
        ],
        project_name=project_name,
        project_id=project_id,
        created_at_display=format_datetime_for_user(app_obj.created_at, current) if app_obj.created_at else 'N/A',
        updated_at_display=format_datetime_for_user(app_obj.updated_at, current) if app_obj.updated_at else 'N/A',
        can_edit_application=can_write_application(current, app_obj),
        can_change_project=has_platform_role(current, PLATFORM_ADMIN),
        access_summary=serialize_application_access_summary(app_obj, current),
        access_level_label=access_label(app_access_level),
        script_username=current.username if current else 'USERNAME'
    )

@app.route('/application/<int:app_id>/details')
@login_required
def application_details_page(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return error_page_response(403, 'You do not have access to this application.')
    project_name = app_obj.projects[0].name if app_obj.projects else None
    project_id = app_obj.projects[0].id if app_obj.projects else None
    version_context = application_version_context(app_obj.id, current)
    app_access_level = application_access_level_for_user(current, app_obj)
    return render_template(
        'application_details.html',
        app=app_obj,
        project_name=project_name,
        project_id=project_id,
        **version_context,
        app_labels=application_labels(app_obj.label),
        repository_branches=[
            serialize_repository_branch(branch, current)
            for branch in sorted(app_obj.repository_branches, key=lambda item: (not item.is_default, item.branch_name.lower()))
        ],
        deployments=[
            serialize_application_deployment(deployment, current)
            for deployment in sorted(app_obj.deployments, key=lambda item: (item.deployment_type, item.name.lower()))
        ],
        deployment_types=[
            {'value': deployment_type, 'label': deployment_type_label(deployment_type)}
            for deployment_type in DEPLOYMENT_TYPES
        ],
        created_at_display=format_datetime_for_user(app_obj.created_at, current) if app_obj.created_at else 'N/A',
        updated_at_display=format_datetime_for_user(app_obj.updated_at, current) if app_obj.updated_at else 'N/A',
        can_edit_application=can_write_application(current, app_obj),
        can_change_project=has_platform_role(current, PLATFORM_ADMIN),
        access_summary=serialize_application_access_summary(app_obj, current),
        access_level_label=access_label(app_access_level),
        script_username=current.username if current else 'USERNAME'
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
        'repository_branches': [
            serialize_repository_branch(branch, current)
            for branch in sorted(app_obj.repository_branches, key=lambda item: (not item.is_default, item.branch_name.lower()))
        ],
        'deployments': [
            serialize_application_deployment(deployment, current)
            for deployment in sorted(app_obj.deployments, key=lambda item: (item.deployment_type, item.name.lower()))
        ],
        'project_id': project.id if project else None,
        'project_name': project.name if project else 'No project',
        'access_level': app_access_level,
        'access_label': access_label(app_access_level),
        'access_code': access_code(app_access_level),
        'can_edit': can_write_application(current, app_obj),
        'can_change_project': has_platform_role(current, PLATFORM_ADMIN)
    }
    return jsonify(app_data)


@app.route('/api/application/<int:app_id>/deployments', methods=['POST'])
@login_required
def create_application_deployment(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_write_application(current, app_obj):
        return json_error('You do not have permission to configure deployments.', 403)

    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    deployment_type = normalize_deployment_type(data.get('deployment_type'))
    base_url = normalize_deployment_url(data.get('base_url'))
    if not name:
        return json_error('Deployment name is required.', 400)
    if not base_url or not is_valid_url(base_url):
        return json_error('Deployment URL must start with http:// or https://.', 400)

    deployment = ApplicationDeployment(
        application_id=app_obj.id,
        name=name,
        deployment_type=deployment_type,
        base_url=base_url,
    )
    db.session.add(deployment)
    log_change('created', 'deployment', None, name, f'Configured deployment for application "{app_obj.name}".', current)
    db.session.commit()
    return jsonify({
        'message': 'Deployment configured.',
        'deployment': serialize_application_deployment(deployment, current),
    }), 201


@app.route('/api/application_deployments/<int:deployment_id>', methods=['PUT'])
@login_required
def update_application_deployment(deployment_id):
    deployment = ApplicationDeployment.query.get_or_404(deployment_id)
    current = get_current_user()
    if not can_write_application(current, deployment.application):
        return json_error('You do not have permission to update this deployment.', 403)

    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    base_url = normalize_deployment_url(data.get('base_url'))
    if not name:
        return json_error('Deployment name is required.', 400)
    if not base_url or not is_valid_url(base_url):
        return json_error('Deployment URL must start with http:// or https://.', 400)

    deployment.name = name
    deployment.deployment_type = normalize_deployment_type(data.get('deployment_type'))
    deployment.base_url = base_url
    log_change('updated', 'deployment', deployment.id, name, f'Updated deployment for application "{deployment.application.name}".', current)
    db.session.commit()
    return jsonify({
        'message': 'Deployment updated.',
        'deployment': serialize_application_deployment(deployment, current),
    })


@app.route('/api/application_deployments/<int:deployment_id>', methods=['DELETE'])
@login_required
def delete_application_deployment(deployment_id):
    deployment = ApplicationDeployment.query.get_or_404(deployment_id)
    current = get_current_user()
    if not can_write_application(current, deployment.application):
        return json_error('You do not have permission to delete this deployment.', 403)

    deployment_name = deployment.name
    application_name = deployment.application.name
    log_change('deleted', 'deployment', deployment.id, deployment_name, f'Deleted deployment from application "{application_name}".', current)
    db.session.delete(deployment)
    db.session.commit()
    return jsonify({'message': 'Deployment deleted.'})


@app.route('/api/application_deployments/<int:deployment_id>/check', methods=['POST'])
@login_required
def check_deployment(deployment_id):
    deployment = ApplicationDeployment.query.get_or_404(deployment_id)
    current = get_current_user()
    if not can_view_application(current, deployment.application):
        return json_error('You do not have permission to check this deployment.', 403)

    ok, error = check_application_deployment(deployment)
    db.session.commit()
    payload = {
        'message': 'Deployment check completed.' if ok else f'Deployment check completed with errors: {error}',
        'deployment': serialize_application_deployment(deployment, current),
    }
    return jsonify(payload), 200


@app.route('/api/application/<int:app_id>/repository/refresh', methods=['POST'])
@login_required
def refresh_application_repository(app_id):
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return json_error('You do not have permission to refresh repository data.', 403)
    if not app_obj.link:
        return json_error('Repository URL is required before branch data can be refreshed.', 400)

    ok, error = sync_application_repository_branches(app_obj)
    if not ok:
        db.session.rollback()
        cached_branches = [
            serialize_repository_branch(branch, current)
            for branch in sorted(app_obj.repository_branches, key=lambda item: (not item.is_default, item.branch_name.lower()))
        ]
        if 'rate limit' in str(error).lower():
            return jsonify({
                'message': 'Repository refresh skipped because the provider rate limit was reached. Showing cached data.',
                'warning': f'Could not refresh repository data: {error}',
                'repository_branches': cached_branches
            }), 200
        return json_error(f'Could not refresh repository data: {error}', 400)
    db.session.commit()
    return jsonify({
        'message': 'Repository data refreshed.',
        'repository_branches': [
            serialize_repository_branch(branch, current)
            for branch in sorted(app_obj.repository_branches, key=lambda item: (not item.is_default, item.branch_name.lower()))
        ]
    })

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
        change_date = format_date_for_user(last_version.change_date, user) if last_version else 'N/A'
        change_datetime = format_datetime_for_user(last_version.change_date, user) if last_version else 'N/A'
        app_access_level = application_access_level_for_user(user, app_obj)
        apps_data.append({
            'id': app_obj.id,
            'name': app_obj.name,
            'version_info': version_info,
            'change_date': change_date,
            'change_datetime': change_datetime,
            'change_sort': last_version.change_date.isoformat() if last_version else '',
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
    current = get_current_user()
    if not can_view_application(current, app_obj):
        return json_error('You do not have access to this application.', 403)
    versions = Version.query.filter_by(application_id=app_id).order_by(Version.change_date.desc()).all()
    versions_data = [serialize_version(version, current) for version in versions]
    return jsonify(versions_data)

@app.route('/edit_application/<int:app_id>', methods=['POST'])
@login_required
def edit_application(app_id):
    data = request.get_json()
    app_obj = Application.query.get_or_404(app_id)
    current = get_current_user()
    if not can_write_application(current, app_obj):
        return json_error('You do not have permission to update this application.', 403)

    previous_projects = list(app_obj.projects)
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
        touch_projects({project.id: project for project in previous_projects + list(app_obj.projects)}.values())
        log_change('updated', 'application', app_obj.id, app_obj.name, 'Updated application details.', current)
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

        versioning_type = normalize_versioning_type(data.get('versioning_type'))
        initial_version_number, version_error = normalize_initial_version_for_options(
            versioning_type,
            data.get('initial_version'),
            data.get('prerelease_identifier')
        )
        if version_error:
            return jsonify({'error': version_error}), 400

        existing_app = Application.query.filter(func.lower(Application.name) == name.lower()).first()
        if existing_app:
            return jsonify({'error': 'Application name already exists. Please choose another name.'}), 400

        projects = Project.query.filter(Project.id.in_(project_ids)).all() if project_ids else []
        new_app = Application(name=name, link=link, label=label)
        new_app.projects.extend(projects)

        db.session.add(new_app)
        db.session.flush()
        touch_projects(projects)

        initial_version = Version(
            application_id=new_app.id,
            number=initial_version_number,
            version_type=versioning_type,
            change_date=datetime.utcnow()
        )
        db.session.add(initial_version)
        log_change('created', 'application', new_app.id, new_app.name, f'Created application with initial version {initial_version.number}.', get_current_user())
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
        current = get_current_user()
        application_name = app_to_delete.name
        log_change('deleted', 'application', app_to_delete.id, application_name, 'Deleted application.', current)
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
    projects_data = [{'id': p.id, 'name': p.name, 'description': p.description or ''} for p in projects]
    return jsonify(projects_data)

@app.route('/app/<int:application_id>/update_version', methods=['POST'])
@jwt_required()
def update_version(application_id):
    try:
        payload = request.get_json(silent=True) or {}
        jwt_user = load_user_for_jwt_identity(get_jwt_identity())
        app_obj = Application.query.get_or_404(application_id)
        if not can_write_application(jwt_user, app_obj):
            return jsonify({'error': 'You do not have permission to update this application.'}), 403
        version_part = payload.get('version_part')
        if version_part not in ['major', 'minor', 'patch']:
            return jsonify({'error': 'Invalid version part'}), 400

        latest_version = Version.query.filter_by(application_id=application_id).order_by(Version.change_date.desc()).first()
        if latest_version is None:
            return jsonify({'error': 'No versions found for this application'}), 404

        versioning_type = normalize_versioning_type(latest_version.version_type)
        prerelease = payload.get('prerelease') or payload.get('pre_release') or payload.get('prerelease_identifier')
        try:
            new_version_number = increment_version_number(
                latest_version.number,
                versioning_type,
                version_part,
                prerelease=prerelease
            )
        except ValueError as error:
            return jsonify({'error': str(error)}), 400

        release_notes = release_notes_from_payload(payload)
        new_version = Version(
            application_id=application_id,
            number=new_version_number,
            version_type=versioning_type,
            notes=release_notes
        )
        db.session.add(new_version)
        log_change('created', 'version', None, new_version_number, f'Created version for application "{app_obj.name}".', jwt_user)
        db.session.commit()

        return jsonify({'new_version': new_version_number, 'notes': release_notes})
    except Exception as e:
        logging.error(f"Error updating version for application {application_id}: {str(e)}")
        return jsonify({'error': 'Server error while updating version'}), 500


@app.route('/app/<int:application_id>/versioning', methods=['PUT'])
@login_required
def update_application_versioning(application_id):
    app_obj = Application.query.get_or_404(application_id)
    current = get_current_user()
    if not can_write_application(current, app_obj):
        return json_error('You do not have permission to update this application.', 403)

    payload = request.get_json(silent=True) or {}
    versioning_type = versioning_type_from_options(
        bool(payload.get('enable_prerelease')),
        bool(payload.get('enable_build'))
    )
    prerelease_value, prerelease_error = validate_prerelease_identifier(payload.get('prerelease_identifier'))
    if prerelease_error:
        return json_error(prerelease_error, 400)
    if versioning_uses_prerelease(versioning_type) and not prerelease_value:
        return json_error('Pre-release Label is required when Pre-release Label is enabled.', 400)

    latest_version = Version.query.filter_by(application_id=application_id).order_by(Version.change_date.desc()).first()
    if latest_version is None:
        return json_error('No versions found for this application.', 404)

    try:
        major, minor, patch, build, existing_prerelease = parse_version_number(latest_version.number)
    except ValueError as error:
        return json_error(str(error), 400)

    build_value = build
    if versioning_uses_build(versioning_type):
        raw_build_number = payload.get('build_number')
        if raw_build_number in (None, ''):
            build_value = build if build is not None else 0
        else:
            try:
                build_value = int(raw_build_number)
            except (TypeError, ValueError):
                return json_error('Build number must be a whole number.', 400)
            if build_value < 0:
                return json_error('Build number must be zero or greater.', 400)

    next_prerelease = prerelease_value or existing_prerelease
    next_build = build_value if versioning_uses_build(versioning_type) else None
    latest_version.version_type = versioning_type
    latest_version.number = format_version_number(
        major,
        minor,
        patch,
        next_build,
        next_prerelease,
        versioning_type
    )
    log_change('updated', 'versioning', latest_version.id, app_obj.name, f'Updated versioning options to {versioning_type}.', current)
    db.session.commit()
    version_context = application_version_context(application_id, current)

    return jsonify({
        'message': 'Versioning options updated successfully.',
        'latest_version': serialize_version(latest_version, current),
        'latest_version_type': version_context['latest_version_type'],
        'latest_version_type_label': version_context['latest_version_type_label'],
        'latest_prerelease_identifier': version_context['latest_prerelease_identifier'],
        'latest_uses_prerelease': version_context['latest_uses_prerelease'],
        'latest_uses_build': version_context['latest_uses_build'],
        'latest_build_number': version_context['latest_build_number'],
    })

### Project JSON API routes
@app.route('/get_projects_data', methods=['GET'])
@login_required
def get_projects_data():
    search_query = request.args.get('search', '').strip()
    ids_param = request.args.get('ids', '').strip()
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'start_date').strip().lower()
    sort_dir = request.args.get('sort_dir', 'desc').strip().lower()
    per_page = 5

    user = get_current_user()
    project_ids = accessible_project_ids(user)
    requested_ids = [int(value) for value in ids_param.split(',') if value.strip().isdigit()] if ids_param else []
    projects_query = Project.query
    if search_query:
        projects_query = projects_query.filter(Project.name.ilike(f'%{search_query}%'))
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

    projects = projects_query.all()

    def project_access_sort_value(project):
        return project_role_display_code(user, project.id) or access_code(project_access_level_for_user(user, project.id)) or ''

    sorters = {
        'name': lambda project: (project.name or '').lower(),
        'status': lambda project: (project.status or '').lower(),
        'start_date': lambda project: project.start_date or datetime.min,
        'access': lambda project: project_access_sort_value(project).lower(),
    }
    sort_key = sorters.get(sort_by, sorters['start_date'])
    reverse = sort_dir != 'asc'
    projects = sorted(projects, key=sort_key, reverse=reverse)

    total_projects = len(projects)
    total_pages = math.ceil(total_projects / per_page) if total_projects else 0
    page = min(max(page, 1), total_pages or 1)
    start = (page - 1) * per_page
    end = start + per_page
    projects = projects[start:end]

    projects_data = []
    for project in projects:
        project_access_level = project_access_level_for_user(user, project.id)
        projects_data.append({
            'id': project.id,
            'name': project.name,
            'description': project.description or '',
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
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_num': page - 1 if page > 1 else None,
        'next_num': page + 1 if page < total_pages else None,
        'page': page,
        'total_pages': total_pages,
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
        log_change('created', 'project', new_project.id, new_project.name, 'Created project.', current)
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
        current = get_current_user()
        project_name = project.name
        log_change('deleted', 'project', project.id, project_name, 'Deleted project.', current)
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

    def latest_application_version_number(app_obj):
        latest_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
        return latest_version.number if latest_version else 'No versions available'

    return jsonify({
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'source_link': project.source_link,
        'created_at': format_datetime_for_user(project.created_at, current),
        'updated_at': format_datetime_for_user(project.updated_at or project.created_at, current),
        'status': project.status,
        'access_level': project_access_level,
        'access_label': access_label(project_access_level),
        'access_code': access_code(project_access_level),
        'project_role_label': project_role_display_label(current, project_id),
        'project_role_code': project_role_display_code(current, project_id),
        'can_edit': can_manage_project_resource(current, project_id),
        'access_summary': serialize_project_access_summary(project, current),
        'applications': [
            {
                'id': app.id,
                'name': app.name,
                'access_level': application_access_level_for_user(current, app),
                'access_label': access_label(application_access_level_for_user(current, app)),
                'access_code': access_code(application_access_level_for_user(current, app)),
                'can_view': can_view_application(current, app),
                'current_version': latest_application_version_number(app),
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


def serialize_project_application_option(app_obj, current):
    latest_version = Version.query.filter_by(application_id=app_obj.id).order_by(Version.change_date.desc()).first()
    return {
        'id': app_obj.id,
        'name': app_obj.name,
        'current_version': latest_version.number if latest_version else 'No versions available',
        'access_label': access_label(application_access_level_for_user(current, app_obj)),
        'access_code': access_code(application_access_level_for_user(current, app_obj)),
    }


@app.route('/api/projects/<int:project_id>/available_applications')
@login_required
def available_project_applications(project_id):
    project = Project.query.get_or_404(project_id)
    current = get_current_user()
    if not can_manage_project_resource(current, project_id):
        return json_error('You do not have permission to link applications to this project.', 403)

    query = Application.query.filter(~Application.projects.any())
    applications = [
        app_obj for app_obj in query.order_by(Application.name).all()
        if can_write_application(current, app_obj)
    ]
    return jsonify([serialize_project_application_option(app_obj, current) for app_obj in applications])


@app.route('/api/projects/<int:project_id>/applications', methods=['POST'])
@login_required
def link_project_application(project_id):
    project = Project.query.get_or_404(project_id)
    current = get_current_user()
    if not can_manage_project_resource(current, project_id):
        return json_error('You do not have permission to link applications to this project.', 403)

    data = request.get_json(silent=True) or {}
    application_id = data.get('application_id')
    app_obj = Application.query.get_or_404(application_id)
    if not can_write_application(current, app_obj):
        return json_error('You do not have permission to link this application.', 403)
    if app_obj.projects and project not in app_obj.projects:
        return json_error('This application is already linked to another project.', 400)

    if app_obj not in project.applications:
        project.applications.append(app_obj)
        touch_project(project)
        log_change('created', 'project application link', project.id, project.name, f'Linked application "{app_obj.name}".', current)
        db.session.commit()
    return jsonify({'message': 'Application linked successfully.'})


@app.route('/api/projects/<int:project_id>/applications/<int:application_id>', methods=['DELETE'])
@login_required
def unlink_project_application(project_id, application_id):
    project = Project.query.get_or_404(project_id)
    current = get_current_user()
    if not can_manage_project_resource(current, project_id):
        return json_error('You do not have permission to remove applications from this project.', 403)

    app_obj = Application.query.get_or_404(application_id)
    if app_obj in project.applications:
        project.applications.remove(app_obj)
        touch_project(project)
        log_change('deleted', 'project application link', project.id, project.name, f'Removed application "{app_obj.name}".', current)
        db.session.commit()
    return jsonify({'message': 'Application removed from project.'})


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
    touch_project(project)

    try:
        log_change('updated', 'project', project.id, project.name, 'Updated project details.', get_current_user())
        db.session.commit()
        return jsonify({'message': 'Project updated successfully'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating project {project_id}: {str(e)}")
        return jsonify({'error': 'Database error'}), 500

### User and project membership routes
def serialize_user(user, display_user=None):
    display_user = display_user or user
    return {
        'id': user.id,
        'username': user.username,
        'full_name': user.full_name or '',
        'email': user.email or '',
        'timezone': user.timezone or DEFAULT_TIMEZONE,
        'datetime_format': normalize_datetime_format(getattr(user, 'datetime_format', DEFAULT_DATETIME_FORMAT)),
        'datetime_format_label': DATETIME_FORMAT_OPTIONS[normalize_datetime_format(getattr(user, 'datetime_format', DEFAULT_DATETIME_FORMAT))]['label'],
        'platform_role': user.platform_role,
        'platform_role_label': PLATFORM_ROLE_LABELS.get(user.platform_role, user.platform_role),
        'is_active': bool(user.is_active),
        'can_create_projects': bool(user.can_create_projects),
        'status': 'Active' if user.is_active else 'Disabled',
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'created_at_display': format_datetime_for_user(user.created_at, display_user) if user.created_at else 'N/A',
        'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
        'last_login_display': format_datetime_for_user(user.last_login_at, display_user) if user.last_login_at else 'Never'
    }


def serialize_user_details(user, display_user=None):
    data = serialize_user(user, display_user)
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


def serialize_application_access_summary(app_obj, viewer=None):
    project = app_obj.projects[0] if app_obj.projects else None
    can_manage_access = can_manage_application_membership(viewer, app_obj, project_id=project.id) if project else has_platform_role(viewer, PLATFORM_ADMIN)
    project_memberships = []
    if project:
        project_memberships = ProjectMembership.query.join(User).filter(
            ProjectMembership.project_id == project.id
        ).order_by(User.username).all()

    project_managers = []
    project_operators = []
    for membership in project_memberships:
        user_data = {
            'membership_id': membership.id,
            'can_remove_access': can_manage_project_membership(viewer, project.id, membership.user),
            'user_id': membership.user_id,
            'username': membership.user.username,
            'full_name': membership.user.full_name or '',
            'project_role': membership.project_role,
            'project_role_label': project_role_label(membership.project_role),
            'access_level': membership.access_level,
            'access_label': access_label(membership.access_level),
        }
        if membership.project_role == PROJECT_ADMIN:
            project_managers.append(user_data)
        elif membership.project_role == PROJECT_USER:
            project_operators.append(user_data)

    include_platform_admins = has_platform_role(viewer, PLATFORM_ADMIN)
    platform_admins = []
    if include_platform_admins:
        platform_admins = [
            {
                'user_id': user.id,
                'username': user.username,
                'full_name': user.full_name or '',
                'platform_role': user.platform_role,
                'platform_role_label': PLATFORM_ROLE_LABELS.get(user.platform_role, user.platform_role),
            }
            for user in User.query.filter_by(is_active=True, platform_role=PLATFORM_ADMIN).order_by(User.username).all()
        ]

    effective_read_write = []
    effective_read_only = []
    for user in User.query.filter_by(is_active=True).order_by(User.username).all():
        if user.platform_role == PLATFORM_ADMIN:
            continue
        effective_access = application_access_level_for_user(user, app_obj)
        if effective_access not in (ACCESS_READ_WRITE, ACCESS_VIEW_ONLY):
            continue
        project_membership = get_project_membership(user, project.id) if project else None
        application_membership = get_application_membership(user, app_obj.id)
        user_data = {
            'membership_id': application_membership.id if application_membership else None,
            'project_membership_id': project_membership.id if project_membership else None,
            'can_remove_access': can_manage_application_membership(viewer, app_obj, user, project_id=project.id if project else None),
            'user_id': user.id,
            'username': user.username,
            'full_name': user.full_name or '',
            'platform_role': user.platform_role,
            'platform_role_label': PLATFORM_ROLE_LABELS.get(user.platform_role, user.platform_role),
            'project_role': project_membership.project_role if project_membership else None,
            'project_role_label': project_role_label(project_membership.project_role) if project_membership else 'No Project Membership',
            'access_level': effective_access,
            'access_label': access_label(effective_access),
            'is_project_manager': bool(project_membership and project_membership.project_role == PROJECT_ADMIN),
        }
        if effective_access == ACCESS_READ_WRITE:
            effective_read_write.append(user_data)
        else:
            effective_read_only.append(user_data)

    return {
        'project_name': project.name if project else 'No project',
        'can_manage_access': can_manage_access,
        'platform_admins': platform_admins,
        'show_platform_admin_names': include_platform_admins,
        'project_managers': project_managers,
        'project_operators': project_operators,
        'application_read_write': effective_read_write,
        'application_read_only': effective_read_only,
    }


def serialize_project_access_summary(project, viewer=None):
    project_memberships = ProjectMembership.query.join(User).filter(
        ProjectMembership.project_id == project.id,
        User.is_active.is_(True)
    ).order_by(User.username).all()

    managers = []
    operators = []
    for membership in project_memberships:
        user_data = {
            'membership_id': membership.id,
            'can_remove_access': can_manage_project_membership(viewer, project.id, membership.user),
            'user_id': membership.user_id,
            'username': membership.user.username,
            'full_name': membership.user.full_name or '',
            'project_role': membership.project_role,
            'project_role_label': project_role_label(membership.project_role),
            'access_level': membership.access_level,
            'access_label': access_label(membership.access_level),
        }
        if membership.project_role == PROJECT_ADMIN:
            managers.append(user_data)
        elif membership.project_role == PROJECT_USER:
            operators.append(user_data)

    include_platform_admins = has_platform_role(viewer, PLATFORM_ADMIN)
    platform_admins = []
    if include_platform_admins:
        platform_admins = [
            {
                'user_id': user.id,
                'username': user.username,
                'full_name': user.full_name or '',
                'platform_role': user.platform_role,
                'platform_role_label': PLATFORM_ROLE_LABELS.get(user.platform_role, user.platform_role),
            }
            for user in User.query.filter_by(is_active=True, platform_role=PLATFORM_ADMIN).order_by(User.username).all()
        ]

    return {
        'platform_admins': platform_admins,
        'show_platform_admin_names': include_platform_admins,
        'managers': managers,
        'operators': operators,
    }


@app.route('/content/settings')
@login_required
def settings_content():
    return render_template(
        'settings.html',
        timezone_options=get_timezone_options(),
        datetime_format_options=get_datetime_format_options()
    )


@app.route('/content/system-settings')
@login_required
def system_settings_content():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('You do not have permission to access system settings.', 403)
    return render_template('system_settings.html')


@app.route('/api/system/logs')
@login_required
def system_logs():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('Only admins can view system logs.', 403)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search_query = request.args.get('search', '', type=str).strip()
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    query = ChangeLog.query.order_by(ChangeLog.created_at.desc(), ChangeLog.id.desc())
    if search_query:
        search_like = f'%{search_query.lower()}%'
        query = query.filter(or_(
            func.lower(ChangeLog.action).like(search_like),
            func.lower(ChangeLog.entity_type).like(search_like),
            func.lower(ChangeLog.entity_name).like(search_like),
            func.lower(ChangeLog.details).like(search_like),
            func.lower(ChangeLog.actor_username).like(search_like),
        ))
    total_items = query.count()
    total_pages = max(1, math.ceil(total_items / per_page)) if total_items else 1
    page = min(page, total_pages)
    entries = query.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        'logs': [serialize_change_log(entry, current) for entry in entries],
        'page': page,
        'per_page': per_page,
        'total_items': total_items,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    })


@app.route('/api/system/logs/download')
@login_required
def download_system_logs():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('Only admins can download system logs.', 403)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['date', 'actor', 'action', 'entity_type', 'entity_id', 'entity_name', 'details'])
    entries = ChangeLog.query.order_by(ChangeLog.created_at.desc(), ChangeLog.id.desc()).all()
    for entry in entries:
        writer.writerow([
            format_datetime_for_user(entry.created_at, current) if entry.created_at else '',
            entry.actor_username or 'system',
            entry.action,
            entry.entity_type,
            entry.entity_id or '',
            entry.entity_name or '',
            entry.details or '',
        ])
    filename = f"vermicelli-change-logs-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/api/system/verify-admin-password', methods=['POST'])
@login_required
def verify_system_admin_password():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('Only admins can verify system access.', 403)
    admin_password = backup_request_value('admin_password')
    if not admin_password or not current.check_password(admin_password):
        return json_error('Current admin password is incorrect.', 400)
    return jsonify({'message': 'Admin password verified.'})


@app.route('/api/system/backup', methods=['POST'])
@login_required
def export_system_backup():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('Only admins can export system backups.', 403)

    backup_password = backup_request_value('backup_password')
    encrypted_payload, error = encrypt_backup_payload(serialize_backup_payload(), backup_password)
    if error:
        return json_error(error, 400)

    log_change('exported', 'backup', None, 'System backup', 'Exported encrypted system backup.', current)
    db.session.commit()
    filename = f"vermicelli-backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.vmbak"
    return Response(
        json.dumps(encrypted_payload, indent=2, sort_keys=True),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )


@app.route('/api/system/backup/import', methods=['POST'])
@login_required
def import_system_backup():
    current = get_current_user()
    if not has_platform_role(current, PLATFORM_ADMIN):
        return json_error('Only admins can import system backups.', 403)

    admin_password = backup_request_value('admin_password')
    if not admin_password or not current.check_password(admin_password):
        return json_error('Current admin password is incorrect.', 400)

    backup_password = backup_request_value('backup_password')
    encrypted_payload, error = encrypted_backup_payload_from_request()
    if error:
        return json_error(error, 400)

    payload, error = decrypt_backup_payload(encrypted_payload, backup_password)
    if error:
        return json_error(error, 400)

    actor_username = current.username
    ok, error = import_backup_payload(payload)
    if not ok:
        return json_error(error, 400)

    restored_actor = User.query.filter_by(username=actor_username).first()
    db.session.add(ChangeLog(
        action='restored',
        entity_type='backup',
        entity_name='System backup',
        details='Restored encrypted system backup.',
        actor_user_id=restored_actor.id if restored_actor else None,
        actor_username=actor_username,
    ))
    db.session.commit()
    session.clear()
    return jsonify({'message': 'Backup imported successfully. Please sign in again.'})


@app.route('/api/setup/test-database', methods=['POST'])
def test_initial_setup_database():
    if not setup_is_available(require_empty_data=True):
        return json_error('Initial setup is available only before any data exists.', 403)

    payload = request.get_json(silent=True) if request.is_json else request.form
    database_config, error = setup_database_config_from_request(payload or {})
    if error:
        return json_error(error, 400)

    ok, error = test_setup_database_connection(database_config)
    if not ok:
        return json_error(f'Database connection failed: {error}', 400)
    return jsonify({'message': 'Database connection succeeded.'})


@app.route('/api/bootstrap/backup/verify', methods=['POST'])
def verify_bootstrap_backup():
    if not setup_is_available(require_empty_data=True):
        return json_error('Backup validation is available only before any data exists.', 403)

    backup_password = backup_request_value('backup_password')
    encrypted_payload, error = encrypted_backup_payload_from_request()
    if error:
        return json_error(error, 400)

    payload, error = decrypt_backup_payload(encrypted_payload, backup_password)
    if error:
        return json_error(error, 400)

    data, error = validate_backup_payload(payload)
    if error:
        return json_error(error, 400)

    return jsonify({
        'message': 'Backup is valid.',
        'summary': backup_validation_summary(data),
        'format': ENCRYPTED_BACKUP_FORMAT,
        'version': BACKUP_VERSION,
    })


@app.route('/api/bootstrap/backup/import', methods=['POST'])
def import_bootstrap_backup():
    if admin_count() > 0 or database_has_any_data():
        return json_error('Bootstrap backup import is available only before any data exists.', 403)

    if backup_request_value('restore_confirmation') != 'RESTORE':
        return json_error('Type RESTORE to confirm the restore.', 400)

    backup_password = backup_request_value('backup_password')
    encrypted_payload, error = encrypted_backup_payload_from_request()
    if error:
        return json_error(error, 400)

    payload, error = decrypt_backup_payload(encrypted_payload, backup_password)
    if error:
        return json_error(error, 400)

    data, error = validate_backup_payload(payload)
    if error:
        return json_error(error, 400)

    try:
        complete_initial_setup_config({'DB_ENGINE': 'sqlite', 'DB': DB_NAME or 'verdb'})
    except Exception as error:
        logging.exception("Bootstrap backup restore setup failed")
        return json_error(f'Backup restore setup failed: {error}', 400)

    ok, error = import_backup_payload(payload)
    if not ok:
        return json_error(error, 400)

    session.clear()
    return jsonify({'message': 'Backup imported successfully. Sign in with an account from the backup.'})


@app.route('/api/me', methods=['GET'])
@login_required
def get_me():
    user = get_current_user()
    if not user:
        return json_error('Settings are available only for database users.', 403)
    return jsonify(serialize_user_details(user, user))


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
    datetime_format = data.get(
        'datetime_format',
        getattr(user, 'datetime_format', DEFAULT_DATETIME_FORMAT) or DEFAULT_DATETIME_FORMAT
    ).strip()

    if not is_valid_timezone(timezone_name):
        return json_error('Invalid time zone.', 400)
    if not is_valid_datetime_format(datetime_format):
        return json_error('Invalid date and time format.', 400)

    user.email = email
    user.full_name = full_name
    user.timezone = timezone_name
    user.datetime_format = normalize_datetime_format(datetime_format)
    log_change('updated', 'user', user.id, user.username, 'Updated account settings.', user)
    db.session.commit()
    return jsonify(serialize_user_details(user, user))


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
    log_change('updated', 'user', user.id, user.username, 'Changed account password.', user)
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
    return jsonify([serialize_user(user, current) for user in query.order_by(User.username).all()])


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
    db.session.flush()
    log_change('created', 'user', new_user.id, new_user.username, 'Created user account.', current)
    db.session.commit()
    return jsonify(serialize_user(new_user, current)), 201


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
    log_change('updated', 'user', target.id, target.username, 'Updated user account.', current)
    db.session.commit()
    return jsonify(serialize_user(target, current))


@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user_details(user_id):
    current = get_current_user()
    target = User.query.get_or_404(user_id)
    if not can_manage_user(current, target, target.platform_role) and not can_manage_users_page(current):
        return json_error('You do not have permission to view this user.', 403)
    return jsonify(serialize_user_details(target, current))


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
    log_change('updated', 'user', target.id, target.username, 'Enabled user account.' if is_active else 'Disabled user account.', current)
    db.session.commit()
    if session.get('user_id') == user_id and not is_active:
        session.clear()
    return jsonify(serialize_user(target, current))


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

    username = target.username
    log_change('deleted', 'user', target.id, username, 'Deleted user account.', current)
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


def ensure_project_applications_read_write_access(user_id, project):
    """Give a user explicit read-write access to every application in a project."""
    updated_memberships = []
    for app_obj in project.applications:
        app_membership = ApplicationMembership.query.filter_by(
            user_id=user_id,
            application_id=app_obj.id,
        ).first()
        if app_membership:
            app_membership.access_level = ACCESS_READ_WRITE
        else:
            app_membership = ApplicationMembership(
                user_id=user_id,
                application_id=app_obj.id,
                access_level=ACCESS_READ_WRITE,
            )
            db.session.add(app_membership)
        updated_memberships.append(app_membership)
    return updated_memberships


@app.route('/api/project_memberships', methods=['POST'])
@login_required
def create_project_membership():
    current = get_current_user()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    project_id = data.get('project_id')
    project_role = data.get('project_role', PROJECT_USER)
    target_user = User.query.get_or_404(user_id)
    project = Project.query.get_or_404(project_id)
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
    if project_role == PROJECT_ADMIN:
        ensure_project_applications_read_write_access(user_id, project)
    touch_project(project)
    log_change('created', 'project access', None, project.name, f'Granted {project_role_label(project_role)} access to {target_user.username}.', current)
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
    if project_role == PROJECT_ADMIN:
        ensure_project_applications_read_write_access(membership.user_id, membership.project)
    touch_project(membership.project)
    log_change('updated', 'project access', membership.id, membership.project.name, f'Changed {membership.user.username} to {project_role_label(project_role)}.', current)
    db.session.commit()
    return jsonify(serialize_membership(membership))


def project_membership_application_access(membership):
    project_applications = sorted(membership.project.applications, key=lambda app_obj: app_obj.name.lower())
    project_application_ids = [app_obj.id for app_obj in project_applications]
    if not project_application_ids:
        return []
    memberships = ApplicationMembership.query.join(Application).filter(
        ApplicationMembership.user_id == membership.user_id,
        ApplicationMembership.application_id.in_(project_application_ids)
    ).order_by(Application.name).all()
    memberships_by_application = {
        app_membership.application_id: app_membership
        for app_membership in memberships
    }
    if membership.project_role == PROJECT_ADMIN:
        return [
            {
                'membership_id': memberships_by_application.get(app_obj.id).id if memberships_by_application.get(app_obj.id) else None,
                'application_id': app_obj.id,
                'application_name': app_obj.name,
                'access_level': ACCESS_READ_WRITE,
                'access_code': access_code(ACCESS_READ_WRITE),
                'access_label': access_label(ACCESS_READ_WRITE),
            }
            for app_obj in project_applications
        ]
    return [
        {
            'membership_id': app_membership.id,
            'application_id': app_membership.application_id,
            'application_name': app_membership.application.name,
            'access_level': app_membership.access_level,
            'access_code': access_code(app_membership.access_level),
            'access_label': access_label(app_membership.access_level),
        }
        for app_membership in memberships
        if app_membership.access_level in (ACCESS_READ_WRITE, ACCESS_VIEW_ONLY)
    ]


@app.route('/api/project_memberships/<int:membership_id>/application_access', methods=['GET'])
@login_required
def project_membership_application_access_preview(membership_id):
    current = get_current_user()
    membership = ProjectMembership.query.get_or_404(membership_id)
    if not can_manage_project_membership(current, membership.project_id, membership.user):
        return json_error('You do not have permission to view this membership.', 403)

    return jsonify({
        'project_id': membership.project_id,
        'project_name': membership.project.name,
        'user_id': membership.user_id,
        'username': membership.user.username,
        'applications': project_membership_application_access(membership),
    })


@app.route('/api/project_memberships/<int:membership_id>', methods=['DELETE'])
@login_required
def delete_project_membership(membership_id):
    current = get_current_user()
    membership = ProjectMembership.query.get_or_404(membership_id)
    if not can_manage_project_membership(current, membership.project_id, membership.user):
        return json_error('You do not have permission to delete this membership.', 403)

    data = request.get_json(silent=True) or {}
    delete_application_access = bool(data.get('delete_application_access'))
    deleted_application_memberships = []
    if delete_application_access:
        project_application_ids = [app_obj.id for app_obj in membership.project.applications]
        if project_application_ids:
            deleted_application_memberships = ApplicationMembership.query.filter(
                ApplicationMembership.user_id == membership.user_id,
                ApplicationMembership.application_id.in_(project_application_ids)
            ).all()
            for app_membership in deleted_application_memberships:
                if can_manage_application_membership(current, app_membership.application, app_membership.user, membership.project_id):
                    db.session.delete(app_membership)
    elif membership.project_role == PROJECT_ADMIN:
        ensure_project_applications_read_write_access(membership.user_id, membership.project)

    touch_project(membership.project)
    log_change('deleted', 'project access', membership.id, membership.project.name, f'Removed project access for {membership.user.username}.', current)
    db.session.delete(membership)
    db.session.commit()
    return jsonify({
        'message': 'Membership deleted successfully',
        'deleted_application_memberships': len(deleted_application_memberships),
    })


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
    if project_id:
        touch_project(project)
    else:
        touch_projects(app_obj.projects)
    log_change('created', 'application access', None, app_obj.name, f'Granted {access_label(access_level)} application access to {target_user.username}.', current)
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
    if project_id:
        touch_project(project)
    else:
        touch_projects(membership.application.projects)
    log_change('updated', 'application access', membership.id, membership.application.name, f'Changed {membership.user.username} to {access_label(access_level)}.', current)
    db.session.commit()
    return jsonify(serialize_application_membership(membership))


@app.route('/api/application_memberships/<int:membership_id>', methods=['DELETE'])
@login_required
def delete_application_membership(membership_id):
    current = get_current_user()
    membership = ApplicationMembership.query.get_or_404(membership_id)
    if not can_manage_application_membership(current, membership.application, membership.user):
        return json_error('You do not have permission to delete this application membership.', 403)

    touched_projects = list(membership.application.projects)
    log_change('deleted', 'application access', membership.id, membership.application.name, f'Removed application access for {membership.user.username}.', current)
    db.session.delete(membership)
    touch_projects(touched_projects)
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
    touched_projects = {project.id: project}
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

    touch_projects(touched_projects.values())
    log_change('updated', 'access', project.id, project.name, f'Bulk updated access for {len(user_ids)} user(s).', current)
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
