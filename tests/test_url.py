import os
import sys
import io
import json

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

os.environ['JWT_SECRET_KEY'] = 'test'
os.environ['SECRET_KEY'] = 'test'
os.environ['SESSION_TYPE'] = 'filesystem'
os.environ['DB_ENGINE'] = 'sqlite'
os.environ['DB'] = 'testdb'
os.environ['USERS'] = ''

import pytest

from main import (
    ACCESS_NO_ACCESS,
    ACCESS_READ_WRITE,
    ACCESS_VIEW_ONLY,
    Application,
    ApplicationMembership,
    PLATFORM_ADMIN,
    PLATFORM_SUPER_ADMIN,
    PLATFORM_USER,
    PROJECT_ADMIN,
    PROJECT_USER,
    Project,
    ProjectMembership,
    User,
    Version,
    app,
    db,
    decrypt_backup_payload,
    encrypt_backup_payload,
    is_valid_datetime_format,
    is_valid_timezone,
    is_valid_url,
)
from datetime import datetime


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def create_user(username, role=PLATFORM_USER):
    user = User(username=username, full_name=username.title(), platform_role=role)
    user.set_password('password')
    db.session.add(user)
    db.session.commit()
    return user


def login_as(client, user):
    with client.session_transaction() as sess:
        sess.clear()
        sess['user_id'] = user.id
        sess['username'] = user.username
        sess['platform_role'] = user.platform_role


def make_backup_payload():
    admin = User(username='restored-admin', full_name='Restored Admin', platform_role=PLATFORM_ADMIN)
    admin.set_password('password')
    member = User(username='restored-member', full_name='Restored Member', platform_role=PLATFORM_USER)
    member.set_password('password')
    return {
        'format': 'vermicelli-backup',
        'version': 1,
        'exported_at': '2026-04-29T10:00:00Z',
        'data': {
            'users': [
                {
                    'id': 1,
                    'username': admin.username,
                    'full_name': admin.full_name,
                    'timezone': 'UTC',
                    'datetime_format': 'iso_24',
                    'email': 'admin@example.com',
                    'is_active': True,
                    'can_create_projects': False,
                    'last_login_at': None,
                    'password_hash': admin.password_hash,
                    'platform_role': PLATFORM_ADMIN,
                    'created_at': '2026-04-29T10:00:00',
                    'updated_at': '2026-04-29T10:00:00',
                },
                {
                    'id': 2,
                    'username': member.username,
                    'full_name': member.full_name,
                    'timezone': 'Asia/Baku',
                    'datetime_format': 'eu_numeric_24',
                    'email': 'member@example.com',
                    'is_active': True,
                    'can_create_projects': True,
                    'last_login_at': None,
                    'password_hash': member.password_hash,
                    'platform_role': PLATFORM_USER,
                    'created_at': '2026-04-29T10:00:00',
                    'updated_at': '2026-04-29T10:00:00',
                },
            ],
            'projects': [
                {
                    'id': 1,
                    'name': 'Restored Project',
                    'description': 'From backup',
                    'source_link': 'https://example.com/project',
                    'status': 'In Progress',
                    'created_at': '2026-04-29T10:00:00',
                    'start_date': '2026-04-29T10:00:00',
                }
            ],
            'applications': [
                {
                    'id': 1,
                    'name': 'Restored Application',
                    'created_at': '2026-04-29T10:00:00',
                    'updated_at': '2026-04-29T10:00:00',
                    'link': 'https://example.com/app',
                    'label': 'restored',
                }
            ],
            'versions': [
                {
                    'id': 1,
                    'application_id': 1,
                    'number': '1.2.3',
                    'version_type': 'release',
                    'change_date': '2026-04-29T10:00:00',
                    'notes': 'Restored release',
                }
            ],
            'project_applications': [
                {'project_id': 1, 'application_id': 1}
            ],
            'project_memberships': [
                {
                    'id': 1,
                    'user_id': 2,
                    'project_id': 1,
                    'project_role': PROJECT_ADMIN,
                    'access_level': ACCESS_READ_WRITE,
                    'created_at': '2026-04-29T10:00:00',
                    'updated_at': '2026-04-29T10:00:00',
                }
            ],
            'application_memberships': [
                {
                    'id': 1,
                    'user_id': 2,
                    'application_id': 1,
                    'access_level': ACCESS_READ_WRITE,
                    'created_at': '2026-04-29T10:00:00',
                    'updated_at': '2026-04-29T10:00:00',
                }
            ],
        }
    }


def make_encrypted_backup_payload(password='backup-password'):
    payload, error = encrypt_backup_payload(make_backup_payload(), password)
    assert error is None
    return payload


def test_is_valid_url():
    assert is_valid_url('http://example.com')
    assert is_valid_url('https://example.com')
    assert not is_valid_url('ftp://example.com')
    assert is_valid_url('')


def test_is_valid_timezone():
    assert is_valid_timezone('UTC')
    assert is_valid_timezone('Asia/Baku')
    assert not is_valid_timezone('Invalid/Timezone')


def test_datetime_format_validator():
    assert is_valid_datetime_format('iso_24')
    assert is_valid_datetime_format('eu_numeric_24')
    assert not is_valid_datetime_format('invalid-format')


def test_first_super_admin_can_register_when_none_exists(client):
    response = client.post('/register', data={
        'username': 'root',
        'full_name': 'Root User',
        'password': 'password',
        'password_confirmation': 'password',
    })

    assert response.status_code == 302
    user = User.query.filter_by(username='root').one()
    assert user.platform_role == PLATFORM_SUPER_ADMIN


def test_second_public_super_admin_registration_is_blocked(client):
    create_user('root', PLATFORM_SUPER_ADMIN)

    response = client.post('/register', data={
        'username': 'second',
        'full_name': 'Second Root',
        'password': 'password',
        'password_confirmation': 'password',
    })

    assert response.status_code == 403
    assert User.query.filter_by(username='second').first() is None


def test_login_page_links_initial_setup_without_super_admin_language(client):
    response = client.get('/login')

    assert response.status_code == 200
    body = response.data.decode()
    assert 'Start initial setup' in body
    assert 'Register super admin' not in body


def test_register_page_shows_bootstrap_import_only_when_open(client):
    open_response = client.get('/register')

    assert open_response.status_code == 200
    body = open_response.data.decode()
    assert 'Welcome to Vermicelli' in body
    assert 'Start Initial Setup' in body
    assert 'Database Choice' in body
    assert 'Account Creation' in body
    assert 'Database Configuration' in body
    assert 'Restore from Backup' in body
    assert 'Restore Target Database' in body
    assert 'Type RESTORE to continue' in body
    assert 'Database and application configuration are generated automatically' in body
    assert 'default database name' not in body
    assert 'SECRET_KEY' not in body
    assert 'JWT_SECRET_KEY' not in body
    assert 'SESSION_TYPE' not in body
    assert 'setup-panel' not in body
    assert 'id="databaseConfigStep"' in body
    assert 'id="continueDatabaseChoice"' in body
    assert 'id="continueDatabaseConfig"' in body
    assert 'id="postgresSetupStep"' not in body
    assert body.count('setup-window') >= 8
    assert b'id="bootstrapBackupFile"' in open_response.data
    assert b'id="bootstrapBackupPassword"' in open_response.data
    assert b'id="bootstrapImportButton"' in open_response.data

    create_user('root', PLATFORM_SUPER_ADMIN)
    closed_response = client.get('/register')

    assert closed_response.status_code == 200
    assert b'id="bootstrapBackupFile"' not in closed_response.data


def test_super_admin_can_create_another_super_admin(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    login_as(client, root)

    response = client.post('/api/users', json={
        'username': 'second',
        'full_name': 'Second Root',
        'password': 'password',
        'password_confirmation': 'password',
        'platform_role': PLATFORM_SUPER_ADMIN,
    })

    assert response.status_code == 201
    assert User.query.filter_by(username='second').one().platform_role == PLATFORM_SUPER_ADMIN


def test_last_super_admin_cannot_be_deleted(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    login_as(client, root)

    response = client.delete(f'/api/users/{root.id}')

    assert response.status_code == 400
    assert User.query.get(root.id) is not None


def test_last_super_admin_cannot_be_demoted(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    login_as(client, root)

    response = client.put(f'/api/users/{root.id}', json={
        'username': 'root',
        'full_name': 'Root User',
        'platform_role': PLATFORM_USER,
    })

    assert response.status_code == 400
    assert User.query.get(root.id).platform_role == PLATFORM_SUPER_ADMIN


def test_admin_can_edit_other_admin(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    target = create_user('other-admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.put(f'/api/users/{target.id}', json={
        'username': 'other-admin',
        'full_name': 'Other Admin Updated',
        'platform_role': PLATFORM_ADMIN,
    })

    assert response.status_code == 200
    assert User.query.get(target.id).full_name == 'Other Admin Updated'


def test_admin_can_create_user_with_project_creation_permission(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.post('/api/users', json={
        'username': 'builder',
        'full_name': 'Builder User',
        'password': 'password',
        'password_confirmation': 'password',
        'platform_role': PLATFORM_USER,
        'can_create_projects': True,
    })

    assert response.status_code == 201
    assert User.query.filter_by(username='builder').one().can_create_projects is True


def test_project_admin_can_assign_another_project_admin_in_own_project(client):
    actor = create_user('project-admin')
    target = create_user('project-peer')
    project = Project(name='Project A', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=actor.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, actor)

    response = client.post('/api/project_memberships', json={
        'user_id': target.id,
        'project_id': project.id,
        'project_role': PROJECT_ADMIN,
        'access_level': ACCESS_READ_WRITE,
    })

    assert response.status_code == 201
    membership = ProjectMembership.query.filter_by(user_id=target.id, project_id=project.id).one()
    assert membership.project_role == PROJECT_ADMIN


def test_project_admin_cannot_manage_another_project(client):
    actor = create_user('project-admin')
    target = create_user('project-peer')
    own_project = Project(name='Own Project', status='Draft')
    other_project = Project(name='Other Project', status='Draft')
    db.session.add_all([own_project, other_project])
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=actor.id,
        project_id=own_project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, actor)

    response = client.post('/api/project_memberships', json={
        'user_id': target.id,
        'project_id': other_project.id,
        'project_role': PROJECT_USER,
        'access_level': ACCESS_VIEW_ONLY,
    })

    assert response.status_code == 403
    assert ProjectMembership.query.filter_by(user_id=target.id, project_id=other_project.id).first() is None


def test_project_admin_cannot_open_users_page(client):
    actor = create_user('project-admin')
    project = Project(name='Project A', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=actor.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, actor)

    response = client.get('/content/users')

    assert response.status_code == 403


def test_main_navigation_uses_dashboard_label(client):
    user = create_user('member')
    login_as(client, user)

    response = client.get('/')

    assert response.status_code == 200
    body = response.data.decode()
    assert '>Dashboard<' in body
    assert '>Home<' not in body


def test_user_can_belong_to_multiple_projects_with_different_rights(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    target = create_user('member')
    project_a = Project(name='Project A', status='Draft')
    project_b = Project(name='Project B', status='Draft')
    db.session.add_all([project_a, project_b])
    db.session.commit()
    login_as(client, root)

    response_a = client.post('/api/project_memberships', json={
        'user_id': target.id,
        'project_id': project_a.id,
        'project_role': PROJECT_USER,
        'access_level': ACCESS_VIEW_ONLY,
    })
    response_b = client.post('/api/project_memberships', json={
        'user_id': target.id,
        'project_id': project_b.id,
        'project_role': PROJECT_ADMIN,
        'access_level': ACCESS_READ_WRITE,
    })

    assert response_a.status_code == 201
    assert response_b.status_code == 201
    memberships = ProjectMembership.query.filter_by(user_id=target.id).order_by(ProjectMembership.project_id).all()
    assert len(memberships) == 2
    assert {membership.project_role for membership in memberships} == {PROJECT_USER, PROJECT_ADMIN}
    assert {membership.access_level for membership in memberships} == {ACCESS_VIEW_ONLY, ACCESS_READ_WRITE}


def test_user_can_update_full_name_and_timezone_without_changing_id_or_username(client):
    user = create_user('member')
    original_id = user.id
    login_as(client, user)

    response = client.put('/api/me', json={
        'username': 'ignored-change',
        'full_name': 'Member Renamed',
        'timezone': 'Asia/Baku',
        'datetime_format': 'eu_numeric_24',
    })

    assert response.status_code == 200
    updated = User.query.get(original_id)
    assert updated.id == original_id
    assert updated.username == 'member'
    assert updated.full_name == 'Member Renamed'
    assert updated.timezone == 'Asia/Baku'
    assert updated.datetime_format == 'eu_numeric_24'
    assert response.get_json()['datetime_format_label'] == '28/04/2026 14:30'


def test_user_cannot_save_invalid_datetime_format(client):
    user = create_user('member')
    login_as(client, user)

    response = client.put('/api/me', json={'datetime_format': 'moon-clock'})

    assert response.status_code == 400
    assert User.query.get(user.id).datetime_format == 'iso_24'


def test_account_settings_payload_includes_nested_assignments_and_metadata(client):
    user = create_user('member')
    user.email = 'member@example.com'
    user.last_login_at = datetime(2026, 1, 2, 9, 15)
    project = Project(name='Settings Project', status='Draft')
    read_only_app = Application(name='Settings Read Only App')
    writable_app = Application(name='Settings Writable App')
    read_only_app.projects.append(project)
    writable_app.projects.append(project)
    db.session.add_all([project, read_only_app, writable_app])
    db.session.flush()
    db.session.add_all([
        Version(application_id=read_only_app.id, number='1.0.0'),
        Version(application_id=writable_app.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=read_only_app.id,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=writable_app.id,
            access_level=ACCESS_READ_WRITE,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    response = client.get('/api/me')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['email'] == 'member@example.com'
    assert payload['datetime_format'] == 'iso_24'
    assert payload['datetime_format_label'] == '2026-04-28 14:30'
    assert payload['last_login_at'] is not None
    assert payload['status'] == 'Active'
    assert len(payload['assigned_projects']) == 1
    assert payload['assigned_projects'][0]['name'] == 'Settings Project'
    apps = {app['name']: app for app in payload['assigned_projects'][0]['applications']}
    assert apps['Settings Read Only App']['access_code'] == 'RO'
    assert apps['Settings Writable App']['access_code'] == 'RW'


def test_account_settings_content_combines_general_and_shows_datetime_format(client):
    user = create_user('member')
    login_as(client, user)

    response = client.get('/content/settings')

    assert response.status_code == 200
    body = response.data.decode()
    assert 'data-settings-tab="generalTab"' not in body
    assert 'id="settingsDatetimeFormat"' in body
    assert 'Time and Date Format' in body


def test_system_settings_page_is_admin_only_and_linked_from_avatar_menu(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    shell_response = client.get('/')
    assert shell_response.status_code == 200
    assert b'System Settings' in shell_response.data
    assert b'data-page="system-settings"' in shell_response.data

    admin_response = client.get('/content/system-settings')
    assert admin_response.status_code == 200
    admin_body = admin_response.data.decode()
    assert 'System Settings' in admin_body
    assert 'Export Backup' in admin_body
    assert 'Restore Backup' in admin_body

    user = create_user('member')
    login_as(client, user)

    shell_user_response = client.get('/')
    assert b'System Settings' not in shell_user_response.data
    user_response = client.get('/content/system-settings')
    assert user_response.status_code == 403


def test_account_settings_no_longer_contains_system_tab(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.get('/content/settings')

    assert response.status_code == 200
    body = response.data.decode()
    assert 'data-settings-tab="systemTab"' not in body
    assert 'Export Backup' not in body


def test_admin_can_export_encrypted_system_backup(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    project = Project(name='Backup Project', status='Draft')
    app_obj = Application(name='Backup App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add(Version(application_id=app_obj.id, number='1.0.0'))
    db.session.commit()
    login_as(client, admin)

    response = client.post('/api/system/backup', json={'backup_password': 'backup-password'})

    assert response.status_code == 200
    assert response.mimetype == 'application/json'
    assert 'attachment' in response.headers['Content-Disposition']
    assert response.headers['Content-Disposition'].endswith('.vmbak"')
    encrypted_payload = json.loads(response.data.decode())
    assert encrypted_payload['format'] == 'vermicelli-encrypted-backup'
    assert 'ciphertext' in encrypted_payload
    assert 'data' not in encrypted_payload
    payload, error = decrypt_backup_payload(encrypted_payload, 'backup-password')
    assert error is None
    assert payload['format'] == 'vermicelli-backup'
    assert payload['data']['users'][0]['username'] == 'admin'
    assert payload['data']['projects'][0]['name'] == 'Backup Project'
    assert payload['data']['applications'][0]['name'] == 'Backup App'
    assert payload['data']['project_applications'] == [{'application_id': app_obj.id, 'project_id': project.id}]


def test_export_system_backup_requires_encryption_password(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.post('/api/system/backup', json={})

    assert response.status_code == 400
    assert b'encryption password is required' in response.data


def test_regular_user_cannot_export_or_import_system_backup(client):
    user = create_user('member')
    login_as(client, user)

    export_response = client.post('/api/system/backup', json={'backup_password': 'backup-password'})
    import_response = client.post('/api/system/backup/import', json={
        'backup': make_encrypted_backup_payload(),
        'admin_password': 'password',
        'backup_password': 'backup-password',
    })

    assert export_response.status_code == 403
    assert import_response.status_code == 403


def test_admin_can_import_system_backup_and_replaces_data(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    old_project = Project(name='Old Project', status='Draft')
    db.session.add(old_project)
    db.session.commit()
    login_as(client, admin)
    payload = make_encrypted_backup_payload()

    response = client.post(
        '/api/system/backup/import',
        data={
            'backup': (io.BytesIO(json.dumps(payload).encode('utf-8')), 'backup.vmbak'),
            'admin_password': 'password',
            'backup_password': 'backup-password',
        },
        content_type='multipart/form-data'
    )

    assert response.status_code == 200
    assert Project.query.filter_by(name='Old Project').first() is None
    assert Project.query.filter_by(name='Restored Project').one()
    assert Application.query.filter_by(name='Restored Application').one()
    restored_admin = User.query.filter_by(username='restored-admin').one()
    assert restored_admin.platform_role == PLATFORM_ADMIN
    assert restored_admin.check_password('password')
    restored_member = User.query.filter_by(username='restored-member').one()
    assert restored_member.can_create_projects is True
    assert ProjectMembership.query.filter_by(user_id=restored_member.id).one().project_role == PROJECT_ADMIN
    with client.session_transaction() as sess:
        assert 'user_id' not in sess


def test_admin_import_requires_current_admin_password_before_backup_password(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.post('/api/system/backup/import', json={
        'backup': make_encrypted_backup_payload(),
        'admin_password': 'wrong',
        'backup_password': 'backup-password',
    })

    assert response.status_code == 400
    assert b'Current admin password is incorrect' in response.data
    assert User.query.filter_by(username='admin').one()


def test_admin_import_rejects_wrong_backup_password(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    response = client.post('/api/system/backup/import', json={
        'backup': make_encrypted_backup_payload(),
        'admin_password': 'password',
        'backup_password': 'wrong',
    })

    assert response.status_code == 400
    assert b'Backup password is incorrect' in response.data
    assert User.query.filter_by(username='admin').one()


def test_admin_password_verification_endpoint(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)

    failed_response = client.post('/api/system/verify-admin-password', json={'admin_password': 'wrong'})
    ok_response = client.post('/api/system/verify-admin-password', json={'admin_password': 'password'})

    assert failed_response.status_code == 400
    assert ok_response.status_code == 200


def test_bootstrap_backup_import_allowed_only_when_database_is_empty(client):
    payload = make_encrypted_backup_payload()

    response = client.post('/api/bootstrap/backup/import', json={
        'backup': payload,
        'backup_password': 'backup-password',
        'restore_confirmation': 'RESTORE',
    })

    assert response.status_code == 200
    restored_admin = User.query.filter_by(username='restored-admin').one()
    assert restored_admin.platform_role == PLATFORM_ADMIN
    assert restored_admin.check_password('password')
    assert Application.query.filter_by(name='Restored Application').one()

    blocked_response = client.post('/api/bootstrap/backup/import', json={
        'backup': payload,
        'backup_password': 'backup-password',
        'restore_confirmation': 'RESTORE',
    })

    assert blocked_response.status_code == 403


def test_bootstrap_backup_can_be_verified_before_restore(client):
    response = client.post('/api/bootstrap/backup/verify', json={
        'backup': make_encrypted_backup_payload(),
        'backup_password': 'backup-password',
    })

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['message'] == 'Backup is valid.'
    assert payload['summary']['users'] == 2
    assert payload['summary']['projects'] == 1
    assert payload['summary']['applications'] == 1


def test_bootstrap_backup_import_requires_restore_confirmation(client):
    response = client.post('/api/bootstrap/backup/import', json={
        'backup': make_encrypted_backup_payload(),
        'backup_password': 'backup-password',
    })

    assert response.status_code == 400
    assert b'Type RESTORE' in response.data
    assert User.query.count() == 0


def test_bootstrap_backup_import_rejects_non_empty_database_without_admin(client):
    db.session.add(Project(name='Orphan Project', status='Draft'))
    db.session.commit()

    response = client.post('/api/bootstrap/backup/import', json={
        'backup': make_encrypted_backup_payload(),
        'backup_password': 'backup-password',
        'restore_confirmation': 'RESTORE',
    })

    assert response.status_code == 403
    assert User.query.count() == 0


def test_backup_import_rejects_payload_without_admin(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    login_as(client, admin)
    payload = make_backup_payload()
    payload['data']['users'][0]['platform_role'] = PLATFORM_USER
    encrypted_payload, error = encrypt_backup_payload(payload, 'backup-password')
    assert error is None

    response = client.post('/api/system/backup/import', json={
        'backup': encrypted_payload,
        'admin_password': 'password',
        'backup_password': 'backup-password',
    })

    assert response.status_code == 400
    assert b'at least one admin user' in response.data


def test_deleted_projects_and_applications_are_not_shown_in_user_access(client):
    user = create_user('member')
    project = Project(name='Deleted Access Project', status='Draft')
    app_obj = Application(name='Deleted Access App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add_all([
        Version(application_id=app_obj.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=app_obj.id,
            access_level=ACCESS_VIEW_ONLY,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    db.session.delete(app_obj)
    db.session.delete(project)
    db.session.commit()

    response = client.get('/api/me')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['assigned_projects'] == []
    assert payload['assigned_applications'] == []


def test_user_password_change_requires_current_password(client):
    user = create_user('member')
    login_as(client, user)

    response = client.post('/api/me/password', json={
        'current_password': 'wrong',
        'new_password': 'new-password',
        'password_confirmation': 'new-password',
    })

    assert response.status_code == 400
    assert not User.query.get(user.id).check_password('new-password')


def test_user_can_change_password_with_current_password(client):
    user = create_user('member')
    login_as(client, user)

    response = client.post('/api/me/password', json={
        'current_password': 'password',
        'new_password': 'new-password',
        'password_confirmation': 'new-password',
    })

    assert response.status_code == 200
    assert User.query.get(user.id).check_password('new-password')


def test_application_release_date_uses_user_timezone(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    root.timezone = 'Asia/Baku'
    app_obj = Application(name='Timezone App')
    db.session.add(app_obj)
    db.session.flush()
    db.session.add(Version(
        application_id=app_obj.id,
        number='1.0.0',
        change_date=datetime(2026, 1, 1, 22, 30)
    ))
    db.session.commit()
    login_as(client, root)

    response = client.get('/get_applications_data')

    assert response.status_code == 200
    payload = response.get_json()[0]
    assert payload['change_date'] == '2026-01-02'
    assert payload['change_datetime'].startswith('2026-01-02 02:30')


def test_application_release_date_uses_user_datetime_format(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    root.timezone = 'Asia/Baku'
    root.datetime_format = 'eu_numeric_24'
    app_obj = Application(name='Formatted App')
    db.session.add(app_obj)
    db.session.flush()
    db.session.add(Version(
        application_id=app_obj.id,
        number='1.0.0',
        change_date=datetime(2026, 1, 1, 22, 30)
    ))
    db.session.commit()
    login_as(client, root)

    response = client.get('/get_applications_data')

    assert response.status_code == 200
    payload = response.get_json()[0]
    assert payload['change_date'] == '02/01/2026'
    assert payload['change_datetime'] == '02/01/2026 02:30'


def test_project_start_date_uses_user_timezone(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    root.timezone = 'Asia/Baku'
    project = Project(
        name='Timezone Project',
        status='Draft',
        start_date=datetime(2026, 1, 1, 22, 30)
    )
    db.session.add(project)
    db.session.commit()
    login_as(client, root)

    response = client.get('/get_projects_data')

    assert response.status_code == 200
    assert response.get_json()['projects'][0]['start_date'] == '2026-01-02'


def test_project_start_date_uses_user_datetime_format(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    root.timezone = 'Asia/Baku'
    root.datetime_format = 'eu_numeric_24'
    project = Project(
        name='Formatted Project',
        status='Draft',
        start_date=datetime(2026, 1, 1, 22, 30)
    )
    db.session.add(project)
    db.session.commit()
    login_as(client, root)

    response = client.get('/get_projects_data')

    assert response.status_code == 200
    assert response.get_json()['projects'][0]['start_date'] == '02/01/2026'


def test_regular_user_cannot_create_project(client):
    user = create_user('member')
    login_as(client, user)

    response = client.post('/create_project', json={
        'name': 'User Project',
        'description': '',
        'source_link': '',
        'status': 'Draft',
        'applications': [],
    })

    assert response.status_code == 403
    assert Project.query.filter_by(name='User Project').first() is None


def test_regular_user_projects_page_hides_new_project_button(client):
    user = create_user('member')
    login_as(client, user)

    response = client.get('/content/projects')

    assert response.status_code == 200
    assert b'<button onclick="openNewProjectModal()"' not in response.data


def test_read_only_user_applications_page_hides_new_application_button(client):
    user = create_user('member')
    project = Project(name='Read Only Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_USER,
        access_level=ACCESS_VIEW_ONLY,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.get('/content/applications')

    assert response.status_code == 200
    assert b'onclick="openModal()"' not in response.data


def test_read_write_user_applications_page_shows_new_application_button(client):
    user = create_user('member')
    project = Project(name='Writable Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.get('/content/applications')

    assert response.status_code == 200
    assert b'onclick="openModal()"' in response.data


def test_read_only_user_can_view_application_but_cannot_edit_details(client):
    user = create_user('member')
    project = Project(name='Read Only Project', status='Draft')
    app_obj = Application(name='Read Only App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add_all([
        Version(application_id=app_obj.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=app_obj.id,
            access_level=ACCESS_VIEW_ONLY,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    details_response = client.get(f'/content/application_details/{app_obj.id}')
    edit_response = client.post(f'/edit_application/{app_obj.id}', json={
        'name': 'Renamed App',
        'link': '',
        'project_id': project.id,
    })

    assert details_response.status_code == 200
    assert b'Access level:</strong> Read-Only' in details_response.data
    assert b'id="editAppModal"' not in details_response.data
    assert f'openEditAppModal({app_obj.id})'.encode() not in details_response.data
    assert f'deleteApplication({app_obj.id})'.encode() not in details_response.data
    assert edit_response.status_code == 403
    assert Application.query.get(app_obj.id).name == 'Read Only App'


def test_read_write_user_application_details_show_edit_controls_and_access(client):
    user = create_user('member')
    project = Project(name='Writable Project', status='Draft')
    app_obj = Application(name='Writable Details App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add_all([
        Version(application_id=app_obj.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=app_obj.id,
            access_level=ACCESS_READ_WRITE,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    response = client.get(f'/content/application_details/{app_obj.id}')

    assert response.status_code == 200
    assert b'Access level:</strong> Read Write' in response.data
    assert b'id="editAppModal"' in response.data
    assert f'openEditAppModal({app_obj.id})'.encode() in response.data
    assert f'deleteApplication({app_obj.id})'.encode() in response.data


def test_read_write_user_api_cannot_change_project_from_edit_modal(client):
    user = create_user('member')
    project = Project(name='Writable Project', status='Draft')
    app_obj = Application(name='Writable Modal App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_USER,
        access_level=ACCESS_VIEW_ONLY,
    ))
    db.session.add(ApplicationMembership(
        user_id=user.id,
        application_id=app_obj.id,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.get(f'/api/application/{app_obj.id}')

    assert response.status_code == 200
    assert response.get_json()['can_change_project'] is False


def test_super_admin_api_can_change_project_from_edit_modal(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    project = Project(name='Project A', status='Draft')
    app_obj = Application(name='System Admin Modal App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.commit()
    login_as(client, root)

    response = client.get(f'/api/application/{app_obj.id}')

    assert response.status_code == 200
    assert response.get_json()['can_change_project'] is True


def test_read_write_user_can_create_application_for_assigned_project(client):
    user = create_user('member')
    project = Project(name='Writable Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.post('/create_application', json={
        'name': 'Writable App',
        'link': '',
        'label': '',
        'project_ids': [project.id],
    })

    assert response.status_code == 201
    assert Application.query.filter_by(name='Writable App').one()


def test_read_write_user_can_edit_application_link_and_label(client):
    user = create_user('member')
    project = Project(name='Writable Project', status='Draft')
    app_obj = Application(name='Writable App', link='https://old.example.com', label='old')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_USER,
        access_level=ACCESS_VIEW_ONLY,
    ))
    db.session.add(ApplicationMembership(
        user_id=user.id,
        application_id=app_obj.id,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.post(f'/edit_application/{app_obj.id}', json={
        'name': 'Writable App',
        'link': 'https://new.example.com',
        'label': 'new-label',
    })

    assert response.status_code == 200
    updated = Application.query.get(app_obj.id)
    assert updated.link == 'https://new.example.com'
    assert updated.label == 'new-label'
    assert updated.projects[0].id == project.id


def test_read_write_user_cannot_change_application_project(client):
    user = create_user('member')
    original_project = Project(name='Original Project', status='Draft')
    other_project = Project(name='Other Project', status='Draft')
    app_obj = Application(name='Writable App')
    app_obj.projects.append(original_project)
    db.session.add_all([original_project, other_project, app_obj])
    db.session.flush()
    db.session.add_all([
        ProjectMembership(
            user_id=user.id,
            project_id=original_project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_READ_WRITE,
        ),
        ProjectMembership(
            user_id=user.id,
            project_id=other_project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_READ_WRITE,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    response = client.post(f'/edit_application/{app_obj.id}', json={
        'name': 'Writable App',
        'link': '',
        'label': '',
        'project_id': other_project.id,
    })

    assert response.status_code == 403
    assert Application.query.get(app_obj.id).projects[0].id == original_project.id


def test_project_and_application_data_include_access_codes(client):
    user = create_user('member')
    read_only_project = Project(name='Read Only Project', status='Draft')
    writable_project = Project(name='Writable Project', status='Draft')
    read_only_app = Application(name='Read Only App')
    writable_app = Application(name='Writable App')
    read_only_app.projects.append(read_only_project)
    writable_app.projects.append(writable_project)
    db.session.add_all([read_only_project, writable_project, read_only_app, writable_app])
    db.session.flush()
    db.session.add_all([
        Version(application_id=read_only_app.id, number='1.0.0'),
        Version(application_id=writable_app.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=read_only_project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ProjectMembership(
            user_id=user.id,
            project_id=writable_project.id,
            project_role=PROJECT_ADMIN,
            access_level=ACCESS_READ_WRITE,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=read_only_app.id,
            access_level=ACCESS_VIEW_ONLY,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    projects_response = client.get('/get_projects_data')
    applications_response = client.get('/get_applications_data')

    assert projects_response.status_code == 200
    assert applications_response.status_code == 200
    project_access = {item['name']: item for item in projects_response.get_json()['projects']}
    application_access = {item['name']: item for item in applications_response.get_json()}
    assert project_access['Read Only Project']['access_code'] == 'RO'
    assert project_access['Read Only Project']['can_edit'] is False
    assert project_access['Writable Project']['access_code'] == 'RW'
    assert project_access['Writable Project']['can_edit'] is True
    assert application_access['Read Only App']['access_code'] == 'RO'
    assert application_access['Read Only App']['can_edit'] is False
    assert application_access['Writable App']['access_code'] == 'RW'
    assert application_access['Writable App']['can_edit'] is True


def test_user_can_have_different_application_access_in_same_project(client):
    user = create_user('member')
    project = Project(name='Mixed Access Project', status='Draft')
    read_only_app = Application(name='Mixed Read Only App')
    writable_app = Application(name='Mixed Writable App')
    read_only_app.projects.append(project)
    writable_app.projects.append(project)
    db.session.add_all([project, read_only_app, writable_app])
    db.session.flush()
    db.session.add_all([
        Version(application_id=read_only_app.id, number='1.0.0'),
        Version(application_id=writable_app.id, number='1.0.0'),
        ProjectMembership(
            user_id=user.id,
            project_id=project.id,
            project_role=PROJECT_USER,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=read_only_app.id,
            access_level=ACCESS_VIEW_ONLY,
        ),
        ApplicationMembership(
            user_id=user.id,
            application_id=writable_app.id,
            access_level=ACCESS_READ_WRITE,
        ),
    ])
    db.session.commit()
    login_as(client, user)

    applications_response = client.get('/get_applications_data')
    edit_read_only_response = client.post(f'/edit_application/{read_only_app.id}', json={
        'name': 'Mixed Read Only App',
        'link': 'https://readonly.example.com',
        'label': 'ro',
    })
    edit_writable_response = client.post(f'/edit_application/{writable_app.id}', json={
        'name': 'Mixed Writable App',
        'link': 'https://rw.example.com',
        'label': 'rw',
    })

    assert applications_response.status_code == 200
    app_access = {item['name']: item for item in applications_response.get_json()}
    assert app_access['Mixed Read Only App']['access_code'] == 'RO'
    assert app_access['Mixed Read Only App']['can_edit'] is False
    assert app_access['Mixed Writable App']['access_code'] == 'RW'
    assert app_access['Mixed Writable App']['can_edit'] is True
    assert edit_read_only_response.status_code == 403
    assert edit_writable_response.status_code == 200
    assert Application.query.get(writable_app.id).link == 'https://rw.example.com'


def test_bulk_application_membership_assignment_supports_mixed_access(client):
    supervisor = create_user('supervisor', PLATFORM_ADMIN)
    target = create_user('member')
    project = Project(name='Bulk Mixed Project', status='Draft')
    read_only_app = Application(name='Bulk Read Only App')
    writable_app = Application(name='Bulk Writable App')
    read_only_app.projects.append(project)
    writable_app.projects.append(project)
    db.session.add_all([project, read_only_app, writable_app])
    db.session.flush()
    db.session.add(ProjectMembership(
        user_id=supervisor.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, supervisor)

    response = client.post('/api/application_memberships/bulk', json={
        'project_id': project.id,
        'user_ids': [target.id],
        'applications': [
            {'application_id': read_only_app.id, 'access_level': ACCESS_VIEW_ONLY},
            {'application_id': writable_app.id, 'access_level': ACCESS_READ_WRITE},
        ],
    })

    assert response.status_code == 200
    project_membership = ProjectMembership.query.filter_by(user_id=target.id, project_id=project.id).one()
    read_only_membership = ApplicationMembership.query.filter_by(user_id=target.id, application_id=read_only_app.id).one()
    writable_membership = ApplicationMembership.query.filter_by(user_id=target.id, application_id=writable_app.id).one()
    assert project_membership.project_role == PROJECT_USER
    assert project_membership.access_level == ACCESS_VIEW_ONLY
    assert read_only_membership.access_level == ACCESS_VIEW_ONLY
    assert writable_membership.access_level == ACCESS_READ_WRITE


def test_admin_can_create_update_and_delete_application_membership(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    target = create_user('operator')
    project = Project(name='Single Application Access Project', status='Draft')
    app_obj = Application(name='Single Access App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.commit()
    login_as(client, admin)

    create_response = client.post('/api/application_memberships', json={
        'user_id': target.id,
        'project_id': project.id,
        'application_id': app_obj.id,
        'access_level': ACCESS_VIEW_ONLY,
    })

    assert create_response.status_code == 201
    membership = ApplicationMembership.query.filter_by(user_id=target.id, application_id=app_obj.id).one()
    assert membership.access_level == ACCESS_VIEW_ONLY

    update_response = client.put(f'/api/application_memberships/{membership.id}', json={
        'project_id': project.id,
        'access_level': ACCESS_READ_WRITE,
    })

    assert update_response.status_code == 200
    assert ApplicationMembership.query.get(membership.id).access_level == ACCESS_READ_WRITE

    delete_response = client.delete(f'/api/application_memberships/{membership.id}')

    assert delete_response.status_code == 200
    assert ApplicationMembership.query.get(membership.id) is None


def test_project_admin_can_create_application_membership_for_own_project(client):
    actor = create_user('project-admin')
    target = create_user('operator')
    project = Project(name='Delegated Application Access Project', status='Draft')
    app_obj = Application(name='Delegated Access App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add(ProjectMembership(
        user_id=actor.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, actor)

    response = client.post('/api/application_memberships', json={
        'user_id': target.id,
        'project_id': project.id,
        'application_id': app_obj.id,
        'access_level': ACCESS_NO_ACCESS,
    })

    assert response.status_code == 201
    membership = ApplicationMembership.query.filter_by(user_id=target.id, application_id=app_obj.id).one()
    assert membership.access_level == ACCESS_NO_ACCESS


def test_admin_can_disable_user_and_details_show_status(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    target = create_user('member')
    login_as(client, root)

    status_response = client.put(f'/api/users/{target.id}/status', json={'is_active': False})
    details_response = client.get(f'/api/users/{target.id}')

    assert status_response.status_code == 200
    assert details_response.status_code == 200
    assert User.query.get(target.id).is_active is False
    assert status_response.get_json()['status'] == 'Disabled'
    assert details_response.get_json()['status'] == 'Disabled'


def test_user_project_details_are_plain_access_without_project_edit(client):
    user = create_user('member')
    project = Project(name='Read Only Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_USER,
        access_level=ACCESS_VIEW_ONLY,
    ))
    db.session.commit()
    login_as(client, user)

    response = client.get(f'/project/{project.id}')

    assert response.status_code == 200
    project_data = response.get_json()
    assert project_data['access_label'] == 'Read-Only'
    assert project_data['access_code'] == 'RO'
    assert project_data['can_edit'] is False


def test_enabled_user_can_create_project_and_is_auto_assigned_manager(client):
    user = create_user('builder')
    user.can_create_projects = True
    db.session.commit()
    login_as(client, user)

    response = client.post('/create_project', json={
        'name': 'Builder Created Project',
        'description': '',
        'source_link': '',
        'status': 'Draft',
        'applications': [],
    })

    assert response.status_code == 201
    project = Project.query.filter_by(name='Builder Created Project').one()
    membership = ProjectMembership.query.filter_by(user_id=user.id, project_id=project.id).one()
    assert membership.project_role == PROJECT_ADMIN
    assert membership.access_level == ACCESS_READ_WRITE


def test_project_creator_manager_can_edit_and_delete_assigned_project(client):
    user = create_user('builder')
    user.can_create_projects = True
    project = Project(name='Managed Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=user.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, user)

    edit_response = client.post(f'/edit_project/{project.id}', json={
        'name': 'Manager Renamed Project',
        'description': 'Updated',
        'source_link': '',
        'status': 'In Progress',
    })
    delete_response = client.delete(f'/delete_project/{project.id}')

    assert edit_response.status_code == 200
    assert delete_response.status_code == 200
    assert Project.query.get(project.id) is None


def test_admin_has_platform_wide_rw_access_to_applications(client):
    admin = create_user('admin', PLATFORM_ADMIN)
    project = Project(name='Admin Project', status='Draft')
    app_obj = Application(name='Admin App')
    app_obj.projects.append(project)
    db.session.add_all([project, app_obj])
    db.session.flush()
    db.session.add_all([
        Version(application_id=app_obj.id, number='1.0.0'),
    ])
    db.session.commit()
    login_as(client, admin)

    applications_response = client.get('/get_applications_data')
    details_response = client.get(f'/content/application_details/{app_obj.id}')
    project_response = client.get('/get_projects_data')

    assert applications_response.status_code == 200
    assert details_response.status_code == 200
    assert project_response.status_code == 200
    app_data = applications_response.get_json()[0]
    project_data = project_response.get_json()['projects'][0]
    assert app_data['access_code'] == 'RW'
    assert app_data['can_edit'] is True
    assert project_data['access_code'] == 'RW'
    assert project_data['can_edit'] is True
    assert b'Access level:</strong> Read Write' in details_response.data
    assert f'openEditAppModal({app_obj.id})'.encode() in details_response.data
    assert f'deleteApplication({app_obj.id})'.encode() in details_response.data


def test_operator_can_have_different_application_access_within_same_project(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    operator = create_user('operator')
    project = Project(name='Mixed Access Project', status='Draft')
    app_ro = Application(name='Read Only App')
    app_rw = Application(name='Read Write App')
    app_none = Application(name='Hidden App')
    app_ro.projects.append(project)
    app_rw.projects.append(project)
    app_none.projects.append(project)
    db.session.add_all([project, app_ro, app_rw, app_none])
    db.session.commit()
    login_as(client, root)

    response = client.post('/api/application_memberships/bulk', json={
        'project_id': project.id,
        'project_role': PROJECT_USER,
        'user_ids': [operator.id],
        'applications': [
            {'application_id': app_ro.id, 'access_level': ACCESS_VIEW_ONLY},
            {'application_id': app_rw.id, 'access_level': ACCESS_READ_WRITE},
            {'application_id': app_none.id, 'access_level': 'no_access'},
        ],
    })

    assert response.status_code == 200
    project_membership = ProjectMembership.query.filter_by(user_id=operator.id, project_id=project.id).one()
    assert project_membership.project_role == PROJECT_USER
    assert project_membership.access_level == ACCESS_VIEW_ONLY

    memberships = {
        membership.application_id: membership.access_level
        for membership in ApplicationMembership.query.filter_by(user_id=operator.id).all()
    }
    assert memberships[app_ro.id] == ACCESS_VIEW_ONLY
    assert memberships[app_rw.id] == ACCESS_READ_WRITE
    assert memberships[app_none.id] == 'no_access'


def test_operator_only_sees_applications_with_explicit_access_inside_project(client):
    root = create_user('root', PLATFORM_SUPER_ADMIN)
    operator = create_user('operator')
    project = Project(name='Operator Project', status='Draft')
    visible_app = Application(name='Visible App')
    hidden_app = Application(name='Hidden App')
    visible_app.projects.append(project)
    hidden_app.projects.append(project)
    db.session.add_all([project, visible_app, hidden_app])
    db.session.flush()
    db.session.add_all([
        Version(application_id=visible_app.id, number='1.0.0'),
        Version(application_id=hidden_app.id, number='1.0.0'),
    ])
    db.session.commit()
    login_as(client, root)

    assignment_response = client.post('/api/application_memberships/bulk', json={
        'project_id': project.id,
        'project_role': PROJECT_USER,
        'user_ids': [operator.id],
        'applications': [
            {'application_id': visible_app.id, 'access_level': ACCESS_VIEW_ONLY},
            {'application_id': hidden_app.id, 'access_level': 'no_access'},
        ],
    })

    assert assignment_response.status_code == 200

    login_as(client, operator)
    applications_response = client.get('/get_applications_data')
    visible_details = client.get(f'/content/application_details/{visible_app.id}')
    hidden_details = client.get(f'/content/application_details/{hidden_app.id}')

    assert applications_response.status_code == 200
    assert [item['name'] for item in applications_response.get_json()] == ['Visible App']
    assert visible_details.status_code == 200
    assert hidden_details.status_code == 403


def test_admin_cannot_be_assigned_to_project_membership(client):
    root = create_user('root', PLATFORM_ADMIN)
    admin = create_user('other-admin', PLATFORM_ADMIN)
    project = Project(name='Admin Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    login_as(client, root)

    response = client.post('/api/project_memberships', json={
        'user_id': admin.id,
        'project_id': project.id,
        'project_role': PROJECT_USER,
        'access_level': ACCESS_VIEW_ONLY,
    })

    assert response.status_code == 400
    assert ProjectMembership.query.filter_by(user_id=admin.id, project_id=project.id).first() is None


def test_manager_can_manage_memberships_in_assigned_project(client):
    manager = create_user('manager')
    target = create_user('member')
    project = Project(name='Managed Project', status='Draft')
    db.session.add(project)
    db.session.commit()
    db.session.add(ProjectMembership(
        user_id=manager.id,
        project_id=project.id,
        project_role=PROJECT_ADMIN,
        access_level=ACCESS_READ_WRITE,
    ))
    db.session.commit()
    login_as(client, manager)

    response = client.post('/api/project_memberships', json={
        'user_id': target.id,
        'project_id': project.id,
        'project_role': PROJECT_USER,
        'access_level': ACCESS_READ_WRITE,
    })

    assert response.status_code == 201
    membership = ProjectMembership.query.filter_by(user_id=target.id, project_id=project.id).one()
    assert membership.project_role == PROJECT_USER
    assert membership.access_level == ACCESS_VIEW_ONLY
