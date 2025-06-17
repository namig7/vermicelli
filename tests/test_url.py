import os
import sys

# Ensure repository root is on sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Set minimal environment before importing main
os.environ['JWT_SECRET_KEY'] = 'test'
os.environ['SECRET_KEY'] = 'test'
os.environ['SESSION_TYPE'] = 'filesystem'
os.environ['DB_ENGINE'] = 'sqlite'
os.environ['DB'] = 'testdb'
os.environ['USERS'] = 'test:testpass'

from main import is_valid_url, app, db

import pytest

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()

def test_is_valid_url():
    assert is_valid_url('http://example.com')
    assert is_valid_url('https://example.com')
    assert not is_valid_url('ftp://example.com')
    assert is_valid_url('')

def test_login_api(client):
    response = client.post('/api/login', json={'username': 'test', 'password': 'testpass'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'access_token' in json_data
