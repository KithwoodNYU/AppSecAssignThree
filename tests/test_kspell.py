import pytest
from .. import create_app
from ..app import app

@pytest.fixture
def client():
    app.config['DEBUG'] = True
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        yield client


# def db(app):
#     from demo import db
#     with app.app_context():
#         db.create_all()
#         yield db
#         db.drop_all()
#         db.session.commit()

def test_registration(client):
    response = client.get('/register')
    #print(response.data)
    assert response.status_code == 200
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Two factor" in response.data

    response = client.post('/register', data = dict({'username':'Harold', 'password':'Blankenship', 'phone2fa':'12345'}), follow_redirects=True)
    
    assert b"success" in response.data

def test_invalid_login_user(client):
    response = client.get('/login')
    #print(response.data)
    assert response.status_code == 200
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Two factor" in response.data

    response = client.post('/login', data = dict({'username':'Billy', 'password':'Badash', 'phone2fa':'12345'}), follow_redirects=True)
    
    assert b"Incorrect" in response.data

def test_invalid_login_2fa(client):
    response = client.get('/login')
    #print(response.data)
    assert response.status_code == 200
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Two factor" in response.data

    response = client.post('/login', data = dict({'username':'Harold', 'password':'Blankenship', 'phone2fa':'8383838'}), follow_redirects=True)
    
    assert b"failure" in response.data

def test_login(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Two factor" in response.data

    response = client.post('/login', data = dict({'username':'Harold', 'password':'Blankenship', 'phone2fa':'12345'}), follow_redirects=True)
    
    assert b"success" in response.data

def test_spellcheck(client):
    test_login(client) # have to login first
    response = client.get('/spell_check')
    assert response.status_code == 200
    assert b"Input Text" in response.data

    response = client.post('/spell_check', data = dict({'inputtext':'Here is my input text and I lyke it'}), follow_redirects=True)
    
    assert b"lyke" in response.data
    assert b"Misspelled" in response.data