from flask import Flask
import os


def create_app():
    flask_app = Flask(__name__)
    flask_app.config['SECRET_KEY'] = os.urandom(32)
    flask_app.config['SESSION_TYPE'] = 'filesystem'
    flask_app.config['SESSION_COOKIE_SECURE'] = True
    flask_app.config['SESSION_COOKIE_HTTPONLY'] = True
    flask_app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    flask_app.app_context().push()
    
    return flask_app