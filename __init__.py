from flask import Flask
from sqlalchemy import create_engine, Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import os

BASE = declarative_base()
DBFILE = "kspell.db"

def create_app():
    flask_app = Flask(__name__)
    flask_app.config['SECRET_KEY'] = os.urandom(32)
    flask_app.config['SESSION_TYPE'] = 'filesystem'
    flask_app.config['SESSION_COOKIE_SECURE'] = True
    flask_app.config['SESSION_COOKIE_HTTPONLY'] = True
    flask_app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    flask_app.app_context().push()
    
    return flask_app


def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}')
    BASE.metadata.bind = engine
    #remove following line before autograder submit
    BASE.metadata.drop_all(engine)
    BASE.metadata.create_all(engine)
    DBSessionMaker = sessionmaker(bind=engine)
    return DBSessionMaker

