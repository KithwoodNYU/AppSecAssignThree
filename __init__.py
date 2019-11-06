from flask import Flask
from sqlalchemy import create_engine, Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import os
from . import db_classes
from hashlib import sha256
from secrets import token_hex
from datetime import datetime

BASE = db_classes.BASE
DBFILE = "kspell.db"

def create_app():
    flask_app = Flask(__name__)
    flask_app.config['SECRET_KEY'] = os.urandom(32)
    flask_app.config['SESSION_TYPE'] = 'filesystem'
    #remove SESSION_COOKIE_SECURE to test using in private browsing
    
    #flask_app.config['SESSION_COOKIE_SECURE'] = True
    #flask_app.config['SESSION_COOKIE_HTTPONLY'] = True
    #flask_app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    flask_app.app_context().push()
    
    return flask_app


def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}', connect_args={'check_same_thread': False})

    BASE.metadata.bind = engine
    #remove following line before autograder submit
    #BASE.metadata.drop_all(engine)
    BASE.metadata.create_all(engine)
    DBSessionMaker = sessionmaker(bind=engine)
    create_default_admin(DBSessionMaker)
    return DBSessionMaker

def create_default_admin(DBSessionMaker):
    session = DBSessionMaker()
    user_r = session.query(db_classes.User).filter(db_classes.User.uname == 'admin').first()
    if user_r == None:
        pword = 'Administrator@1'
        hasher = sha256()
        hasher.update(pword.encode('utf-8'))
        salt = token_hex(nbytes=16)
        hasher.update(salt.encode('utf-8'))
        pword_store = hasher.hexdigest()
        user = db_classes.User(uname='admin', pword=pword_store, phone2fa='12345678901', salt=salt)
        session.add(user)
        session.commit()

