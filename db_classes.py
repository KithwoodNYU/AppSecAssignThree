from sqlalchemy import create_engine, Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

BASE = declarative_base()

class User(BASE):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    phone2fa = Column(String(16), nullable=True)
    salt = Column(String(16), nullable=False)

class LoginRecord(BASE):
    __tablename__ = 'login_history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    login_time = Column(DateTime, nullable=False)
    logout_time = Column(DateTime, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship(User)

class SpellCheckResults(BASE):
    __tablename__ = 'spellcheck_results'
    id = Column(Integer, primary_key=True, autoincrement=True)
    input = Column(String, nullable=False)
    output = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship(User)