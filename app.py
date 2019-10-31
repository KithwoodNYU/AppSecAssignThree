from flask import Flask, render_template, redirect, url_for, session, flash, request, make_response
from flask_session import Session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, validators
from sqlalchemy import create_engine, Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from hashlib import sha256
from secrets import token_hex
from datetime import datetime

import re
import os
import subprocess
from datetime import datetime
from . import app_forms
from . import create_app
from . import setup_db
from . import db_classes


app = create_app()
DBSessionMaker = setup_db()
dbsession = DBSessionMaker()

SECRET_KEY = os.urandom(32)

csrf = CSRFProtect(app)
Session(app)

app_user = []

validate_success = 1
validate_login = 0
validate_2fa = -1
headers = {"Content-Security-Policy":"default-src 'self'",
            "Content-Security-Policy":"frame-ancestors 'none'",
            "Content-Security-Policy":"worker-src 'self'",
            "Content-Security-Policy":"script-src 'self'",
            "Content-Security-Policy":"style-src 'self'",
            "Content-Security-Policy":"img-src 'none'",
            "Content-Security-Policy":"connect-src 'self'",
            "Content-Security-Policy":"font-src 'self'",
            "Content-Security-Policy":"media-src 'self'",
            "Content-Security-Policy":"manifest-src 'self'",
            "Content-Security-Policy":"objec-src 'self'",
            "Content-Security-Policy":"prefetch-src 'self'",
            "X-Content-Type-Options":"nosniff", 
            "X-Frame-Options":"DENY", 
            "X-XSS-Protection":"1; mode=block"}

@app.route('/')
def home():
    if len(app_user) == 0:
        return redirect(url_for('login')), 302, headers
    else:
        return redirect(url_for('spell_check')), 302, headers

@app.route('/set/')
def set():
    session['key'] = 'value'
    return 'ok'

@app.route('/get/')
def get():
    return session.get('key', 'not set')

@app.route('/api/data')
def get_data():
    return app.send_static_file('data.json')

@app.route('/about')
def about():
    r = CreateResponse(render_template('about.html'))

    return r

@app.route('/register', methods=['GET','POST'])
def register():
    try:
        form=app_forms.RegistrationForm(request.form)

        if request.method == 'POST':
            if form.validate_on_submit():

                name = form.username.data
                user_r = dbsession.query(db_classes.User).filter(db_classes.User.uname == name).first()
                if user_r:
                    flash('Username already registered', 'success')
                else:
                    password = form.password.data
                    phone2fa = form.phone2fa.data
                    hasher = sha256()
                    hasher.update(password.encode('utf-8'))
                    salt = token_hex(nbytes=16)
                    hasher.update(salt.encode('utf-8'))
                    pword_store = hasher.hexdigest()
                    user = db_classes.User(uname=name, pword=pword_store, phone2fa=phone2fa, salt=salt)
                    dbsession.add(user)
                    dbsession.commit()
                    flash('Registration was a success', 'success')
                    return redirect(url_for('login')), 302, headers
            else:
                flash('Registration was a failure', 'success')

        r = CreateResponse(render_template('register.html', form=form))
        
        return r
    except Exception as e:
        r = CreateResponse(str(e), 500)
          
        return r

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        form = app_forms.LoginForm(request.form)

        if request.method == 'POST' and form.validate_on_submit():
            if len(app_user) > 0:
                history_record = dbsession.query.filter(db_classes.LoginRecord.user_id == app_user[0].user_id).last()
                if history_record:
                    history_record.logout_time = datetime.now()
                    dbsession.update(history_record)
                    dbsession.commit()
                app_user.clear()

            name = form.username.data
            pword = form.password.data
            phone2fa = form.phone2fa.data

            validation, user_r = validate_user(name, pword, phone2fa)

            if validation == validate_success:
                app_user.append(user_r)
                history_record = db_classes.LoginRecord(user_id = user_r.id, login_time=datetime.now())
                dbsession.add(history_record)
                dbsession.commit()
                flash('Login was a success', 'result')
                return redirect(url_for('spell_check')), 302, headers
            elif validation == validate_login:
                flash('Incorrect username or password', 'result')
            else:
                flash('Two-factor authentication failure', 'result')

            r = CreateResponse(render_template('login.html', form=form))
            return r
    except Exception as e:
        r = CreateResponse(str(e), 500)    
        return r

    r = CreateResponse(render_template('login.html', form=form))
    return r

def validate_user(uname, pword, phone2fa):
    hasher=sha256()
    user_r = dbsession.query(db_classes.User).filter(db_classes.User.uname == uname).first()
    if not user_r:
        return validate_login, None
    salt = user_r.salt
    hasher.update(pword.encode('utf-8'))
    hasher.update(salt.encode('utf-8'))
    password_hash = hasher.hexdigest()
    if not password_hash == user_r.pword:
        return validate_login, None
    
    if not phone2fa == user_r.phone2fa:
        return validate_2fa, None

    return validate_success, user_r

@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if len(app_user) == 0:
        return redirect(url_for('login')), 302, headers

    try:
        form = app_forms.SpellCheckForm(request.form)

        if request.method == 'POST' and form.validate_on_submit():
            lines = form.inputtext.data.split('\n')
            f = open('check_words.txt', 'w')
            f.writelines(lines)
            f.close()

            p = subprocess.run(['./a.out', './check_words.txt', './wordlist.txt'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            msg = '\n'.join(lines)
            sc_form = app_forms.SpellCheckResultsForm()
            sc_form.inputtext.data = msg
            msg = p.stdout.decode('utf-8')
            msg = msg.replace('\n', ', ')
            msg = msg.rstrip(', ')
            
            scresults = db_classes.SpellCheckResults()
            scresults.input = form.inputtext.data
            scresults.output = msg
            scresults.user_id = app_user[0].id
            dbsession.add(scresults)
            dbsession.commit()
            sc_form.misspelled.data = msg
            r = CreateResponse(render_template('sc_results.html', form=sc_form))
            
            return r

    except Exception as e:
        r = CreateResponse(str(e), 500)
        
        return r

    r = CreateResponse(render_template('spell_check.html', form=form))
    
    return r

@app.route('/sc_results', methods=['GET'])
def sc_results():
    if len(app_user) == 0:
        return redirect(url_for('login')), 302, headers

    try:
        form = app_forms.SpellCheckResultsForm(request.form)

    except Exception as e:
        r = CreateResponse(str(e), 500)
         
        return r
    
    r = CreateResponse(render_template('sc_results.html', form=form))
    
    return r

def CreateResponse(resp, status_code = None):
    
    if status_code:
        r = make_response(resp, status_code)
    else:
        r = make_response(resp)
    
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    r.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    r.headers["Content-Security-Policy"] = "worker-src 'self'"
    r.headers["Content-Security-Policy"] = "script-src 'self'"
    r.headers["Content-Security-Policy"] = "style-src 'self'"
    r.headers["Content-Security-Policy"] = "img-src 'none'"
    r.headers["Content-Security-Policy"] = "connect-src 'self'"
    r.headers["Content-Security-Policy"] = "font-src 'self'"
    r.headers["Content-Security-Policy"] = "media-src 'self'"
    r.headers["Content-Security-Policy"] = "manifest-src 'self'"
    r.headers["Content-Security-Policy"] = "objec-src 'self'"
    r.headers["Content-Security-Policy"] = "prefetch-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-XSS-Protection"] = "1; mode=block"

    return r

@app.route('/history', methods=['GET'])
def history():
    if len(app_user) == 0:
        return redirect(url_for('login')), 302, headers

    try:
        form = app_forms.HistoryForm(request.form)
        if app_user[0].uname == 'admin':
            results = dbsession.query(db_classes.SpellCheckResults).all()
        else:    
            results = dbsession.query(db_classes.SpellCheckResults).filter(db_classes.SpellCheckResults.user_id == app_user[0].id).all()
        form.total_queries.data = len(results)
    except Exception as e:
        r = CreateResponse(str(e), 500)
         
        return r
    
    r = CreateResponse(render_template('history.html', form=form, results=results))
    
    return r


@app.route('/history/query<int:id>', methods=['GET'])
def historyquery(id):
    if len(app_user) == 0:
        return redirect(url_for('login')), 302, headers
    
    result = dbsession.query(db_classes.SpellCheckResults).filter(db_classes.SpellCheckResults.id == id).first()
    
    if not result or (app_user[0].uname != 'admin' and app_user[0].id != result.user_id):
        flash('No results', 'result')
        return redirect(url_for('history')), 302, headers

    form = app_forms.HistoryQueryForm(request.form)
    form.query_id.data = id
    form.uname.data = result.user.uname
    form.inputtext.data = result.input
    form.outputtext.data = result.output

    r = CreateResponse(render_template('historyquery.html', form=form))
    
    return r
    