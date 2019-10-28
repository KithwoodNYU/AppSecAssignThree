from flask import Flask, render_template, redirect, url_for, session, flash, request, make_response
from flask_session import Session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, validators
import re
import os
import subprocess
from datetime import datetime
from . import app_forms
from . import create_app

app = create_app()
SECRET_KEY = os.urandom(32)
csrf = CSRFProtect(app)
Session(app)

registration_info = []
logged_in_user = []

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
    if len(registration_info) == 0:
        return redirect('/register'), 302, headers
    elif len(logged_in_user) == 0:
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
                user = {}
                user['username'] = form.username.data
                user['password'] = form.password.data
                user['twofactor'] = form.phone2fa.data
                registration_info.append(user)
                flash('Registration was a success', 'success')
                return redirect(url_for('login')), 302, headers
            else:
                flash('Registration was a faulure', 'success')
        r = CreateResponse(render_template('register.html', form=form))
        
        return r
    except Exception as e:
        r = CreateResponse(str(e), 500)
          
        return r

@app.route('/login', methods=['GET', 'POST'])
def login():
    #if len(registration_info) == 0:
    #    return redirect('/register')
    try:
        form = app_forms.LoginForm(request.form)

        if request.method == 'POST' and form.validate_on_submit():
            logged_in_user.clear()
            user = {}
            user['username'] = form.username.data
            user['password'] = form.password.data
            user['twofactor'] = form.phone2fa.data
            validation = validate_user(user)
            if validation == validate_success:
                logged_in_user.append(user)
                flash('Login was a success', 'result')
            elif validation == validate_login:
                flash('Incorrect username or password', 'result')
            else:
                flash('Two-factor authentication failure', 'result')

            return redirect(url_for('spell_check')), 302, headers
    except Exception as e:
        r = CreateResponse(str(e), 500)
           
        return r

    r = CreateResponse(render_template('login.html', form=form))
     
    return r

def validate_user(user):
    validation_result = validate_login
    for registered_user in registration_info:
        if user['username'] == registered_user['username']:
            if user['password'] == registered_user['password']:
                if user['twofactor'] == registered_user['twofactor']:
                    validation_result = validate_success
                    return validation_result
                else:
                    validation_result = validate_2fa
            else:
                validation_result = validate_login
        else:
            validation_result = validate_login
    
    return validation_result

@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if len(registration_info) == 0:
        return redirect('/register'), 302, headers
    elif len(logged_in_user) == 0:
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
    if len(registration_info) == 0:
        return redirect('/register'), 302, headers
    elif len(logged_in_user) == 0:
        return redirect(url_for('login')), 302, headers

    try:
        form = app_forms.SpellCheckResultsForm(request.form)

        if request.method == 'POST' and form.validate_on_submit():
            return redirect(url_for('spell_check')), 302, headers

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