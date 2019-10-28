from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, HiddenField, validators

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[validators.Length(min=4, max=25), validators.DataRequired()], id='uname')
    password = PasswordField('Password', validators=[validators.Length(min=8, max=25), validators.DataRequired()], id='pword')
    phone2fa = StringField('Two factor phone number', id='2fa')



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()], id='uname')
    password = PasswordField('Password', validators=[validators.DataRequired()], id='pword')
    phone2fa = StringField('Two factor phone number', id='2fa')


class SpellCheckForm(FlaskForm):
    inputtext = TextAreaField('Input Text', validators=[validators.DataRequired()], id='inputtext')

class SpellCheckResultsForm(FlaskForm):
    inputtext = TextAreaField('Input Text', id='textout')
    misspelled = TextAreaField('Misspelled Words', id='mispelled')



    