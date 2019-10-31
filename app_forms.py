from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, HiddenField, IntegerField, FormField, FieldList, validators

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

class QueryForm(FlaskForm):
    query = StringField('Query Result', render_kw={'readonly': True}, id='')

class HistoryForm(FlaskForm):
    total_queries = IntegerField('Total Queries', render_kw={'readonly': True}, id='numqueries')
    queries = FieldList(FormField(QueryForm, min_entries = 0))

class HistoryQueryForm(FlaskForm):
    query_id = IntegerField('Query ID', render_kw={'readonly': True}, id='queryid')
    uname = StringField('Username', render_kw={'readonly': True}, id='username')
    inputtext = TextAreaField('Input Text', id='querytext')
    outputtext = TextAreaField('Misspelled Words', id='queryresults')

class LoginHistoryForm(FlaskForm):
    user_id = IntegerField('User ID', id='userid')



    