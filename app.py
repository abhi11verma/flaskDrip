import os
import json
import datetime

from flask import Flask, url_for, redirect, \
    render_template, session, request
from flask.ext.sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
import base64   
from apiclient import errors
from apiclient.discovery import build

basedir = os.path.abspath(os.path.dirname(__file__))

class Auth:
    """Google Project Credentials"""
    CLIENT_ID = ('277221696598-s7qbeuqfpj9u0ghkc0tqd2v3t23ksfcl.apps.googleusercontent.com')
    CLIENT_SECRET = 'TYrqMTwgCoH-1fJLRBFXAtix'
    REDIRECT_URI = 'https://127.0.0.1:5000/loginsuccess'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']


class Config:
    """Base config"""
    APP_NAME = "Test Google Login"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"
class DevConfig(Config):
    """Dev config"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/drip'

config = {
    "dev": DevConfig,
    "default": DevConfig
}


"""APP creation and configuration"""
app = Flask(__name__)
app.config.from_object(config['dev'])
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


#========================================================================================
""" DB Models """
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())

class Campaign(db.Model, ):
    __tablename__ = "campaign"
    campaign_id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable = False)
    campaign_title = db.Column(db.String(140))
    campaign_stage = db.Column(db.Integer)
    email_subj = db.Column(db.String(250))
    email_body = db.Column(db.Text)
    email_id = db.Column(db.String(100))
    receipent_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    def __init__(self, userid,campaign_title,campaign_stage,email_subj, email_body, email_id, receipent_name):
        self.userid = userid
        self.campaign_title = campaign_title
        self.campaign_stage = campaign_stage
        self.email_subj = email_subj
        self.email_body = email_body
        self.email_id = email_id
        self.receipent_name = receipent_name

class CampaignContact(db.Model):
    __tablename__ = "campaign_contact"
    contact_id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable = False)
    campaign_id = db.Column(db.Integer, nullable = False)
    email_id = db.Column(db.String(100))
    receipent_name = db.Column(db.String(100))

#========================================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth


@app.route('/')
@login_required #if user is not logged in go to login page
def index():
    campaignlist = Campaign.query.filter_by(userid = current_user.id)
    return render_template('createcampaign.html' , campaignlist = campaignlist)

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)



@app.route('/loginsuccess')
def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        google = get_google_auth(state = session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']

            #Check if user already exist using email id
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'

@app.route('/CreateNewCampaign', methods = ['POST'])
def CreateNewCampaign():
    campaign = Campaign(request.form['userid'],request.form['campaign_title'], request.form['campaign_stages'],request.form['email_subj'],request.form['email_body'],request.form['email_id'],request.form['receipent_name'])
    db.session.add(campaign)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))