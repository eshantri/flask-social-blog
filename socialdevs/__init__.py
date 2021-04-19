from flask import Flask, url_for, redirect
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail, Message

app = Flask(__name__)

app.config.from_pyfile('config.cfg')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['SECRET_KEY'] = secrets.token_hex(256)
app.config['SECURITY_PASSWORD_SALT'] = secrets.token_hex(256)
db = SQLAlchemy(app)
mail = Mail(app)
from socialdevs import routes