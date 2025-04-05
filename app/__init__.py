from flask import Flask
from flask_login import LoginManager
from .models import db
import os

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    app.config.update(
        SESSION_COOKIE_SECURE=True,    # HTTPS only
        SESSION_COOKIE_HTTPONLY=True,  # advoid XSS
        SESSION_COOKIE_SAMESITE='Lax', # CSRF protection
        PERMANENT_SESSION_LIFETIME=1800  # 30mins session lifetime
    )
    
    # Generate a secure Secret Key
    app.config['SECRET_KEY'] = os.urandom(24)  # Or manually set a complex string
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/online_storage'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # for upload file
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'secure_uploads')
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    
    # Initialize the extension
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
     # Register the blueprint
    from app.routes import auth, main  # Must be imported here to avoid circular dependencies
    app.register_blueprint(auth)
    app.register_blueprint(main)
    
    with app.app_context():
        db.create_all()
    
    return app