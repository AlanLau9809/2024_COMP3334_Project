import os
from dotenv import load_dotenv  # load environment variables from .env file
from app import create_app, db
from app.models import User, File, FileShare, AuditLog  # import models to ensure they are registered with SQLAlchemy
from flask_login import LoginManager

# load environment variables from .env file if it exists
# load_dotenv()

# create flask app
app = create_app()

# initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # when user is not logged in, redirect to this view

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    return User.query.get(int(user_id))

# CLI command to create database tables
@app.cli.command('init-db')
def init_db():

    with app.app_context():
        db.create_all()
    print("Database tables created!")

if __name__ == '__main__':
    # enable debug mode only if not in production
    app.run(
        host='0.0.0.0',  # allow access from any IP address
        port=5000,
        debug=True       # debug=True will enable auto-reload and better error messages
    )