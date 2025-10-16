import os
import secrets
from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from .models import User  # This will be created later

# Base directory of the instance folder for the app
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
db_path = os.path.join(basedir, 'contacts.db')
upload_folder_path = os.path.join(basedir, 'uploads')

# Initialize extensions
login_manager = LoginManager()
mail = Mail()

def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Load configuration
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(16),
        DATABASE=db_path,
        UPLOAD_FOLDER=upload_folder_path,
        # Flask-Mail configuration, assuming a local debug server
        MAIL_SERVER='localhost',
        MAIL_PORT=8025,
        MAIL_USE_TLS=False,
        MAIL_USE_SSL=False,
        MAIL_USERNAME=None,
        MAIL_PASSWORD=None,
        MAIL_DEFAULT_SENDER=('ExplorityCan Support', 'noreply@exploritycan.com')
    )

    # Initialize extensions with app
    login_manager.init_app(app)
    mail.init_app(app)

    # Configure login manager
    login_manager.login_view = 'routes.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        # User loading logic will be handled here, likely from the database
        # This is a placeholder until the db logic is moved.
        from .db import get_db_connection
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], email=user_data['email'], password_hash=user_data['password_hash'], role=user_data['role'])
        return None

    # Register blueprints
    from . import routes
    app.register_blueprint(routes.bp)

    # Register CLI commands
    from . import db
    app.cli.add_command(db.init_db_command)
    app.cli.add_command(db.promote_user_command)

    return app