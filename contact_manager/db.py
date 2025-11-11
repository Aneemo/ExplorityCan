import sqlite3
import click
from flask import current_app, g
from flask.cli import with_appcontext

def get_db_connection():
    """Establishes a connection to the database."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Closes the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(commit_changes=True):
    """Initializes the database schema."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute('DROP TABLE IF EXISTS contacts')
        cur.execute('DROP TABLE IF EXISTS api_keys')
        cur.execute('DROP TABLE IF EXISTS users')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                mfa_code TEXT,
                mfa_code_expires_at DATETIME
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                interest TEXT,
                passport_number TEXT,
                drivers_license_number TEXT,
                medicare_number TEXT,
                passport_filename TEXT,
                drivers_license_filename TEXT,
                medicare_filename TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        if commit_changes:
            conn.commit()
    finally:
        conn.close()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initializes the database."""
    init_db()
    click.echo('Initialized the database.')

@click.command('promote-user')
@click.argument('username')
@with_appcontext
def promote_user_command(username):
    """Promotes a user to the admin role."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, role FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if not user:
            click.echo(f"User {username} not found.")
            return
        if user['role'] == 'admin':
            click.echo(f"User {username} is already an admin.")
            return

        cur.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user['id'],))
        conn.commit()
        click.echo(f"User {username} has been promoted to admin.")
    except sqlite3.Error as e:
        click.echo(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def init_app(app):
    """Register database functions with the Flask app."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(promote_user_command)