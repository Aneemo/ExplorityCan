import sqlite3
import click
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
import bcrypt

DATABASE = 'contacts.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a real secret key

# Flask-Mail configuration for local debug server
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@exploritycan.com'

mail = Mail(app)
login_manager = LoginManager()

def send_email(to, subject, template, **kwargs):
    """
    Sends an email using Flask-Mail.
    NOTE: For a production app, this should be made asynchronous.
    """
    msg = Message(
        subject,
        recipients=[to],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = render_template(template + '.txt', **kwargs)
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

login_manager.init_app(app)
login_manager.login_view = 'login'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, role FROM users WHERE id = ?", (user_id,))
    user_data = cur.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], role=user_data['role'])
    return None

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(commit_changes=True):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                passport_number TEXT,
                drivers_license_number TEXT,
                medicare_number TEXT,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            );
        ''')
        if commit_changes:
            conn.commit()
    finally:
        conn.close()

@app.cli.command('init-db')
@click.command('init-db') # Ensure this decorator is also present for the command to be registered correctly
def init_db_command():
    """Initializes the database."""
    init_db()
    click.echo('Initialized the database.')

@app.cli.command('promote-user')
@click.argument('username')
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

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/promote', methods=['POST'])
@login_required
@admin_required
def promote_users():
    user_ids_to_promote = request.form.getlist('user_ids')
    if not user_ids_to_promote:
        flash("No users selected for promotion.", "warning")
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        placeholders = ', '.join('?' for _ in user_ids_to_promote)
        query = f"UPDATE users SET role = 'admin' WHERE id IN ({placeholders})"
        
        cur.execute(query, user_ids_to_promote)
        conn.commit()
        
        flash(f"Successfully promoted {len(user_ids_to_promote)} user(s).", "success")
    except sqlite3.Error as e:
        print(f"Database error during promotion: {e}")
        flash("Failed to promote users due to a database error.", "error")
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('admin_dashboard'))

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    contacts_data = []
    try:
        cur = conn.cursor()
        if current_user.role == 'admin':
            sql_query = "SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number, user_id FROM contacts ORDER BY name"
            cur.execute(sql_query)
        else: # Regular user
            sql_query = "SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number, user_id FROM contacts WHERE user_id = ? ORDER BY name"
            cur.execute(sql_query, (current_user.id,))
        contacts_data = cur.fetchall()
    except sqlite3.Error as e:
        print(f"Database error in index route: {e}")
    finally:
        if conn:
            conn.close()
    
    return render_template('index.html', contacts=contacts_data)

@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    name = request.form['name']
    email = request.form.get('email')
    phone = request.form.get('phone')
    passport_number = request.form.get('passport_number')
    drivers_license_number = request.form.get('drivers_license_number')
    medicare_number = request.form.get('medicare_number')

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO contacts (name, email, phone, passport_number, drivers_license_number, medicare_number, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, email, phone, passport_number, drivers_license_number, medicare_number, current_user.id))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('index'))

@app.route('/edit/<int:contact_id>', methods=['GET'])
@login_required
def edit_contact(contact_id):
    conn = get_db_connection()
    contact = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number, user_id FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    if contact:
        if current_user.role == 'user' and contact['user_id'] != current_user.id:
            flash("You are not authorized to edit this contact.", "error")
            return redirect(url_for('index'))
        return render_template('edit_contact.html', contact=contact)
    else:
        return "Contact not found", 404

@app.route('/update/<int:contact_id>', methods=['POST'])
@login_required
def update_contact(contact_id):
    name = request.form['name']
    email = request.form.get('email')
    phone = request.form.get('phone')
    passport_number = request.form.get('passport_number')
    drivers_license_number = request.form.get('drivers_license_number')
    medicare_number = request.form.get('medicare_number')

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM contacts WHERE id = ?", (contact_id,))
        contact_to_update = cur.fetchone()

        if not contact_to_update:
            flash("Contact not found.", "error")
            return redirect(url_for('index'))

        if current_user.role == 'user' and contact_to_update['user_id'] != current_user.id:
            flash("You are not authorized to update this contact.", "error")
            return redirect(url_for('index'))

        cur.execute("""
            UPDATE contacts 
            SET name = ?, email = ?, phone = ?, 
                passport_number = ?, drivers_license_number = ?, medicare_number = ? 
            WHERE id = ?
        """, (name, email, phone, passport_number, drivers_license_number, medicare_number, contact_id))
        conn.commit()
        flash("Contact updated successfully.", "success")
    except sqlite3.Error as e:
        print(f"Database error during update: {e}")
        flash("Failed to update contact due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('index'))

@app.route('/delete/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        if current_user.role == 'admin':
            cur.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
            if cur.rowcount == 0:
                flash("Contact not found or already deleted.", "error")
            else:
                flash("Contact deleted successfully by admin.", "success")
        else:
            cur.execute("DELETE FROM contacts WHERE id = ? AND user_id = ?", (contact_id, current_user.id))
            if cur.rowcount == 0:
                flash("Contact not found or you are not authorized to delete it.", "error")
            else:
                flash("Contact deleted successfully.", "success")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during delete: {e}")
        flash("Failed to delete contact due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already exists.', 'error')
                conn.close()
                return redirect(url_for('register'))

            cur.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email address already registered.', 'error')
                conn.close()
                return redirect(url_for('register'))
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (username, email, hashed_password))
            conn.commit()
            
            send_email(email, 'Welcome to ExplorityCan!', 'email/welcome', username=username)
            
            flash('Registration successful! Please check your email and login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('register'))
        finally:
            if conn:
                conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        user_data = cur.fetchone()
        conn.close()
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
            user_obj = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], role=user_data['role'])
            login_user(user_obj)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)