import sqlite3
import click
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt

DATABASE = 'contacts.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a real secret key

login_manager = LoginManager()
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
        # Add users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
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
        # Create placeholders for SQL query to prevent injection
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
            print(f"DEBUG APP.PY (Admin): Executing query: {sql_query}") # DEBUG
            cur.execute(sql_query)
        else: # Regular user
            sql_query = "SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number, user_id FROM contacts WHERE user_id = ? ORDER BY name"
            print(f"DEBUG APP.PY (User): Executing query: {sql_query} with user_id: {current_user.id}") # DEBUG
            cur.execute(sql_query, (current_user.id,))
        contacts_data = cur.fetchall()
        
        # ---- START DEBUG PRINT IN APP.PY ----
        if contacts_data:
            # Ensure all keys are present if you are accessing them directly, especially user_id
            # For example, convert to dict to be safe if structure varies
            first_contact_dict = dict(contacts_data[0])
            print(f"DEBUG APP.PY: First contact raw data from fetchall: {first_contact_dict}")
            print(f"DEBUG APP.PY: Keys in first contact: {list(first_contact_dict.keys())}")
        else:
            print("DEBUG APP.PY: No contacts found in database by index route for current user/admin.")
        # ---- END DEBUG PRINT IN APP.PY ----

    except sqlite3.Error as e:
        print(f"Database error in index route: {e}")
    except IndexError:
        print("DEBUG APP.PY: contacts_data is empty, cannot access contacts_data[0].") # Handle empty list
    finally:
        if conn:
            conn.close()
    
    return render_template('index.html', contacts=contacts_data)

@app.route('/add_contact', methods=['POST'])
@login_required
def add_contact():
    name = request.form['name']
    email = request.form.get('email') # Use .get() for optional fields
    phone = request.form.get('phone') # Use .get() for optional fields
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
        print(f"Database error: {e}") # For now, just print the error
        # Later, you might want to flash a message to the user
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
        # Fetch user_id along with other contact details
        cur.execute("SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number, user_id FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    if contact:
        # Authorization check
        if current_user.role == 'user' and contact['user_id'] != current_user.id:
            flash("You are not authorized to edit this contact.", "error")
            return redirect(url_for('index')) # Or a 403 page: abort(403)
        return render_template('edit_contact.html', contact=contact)
    else:
        return "Contact not found", 404

@app.route('/update/<int:contact_id>', methods=['POST'])
@login_required
def update_contact(contact_id):
    name = request.form['name'] # Name is required
    email = request.form.get('email')
    phone = request.form.get('phone')
    passport_number = request.form.get('passport_number')
    drivers_license_number = request.form.get('drivers_license_number')
    medicare_number = request.form.get('medicare_number')

    conn = get_db_connection()
    try:
        cur = conn.cursor()

        # First, verify ownership or admin role
        cur.execute("SELECT user_id FROM contacts WHERE id = ?", (contact_id,))
        contact_to_update = cur.fetchone()

        if not contact_to_update:
            flash("Contact not found.", "error")
            return redirect(url_for('index')) # Or 404

        if current_user.role == 'user' and contact_to_update['user_id'] != current_user.id:
            flash("You are not authorized to update this contact.", "error")
            # abort(403) # For API-like behavior
            return redirect(url_for('index')) # For web app behavior

        # If authorized, proceed with update
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
            # Admin can delete any contact
            cur.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
            # Check if any row was affected to see if contact existed
            if cur.rowcount == 0:
                flash("Contact not found or already deleted.", "error")
            else:
                flash("Contact deleted successfully by admin.", "success")
        else:
            # User can only delete their own contacts
            cur.execute("DELETE FROM contacts WHERE id = ? AND user_id = ?", (contact_id, current_user.id))
            # Check if any row was affected
            if cur.rowcount == 0:
                # This could mean contact not found OR not owned by user
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

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already exists.', 'error')
                conn.close()
                return redirect(url_for('register'))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            # Role will be handled by DB default or later step in RBAC plan
            cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
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