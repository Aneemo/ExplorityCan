import sqlite3
import click
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt

DATABASE = 'contacts.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a real secret key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # The route to redirect to for login

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = cur.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
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
                medicare_number TEXT
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
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

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    contacts_data = [] # Use a different variable name temporarily
    try:
        cur = conn.cursor()
        sql_query = "SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number FROM contacts ORDER BY name"
        print(f"DEBUG APP.PY: Executing query: {sql_query}") # DEBUG
        cur.execute(sql_query)
        contacts_data = cur.fetchall()
        
        # ---- START DEBUG PRINT IN APP.PY ----
        if contacts_data:
            print(f"DEBUG APP.PY: First contact raw data from fetchall: {dict(contacts_data[0])}")
            print(f"DEBUG APP.PY: Keys in first contact: {list(contacts_data[0].keys())}")
        else:
            print("DEBUG APP.PY: No contacts found in database by index route.")
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
            INSERT INTO contacts (name, email, phone, passport_number, drivers_license_number, medicare_number)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, email, phone, passport_number, drivers_license_number, medicare_number))
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
        cur.execute("SELECT id, name, email, phone, passport_number, drivers_license_number, medicare_number FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    if contact:
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
        cur.execute("""
            UPDATE contacts 
            SET name = ?, email = ?, phone = ?, 
                passport_number = ?, drivers_license_number = ?, medicare_number = ? 
            WHERE id = ?
        """, (name, email, phone, passport_number, drivers_license_number, medicare_number, contact_id))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during update: {e}")
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
        cur.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during delete: {e}")
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
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cur.fetchone()
        conn.close()
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
            user_obj = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
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