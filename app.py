import sqlite3
import click
from flask import Flask, render_template, request, redirect, url_for

DATABASE = 'contacts.db'

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True)