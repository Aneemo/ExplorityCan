import secrets
import datetime
import sqlite3
import bcrypt
import csv
import io
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session,
    g, current_app, send_from_directory, jsonify, Response
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from functools import wraps

from .db import get_db_connection
from .models import User
from .utils import save_file, send_email

bp = Blueprint('routes', __name__)

# --- Decorators ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You must be an admin to view this page.", "error")
            return redirect(url_for('routes.index'))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if not api_key:
            return jsonify({'message': 'API key is missing'}), 401

        conn = get_db_connection()
        key_data = conn.execute('SELECT * FROM api_keys WHERE key = ?', (api_key,)).fetchone()
        
        if not key_data:
            conn.close()
            return jsonify({'message': 'Invalid API key'}), 401

        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (key_data['user_id'],)).fetchone()
        conn.close()

        if not user_data:
            return jsonify({'message': 'User associated with API key not found'}), 401

        g.current_user = user_data
        g.api_role = key_data['role']

        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    users_with_keys = conn.execute('''
        SELECT
            u.id,
            u.username,
            u.role,
            k.key,
            k.role as api_key_role
        FROM
            users u
        LEFT JOIN
            api_keys k ON u.id = k.user_id
        ORDER BY
            u.username
    ''').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users_with_keys)

@bp.route('/admin/download_user_report')
@login_required
@admin_required
def download_user_report():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role FROM users ORDER BY id').fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Email', 'Role'])
    for user in users:
        writer.writerow([user['id'], user['username'], user['email'], user['role']])
    output.seek(0)
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=user_report.csv"}
    )

@bp.route('/admin/promote', methods=['POST'])
@login_required
@admin_required
def promote_users():
    user_ids_to_promote = request.form.getlist('user_ids')
    if not user_ids_to_promote:
        flash("No users selected for promotion.", "warning")
        return redirect(url_for('routes.admin_dashboard'))

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        placeholders = ', '.join('?' for _ in user_ids_to_promote)
        query = f"UPDATE users SET role = 'admin' WHERE id IN ({placeholders})"
        cur.execute(query, user_ids_to_promote)
        conn.commit()
        flash(f"Successfully promoted {len(user_ids_to_promote)} user(s).", "success")
    except sqlite3.Error as e:
        flash("Failed to promote users due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('routes.admin_dashboard'))

@bp.route('/admin/generate_api_key', methods=['POST'])
@login_required
@admin_required
def generate_api_key():
    user_id = request.form.get('user_id')
    api_role = request.form.get('api_role')

    if not user_id or not api_role:
        flash("User ID and API role are required.", "error")
        return redirect(url_for('routes.admin_dashboard'))

    new_key = secrets.token_hex(32)
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM api_keys WHERE user_id = ?", (user_id,))
        existing_key = cur.fetchone()

        if existing_key:
            cur.execute("UPDATE api_keys SET key = ?, role = ? WHERE user_id = ?", (new_key, api_role, user_id))
            flash("API key updated successfully.", "success")
        else:
            cur.execute("INSERT INTO api_keys (user_id, key, role) VALUES (?, ?, ?)", (user_id, new_key, api_role))
            flash("API key generated successfully.", "success")
        conn.commit()
    except sqlite3.Error as e:
        flash("Failed to generate API key due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('routes.admin_dashboard'))

@bp.route('/')
@login_required
def index():
    conn = get_db_connection()
    contacts_data = []
    try:
        cur = conn.cursor()
        if current_user.role == 'admin':
            sql_query = "SELECT * FROM contacts ORDER BY name"
            cur.execute(sql_query)
        else:
            sql_query = "SELECT * FROM contacts WHERE user_id = ? ORDER BY name"
            cur.execute(sql_query, (current_user.id,))
        contacts_data = cur.fetchall()
    except sqlite3.Error as e:
        print(f"Database error in index route: {e}")
    finally:
        if conn:
            conn.close()
    return render_template('index.html', contacts=contacts_data)

@bp.route('/add_contact', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form.get('email')
        phone = request.form.get('phone')
        passport_number = request.form.get('passport_number')
        drivers_license_number = request.form.get('drivers_license_number')
        medicare_number = request.form.get('medicare_number')
        interest = request.form.get('interest')

        passport_file = request.files.get('passport_file')
        drivers_license_file = request.files.get('drivers_license_file')
        medicare_file = request.files.get('medicare_file')

        passport_filename = save_file(passport_file)
        drivers_license_filename = save_file(drivers_license_file)
        medicare_filename = save_file(medicare_file)

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO contacts (name, email, phone, interest, passport_number, drivers_license_number, medicare_number, user_id,
                                      passport_filename, drivers_license_filename, medicare_filename)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, email, phone, interest, passport_number, drivers_license_number, medicare_number, current_user.id,
                  passport_filename, drivers_license_filename, medicare_filename))
            conn.commit()
            flash("Contact added successfully.", "success")
        except sqlite3.Error as e:
            flash("Failed to add contact due to a database error.", "error")
        finally:
            if conn:
                conn.close()
        return redirect(url_for('routes.index'))
    return render_template('add_contact.html')

@bp.route('/view/<int:contact_id>')
@login_required
def view_contact(contact_id):
    conn = get_db_connection()
    contact = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    if contact:
        if current_user.role == 'user' and contact['user_id'] != current_user.id:
            flash("You are not authorized to view this contact.", "error")
            return redirect(url_for('routes.index'))
        return render_template('view_contact.html', contact=contact)
    else:
        flash("Contact not found.", "error")
        return redirect(url_for('routes.index'))

@bp.route('/edit/<int:contact_id>', methods=['GET'])
@login_required
def edit_contact(contact_id):
    conn = get_db_connection()
    contact = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    if contact:
        if current_user.role == 'user' and contact['user_id'] != current_user.id:
            flash("You are not authorized to edit this contact.", "error")
            return redirect(url_for('routes.index'))
        return render_template('edit_contact.html', contact=contact)
    else:
        return "Contact not found", 404

@bp.route('/update/<int:contact_id>', methods=['POST'])
@login_required
def update_contact(contact_id):
    name = request.form['name']
    email = request.form.get('email')
    phone = request.form.get('phone')
    interest = request.form.get('interest')
    passport_number = request.form.get('passport_number')
    drivers_license_number = request.form.get('drivers_license_number')
    medicare_number = request.form.get('medicare_number')

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        contact = cur.fetchone()

        if not contact:
            flash("Contact not found.", "error")
            return redirect(url_for('routes.index'))

        if current_user.role == 'user' and contact['user_id'] != current_user.id:
            flash("You are not authorized to update this contact.", "error")
            return redirect(url_for('routes.index'))
            
        passport_filename = contact['passport_filename']
        if 'passport_file' in request.files and request.files['passport_file'].filename != '':
            passport_filename = save_file(request.files['passport_file'])

        drivers_license_filename = contact['drivers_license_filename']
        if 'drivers_license_file' in request.files and request.files['drivers_license_file'].filename != '':
            drivers_license_filename = save_file(request.files['drivers_license_file'])
            
        medicare_filename = contact['medicare_filename']
        if 'medicare_file' in request.files and request.files['medicare_file'].filename != '':
            medicare_filename = save_file(request.files['medicare_file'])

        cur.execute("""
            UPDATE contacts 
            SET name = ?, email = ?, phone = ?, interest = ?,
                passport_number = ?, drivers_license_number = ?, medicare_number = ?,
                passport_filename = ?, drivers_license_filename = ?, medicare_filename = ?
            WHERE id = ?
        """, (name, email, phone, interest, passport_number, drivers_license_number, medicare_number,
              passport_filename, drivers_license_filename, medicare_filename, contact_id))
        conn.commit()
        flash("Contact updated successfully.", "success")
    except sqlite3.Error as e:
        flash("Failed to update contact due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('routes.view_contact', contact_id=contact_id))

@bp.route('/delete/<int:contact_id>', methods=['POST'])
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
        flash("Failed to delete contact due to a database error.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for('routes.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('routes.register'))

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                flash('Username already exists.', 'error')
                conn.close()
                return redirect(url_for('routes.register'))

            cur.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash('Email address already registered.', 'error')
                conn.close()
                return redirect(url_for('routes.register'))
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (username, email, hashed_password))
            conn.commit()
            
            send_email(email, 'Welcome to ExplorityCan!', 'email/welcome', username=username)
            
            flash('Registration successful! Please check your email and login.', 'success')
            return redirect(url_for('routes.login'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('routes.register'))
        finally:
            if conn:
                conn.close()
    return render_template('register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cur.fetchone()
        
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
            mfa_code = secrets.token_hex(3).upper()
            expires_at = datetime.datetime.now() + datetime.timedelta(minutes=10)
            
            cur.execute("UPDATE users SET mfa_code = ?, mfa_code_expires_at = ? WHERE id = ?",
                        (mfa_code, expires_at, user_data['id']))
            conn.commit()
            conn.close()

            send_email(user_data['email'], 'Your Login Code', 'email/mfa_code', code=mfa_code)
            
            session['mfa_user_id'] = user_data['id']
            
            flash('Login successful, please check your email for your authentication code.', 'info')
            return redirect(url_for('routes.login_mfa'))
        else:
            conn.close()
            flash('Invalid username or password.', 'error')
            return redirect(url_for('routes.login'))
    return render_template('login.html')

@bp.route('/login/mfa', methods=['GET', 'POST'])
def login_mfa():
    if 'mfa_user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('routes.login'))
    
    if request.method == 'POST':
        user_id = session['mfa_user_id']
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        submitted_code = request.form.get('mfa_code').upper()
        
        if (user_data and user_data['mfa_code'] == submitted_code and
            datetime.datetime.now() <= datetime.datetime.strptime(user_data['mfa_code_expires_at'], '%Y-%m-%d %H:%M:%S.%f')):
            
            user = User(id=user_data['id'], username=user_data['username'], email=user_data['email'], password_hash=user_data['password_hash'], role=user_data['role'])
            login_user(user)
            
            conn.execute("UPDATE users SET mfa_code = NULL, mfa_code_expires_at = NULL WHERE id = ?", (user_id,))
            conn.commit()
            session.pop('mfa_user_id', None)
            
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            conn.close()
            return redirect(next_page or url_for('routes.index'))
        else:
            conn.close()
            flash('Invalid or expired authentication code.', 'error')
            return redirect(url_for('routes.login_mfa'))
            
    return render_template('login_mfa.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('routes.login'))

@bp.route("/reset_password_request", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('routes.index'))
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user_data:
            user = User(id=user_data['id'], username=user_data['username'], email=user_data['email'], password_hash=user_data['password_hash'], role=user_data['role'])
            token = user.get_reset_token()
            send_email(user.email, 'Password Reset Request',
                       'email/reset_password',
                       user=user, token=token)
        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('routes.login'))
    return render_template('reset_password_request.html')

@bp.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('routes.index'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('routes.reset_password_request'))
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_token.html')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user.id))
            conn.commit()
            flash('Your password has been updated! You are now able to log in.', 'success')
            return redirect(url_for('routes.login'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('routes.reset_password_request'))
        finally:
            if conn:
                conn.close()
    return render_template('reset_token.html')

@bp.route('/uploads/<path:filename>')
@login_required
def download_file(filename):
    conn = get_db_connection()
    contact = conn.execute(
        'SELECT * FROM contacts WHERE passport_filename = ? OR drivers_license_filename = ? OR medicare_filename = ?',
        (filename, filename, filename)
    ).fetchone()
    conn.close()

    if not contact:
        return "File not found.", 404

    if current_user.role != 'admin' and contact['user_id'] != current_user.id:
        return "You are not authorized to access this file.", 403

    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# --- API Endpoints ---

def contact_to_dict(contact_row):
    if not contact_row:
        return None
    return {
        'id': contact_row['id'],
        'name': contact_row['name'],
        'email': contact_row['email'],
        'phone': contact_row['phone'],
        'interest': contact_row['interest'],
        'passport_number': contact_row['passport_number'],
        'drivers_license_number': contact_row['drivers_license_number'],
        'medicare_number': contact_row['medicare_number'],
        'user_id': contact_row['user_id']
    }

@bp.route('/api/contacts', methods=['GET'])
@api_key_required
def get_contacts():
    conn = get_db_connection()
    if g.api_role == 'admin':
        contacts_rows = conn.execute('SELECT * FROM contacts ORDER BY name').fetchall()
    else:
        contacts_rows = conn.execute('SELECT * FROM contacts WHERE user_id = ? ORDER BY name', (g.current_user['id'],)).fetchall()
    conn.close()
    contacts = [contact_to_dict(row) for row in contacts_rows]
    return jsonify(contacts)

@bp.route('/api/contacts/<int:contact_id>', methods=['GET'])
@api_key_required
def get_contact(contact_id):
    conn = get_db_connection()
    contact_row = conn.execute('SELECT * FROM contacts WHERE id = ?', (contact_id,)).fetchone()
    conn.close()

    if not contact_row:
        return jsonify({'message': 'Contact not found'}), 404

    if g.api_role == 'user' and contact_row['user_id'] != g.current_user['id']:
        return jsonify({'message': 'Forbidden'}), 403

    return jsonify(contact_to_dict(contact_row))

@bp.route('/api/contacts', methods=['POST'])
@api_key_required
def create_contact():
    if not request.json or not 'name' in request.json:
        return jsonify({'message': 'Missing required field: name'}), 400

    data = request.get_json()
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO contacts (name, email, phone, interest, passport_number, drivers_license_number, medicare_number, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['name'], data.get('email'), data.get('phone'), data.get('interest'),
            data.get('passport_number'), data.get('drivers_license_number'),
            data.get('medicare_number'), g.current_user['id']
        ))
        conn.commit()
        new_contact_id = cur.lastrowid
        new_contact_row = conn.execute('SELECT * FROM contacts WHERE id = ?', (new_contact_id,)).fetchone()
        conn.close()
        return jsonify(contact_to_dict(new_contact_row)), 201
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'message': f'Database error: {e}'}), 500

@bp.route('/api/contacts/<int:contact_id>', methods=['PUT'])
@api_key_required
def update_api_contact(contact_id):
    conn = get_db_connection()
    contact_row = conn.execute('SELECT * FROM contacts WHERE id = ?', (contact_id,)).fetchone()

    if not contact_row:
        conn.close()
        return jsonify({'message': 'Contact not found'}), 404

    if g.api_role == 'user' and contact_row['user_id'] != g.current_user['id']:
        conn.close()
        return jsonify({'message': 'Forbidden'}), 403

    if not request.json:
        conn.close()
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    name = data.get('name', contact_row['name'])
    email = data.get('email', contact_row['email'])
    phone = data.get('phone', contact_row['phone'])
    interest = data.get('interest', contact_row['interest'])
    passport_number = data.get('passport_number', contact_row['passport_number'])
    drivers_license_number = data.get('drivers_license_number', contact_row['drivers_license_number'])
    medicare_number = data.get('medicare_number', contact_row['medicare_number'])

    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE contacts
            SET name = ?, email = ?, phone = ?, interest = ?, passport_number = ?, drivers_license_number = ?, medicare_number = ?
            WHERE id = ?
        """, (name, email, phone, interest, passport_number, drivers_license_number, medicare_number, contact_id))
        conn.commit()
        updated_contact_row = conn.execute('SELECT * FROM contacts WHERE id = ?', (contact_id,)).fetchone()
        conn.close()
        return jsonify(contact_to_dict(updated_contact_row))
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'message': f'Database error: {e}'}), 500

@bp.route('/api/contacts/<int:contact_id>', methods=['DELETE'])
@api_key_required
def delete_api_contact(contact_id):
    conn = get_db_connection()
    contact_row = conn.execute('SELECT * FROM contacts WHERE id = ?', (contact_id,)).fetchone()

    if not contact_row:
        conn.close()
        return jsonify({'message': 'Contact not found'}), 404

    if g.api_role == 'user' and contact_row['user_id'] != g.current_user['id']:
        conn.close()
        return jsonify({'message': 'Forbidden'}), 403

    try:
        conn.execute('DELETE FROM contacts WHERE id = ?', (contact_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Contact deleted successfully'}), 200
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'message': f'Database error: {e}'}), 500

@bp.route('/help')
def help_page():
    return render_template('help.html')