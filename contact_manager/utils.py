import os
import secrets
from werkzeug.utils import secure_filename
from flask import current_app, render_template
from flask_mail import Message
from . import mail

def save_file(file):
    """Saves a file to the upload folder and returns the filename."""
    if not file or file.filename == '':
        return None

    filename = secure_filename(file.filename)
    # To prevent filename collisions, append a random hex
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(filename)
    filename = random_hex + f_ext

    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
    return filename

def send_email(to, subject, template, **kwargs):
    """Sends an email using Flask-Mail."""
    msg = Message(
        subject,
        recipients=[to],
        body=render_template(template + '.txt', **kwargs),
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)