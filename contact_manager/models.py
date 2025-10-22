from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role='user'):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        from .db import get_db_connection
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], email=user_data['email'], password_hash=user_data['password_hash'], role=user_data['role'])
        return None