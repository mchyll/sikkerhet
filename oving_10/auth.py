import hashlib
import os
import sqlite3

# Parametre for PBKDF2-hashing på serversiden
HASH_ALG = 'sha512'
SALT_LEN = 32
ITERATIONS = 100000

TOKEN_LEN_BYTES = 64

# Inneholder tokens og tilhørende brukernavn
tokens = {}


def authenticate(username, password):
    """
    Autentiserer et innloggingsforsøk.
    Dersom gyldig genereres og returneres en tilfeldig token som knyttes til brukeren.
    """
    if check_password_match(username, password):
        return generate_session_token(username)
    else:
        return None


def get_user_password_and_hash(username):
    db = sqlite3.connect('users.db')
    db.row_factory = sqlite3.Row
    c = db.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    c.close()
    db.close()
    return user


def register_user(username, password):
    db = sqlite3.connect('users.db')
    c = db.cursor()

    salt = os.urandom(SALT_LEN)
    hash = hashlib.pbkdf2_hmac(HASH_ALG, password.encode('utf-8'), salt, ITERATIONS).hex()
    salt = salt.hex()

    c.execute('INSERT INTO users(username, password_hash, password_salt) '
              'VALUES (?, ?, ?)', (username, hash, salt))
    db.commit()
    c.close()
    db.close()


def check_password_match(username, password):
    user = get_user_password_and_hash(username)
    if not user:
        return False

    user_salt = bytes.fromhex(user['password_salt'])
    hash = hashlib.pbkdf2_hmac(HASH_ALG, password.encode('utf-8'), user_salt, ITERATIONS).hex()
    return hash == user['password_hash']


def generate_session_token(username):
    """
    Genererer og returnerer en ny tilfeldig token som tilhører gitt brukernavn.
    """
    token = os.urandom(TOKEN_LEN_BYTES).hex()
    tokens[token] = username
    return token


def get_session(token):
    return tokens.get(token, None)
