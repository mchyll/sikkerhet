import hashlib
import os
import sqlite3

HASH_ALG = 'sha512'
SALT_LEN = 32
ITERATIONS = 100000

tokens = {}


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
    # print('salt:', salt)
    # print('hash:', hash)

    c.execute('INSERT INTO users(username, password_hash, password_salt) '
              'VALUES (?, ?, ?)', (username, hash, salt))
    db.commit()
    c.close()
    db.close()


def check_password_match(username, in_password):
    user = get_user_password_and_hash(username)
    if not user:
        return False

    user_salt = bytes.fromhex(user['password_salt'])
    in_hash = hashlib.pbkdf2_hmac(HASH_ALG, in_password.encode('utf-8'), user_salt, ITERATIONS).hex()
    # print('in_hash:', in_hash)
    return in_hash == user['password_hash']


def gen_session_token(username, len_bytes=64):
    token = os.urandom(len_bytes).hex()
    tokens[token] = username
    return token


def get_session(token):
    return tokens.get(token, None)


if __name__ == '__main__':
    # register_user('hyll', '1234')
    print(check_password_match('hyll', '1234'))
    token = gen_session_token('hyll')
    print(token, get_session(token))
