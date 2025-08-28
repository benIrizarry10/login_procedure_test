from flask import Flask, render_template, request, redirect, url_for, session, flash

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import random
import string
import time

app = Flask(__name__)
app.secret_key = 'supersecretkey'

ph = PasswordHasher()
user_db = {}
login_attempts = {}
messages = {}

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 30

def generate_salt(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encrypt(text, shift):
    final_result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            final_result += chr((ord(char) - start + shift) % 26 + start)
        else:
            final_result += char
    return final_result

def decrypt(text, shift):
    return encrypt(text, -shift)

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in user_db:
            return "User already exists"
        if len(password) < 6:
            return "Password too short!"
        salt = generate_salt()
        hashed = ph.hash(password + salt)
        user_db[username] = {'hash': hashed, 'salt': salt}
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        now = time.time()
        attempts = login_attempts.get(username, {'count': 0, 'time': 0})

        if attempts['count'] >= MAX_ATTEMPTS and now - attempts['time'] < LOCKOUT_TIME:
            return "Account locked. Try again later."

        user = user_db.get(username)
        if not user:
            return "User not found"

        try:
            ph.verify(user['hash'], password + user['salt'])
            mfa = request.form.get('mfa')
            if mfa != '123456':
                return "MFA failed"
            session['user'] = username
            login_attempts[username] = {'count': 0, 'time': now}
            return redirect(url_for('index'))
        except VerifyMismatchError:
            login_attempts[username] = {
                'count': attempts['count'] + 1,
                'time': now
            }
            return "Incorrect password"

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_pass = request.form['new_password']
        if len(new_pass) < 6:
            return "Password too short!"
        salt = generate_salt()
        hashed = ph.hash(new_pass + salt)
        user_db[session['user']] = {'hash': hashed, 'salt': salt}
        return render_template('reset.html', success=True)

    return render_template('reset.html')


@app.route('/send', methods=['GET', 'POST'])
def send():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        to = request.form['to']
        msg = request.form['message']
        if to not in user_db:
            return "User does not exist"
        encrypted = encrypt(msg, 4)
        messages[to] = {'message': encrypted, 'sender': session['user']}
        # render success page
        return render_template('send.html', success=True)

    return render_template('send.html')

@app.route('/inbox')
def inbox():
    if 'user' not in session:
        return redirect(url_for('login'))
    message_data = messages.pop(session['user'], None)
    if message_data:
        decrypted = decrypt(message_data['message'], 4)
        return render_template('inbox.html', sender=message_data['sender'], message=decrypted)
    return render_template('inbox.html', sender=None, message=None)

if __name__ == '__main__':
    app.run(debug=True)
