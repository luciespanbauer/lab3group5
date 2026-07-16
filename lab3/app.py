import atexit
import hmac
import os
import sqlite3
import threading
from hashlib import sha256

from Crypto.Cipher import AES
from flask import Flask, render_template, request, session

import SampleNetworkClient
from secure_transport import (
    PROTOCOL_VERSION,
    PacketError,
    decrypt_packet,
    encrypt_packet,
    load_auth_password,
    load_transport_key,
)

app = Flask(__name__)

# Fail during Flask startup when required security configuration is absent.
_transport_key = load_transport_key()
_auth_password = load_auth_password()
app.secret_key = hmac.new(
    _transport_key, b"flask-cookie-signing-v1", sha256
).digest()
_browser_token_key = hmac.new(
    _transport_key, b"flask-encrypted-token-v1", sha256
).digest()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("INCUBATOR_COOKIE_SECURE", "0") == "1",
)

_network_client = None
_network_client_lock = threading.Lock()


def get_network_client():
    global _network_client
    with _network_client_lock:
        if _network_client is None:
            _network_client = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
        return _network_client


def close_network_client():
    global _network_client
    with _network_client_lock:
        if _network_client is not None:
            _network_client.close()
            _network_client = None


atexit.register(close_network_client)


def store_browser_token(token):
    """Keep only an encrypted token envelope in the browser session cookie."""
    packet = encrypt_packet(
        {"version": PROTOCOL_VERSION, "type": "FLASK_TOKEN", "token": token},
        _browser_token_key,
    )
    session["incubator_session"] = packet.decode("ascii")


def load_browser_token():
    packet = session.get("incubator_session")
    if not isinstance(packet, str):
        return None
    try:
        payload = decrypt_packet(packet.encode("ascii"), _browser_token_key)
    except (UnicodeEncodeError, PacketError):
        session.clear()
        return None
    if (
        payload.get("version") != PROTOCOL_VERSION
        or payload.get("type") != "FLASK_TOKEN"
        or not isinstance(payload.get("token"), str)
        or not payload["token"]
    ):
        session.clear()
        return None
    return payload["token"]

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Function to encrypt the password using AES encryption
def encrypt_password(password):
    key = bytearray(b'\x93n\x12\xcbC\xe0|\xd0\xa6%7(?KW\xa9\xc2\x02\x97\xc6\\\xd6\xd9c\xf4x\xb9\xe2\x89\x88<\x9d')
    nonce = b'0123456789abcdef'
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return cipher.nonce + tag + ciphertext


# Verify password
def verify_password(conn, user_password):
    db_query = "SELECT * FROM users"
    db_result = conn.execute(db_query).fetchone()
    db_password = db_result[1]
    encrypted_password = encrypt_password(user_password)
    if encrypted_password == db_password:
        return True
    return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else:
        conn = get_db_connection()
        password = request.form.get('password', '')
        is_password = verify_password(conn, password)

        if is_password:
            try:
                token = get_network_client().authenticate(23456, _auth_password)
                session.clear()
                store_browser_token(token)
                return render_template('authenticate.html', Temp="0.00")
            except SampleNetworkClient.NetworkClientError:
                session.clear()
                return render_template(
                    'login.html', Err="Secure incubator authentication failed"
                )
        else:
            try:
                db_message = ''
                db_query = "SELECT * FROM users WHERE password = '" + password + "'" 
                db_password = conn.execute(db_query).fetchone()
                for x in db_password:
                    db_message = db_message + ":" + str(x)
                return render_template('login.html', Err=str(db_message))
            except Exception:
                return render_template('login.html', Err="Wrong password")
            return render_template('login.html', Err="Wrong password")


@app.route('/get_temp', methods=['POST'])
def start_infinc():
    auth_token = load_browser_token()
    if auth_token is None:
        return render_template('login.html', Err="Authentication required"), 401
    try:
        temp = get_network_client().getTemperatureFromPort(23456, auth_token)
    except SampleNetworkClient.NetworkClientError:
        session.clear()
        return render_template('login.html', Err="Session expired"), 401
    return render_template('authenticate.html', Temp=temp)


@app.route('/set_temp_c', methods=['POST'])
def set_temp_c():
    auth_token = load_browser_token()
    if auth_token is None:
        return render_template('login.html', Err="Authentication required"), 401
    try:
        client = get_network_client()
        client.setTemperatureC(23456, auth_token)
        temp = client.getTemperatureFromPort(23456, auth_token)
    except SampleNetworkClient.NetworkClientError:
        session.clear()
        return render_template('login.html', Err="Session expired"), 401
    return render_template('authenticate.html', Temp=temp)


@app.route('/set_temp_f', methods=['POST'])
def set_temp_f():
    auth_token = load_browser_token()
    if auth_token is None:
        return render_template('login.html', Err="Authentication required"), 401
    try:
        client = get_network_client()
        client.setTemperatureF(23456, auth_token)
        temp = client.getTemperatureFromPort(23456, auth_token)
    except SampleNetworkClient.NetworkClientError:
        session.clear()
        return render_template('login.html', Err="Session expired"), 401
    return render_template('authenticate.html', Temp=temp)


@app.route('/set_temp_k', methods=['POST'])
def set_temp_k():
    auth_token = load_browser_token()
    if auth_token is None:
        return render_template('login.html', Err="Authentication required"), 401
    try:
        client = get_network_client()
        client.setTemperatureK(23456, auth_token)
        temp = client.getTemperatureFromPort(23456, auth_token)
    except SampleNetworkClient.NetworkClientError:
        session.clear()
        return render_template('login.html', Err="Session expired"), 401
    return render_template('authenticate.html', Temp=temp)


@app.route('/logout', methods=['POST'])
def logout():
    auth_token = load_browser_token()
    if auth_token is not None:
        try:
            get_network_client().logout(23456, auth_token)
        except SampleNetworkClient.NetworkClientError:
            pass
    session.clear()
    return render_template('login.html')
