from flask import render_template, Flask, request, redirect
import os
import infinc
import SampleNetworkClient
import sqlite3
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

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
        act_token = db_result[2]
        return True, act_token
    return False, ''


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else:
        conn = get_db_connection()
        password = request.form.get('authToken')
        is_password, act_token = verify_password(conn, password)

        if is_password:
            snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
            is_auth = snc.authenticate(23456, bytes(act_token, 'utf-8'))
            return render_template('authenticate.html', Temp="0.00", Token=is_auth.decode('utf-8'))
        else:
            try:
                db_message = ''
                db_query = "SELECT * FROM users WHERE password = '" + password + "'" 
                db_password = conn.execute(db_query).fetchone()
                for x in db_password:
                    db_message = db_message + ":" + str(x)
                return render_template('login.html', Err=str(db_message))
            except Exception as ex:
                return render_template('login.html', Err=ex)
            return render_template('login.html', Err="Wrong password")


@app.route('/get_temp', methods=['POST'])
def start_infinc():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_c', methods=['POST'])
def set_temp_c():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureC(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_f', methods=['POST'])
def set_temp_f():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureF(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_k', methods=['POST'])
def set_temp_k():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureK(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)