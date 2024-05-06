'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''
from functools import wraps
from random import random, randint
from flask import Flask, render_template, request, abort, url_for, jsonify, session, redirect, make_response
from markupsafe import escape
from flask_login import LoginManager, current_user, login_user
from flask_socketio import SocketIO
import db
import secrets

# import logging
# this turns off Flask Logging, uncomment this to turn off Logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = secrets.token_hex()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure you are using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Can be set to 'Strict' or 'Lax'
socketio = SocketIO(app)

import socket_routes

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return db.get_user(db.get_username(user_id))

# index page
@app.route("/")
def index():
    return render_template("index.jinja")

# login page
@app.route("/login")
def login():
    return render_template("login.jinja")

# handles a post request when the user clicks the log in button
@app.route("/login/user", methods=["POST"])
def login_the_user():

    if not request.is_json:
        abort(404)
    username_input = request.json.get("username")
    password_input = request.json.get("password")
    username = escape(username_input)
    password = escape(password_input)

    #prevents login if the user is already logged in
    if socket_routes.is_user_online(db.get_user_id(username)):
        return "Error: User already logged in!"

    #ensures the case is not a factor for the username and removes accidental spaces in the username or password
    username = db.format_username(username)

    user = db.get_user(username)    #grabs the user object from the database
    
    #prevents login if the user does not exist or the password does not match
    if user is None:
        return "Error: User does not exist!"
    password = str(password)
    if db.checkpassword(password, user.password) == False:
        return "Error: Password does not match!"
    login_user(user)    #authenticates the user, adding them to the connected users
    resp = make_response(url_for('home', username=username))
    resp.set_cookie('username', username, httponly=True)
    return resp

@app.route("/api/users/<string:username>/set_public_key", methods=["PUT"])
def set_public_key(username):
    
    #grabs the public key from the json request, escaping any special characters
    data = request.json
    public_key_input = data.get('public_key')
    public_key = escape(public_key_input)

    #ensuring a public key is provided
    if not public_key:
        return jsonify({'error': 'Missing public key'}), 400

    user = current_user    #grabs the user object from the passed username

    db.set_user_public_key(user.id, public_key)  #sets the public key for the user
    return jsonify({'message': 'Public key updated successfully'}), 200 #returns a success message

@app.route("/api/users/<string:username>/get_public_key", methods=["GET"])
def get_public_key(username):
    # Retrieve the user from your data store. This could be a database, etc.
    # This is just a placeholder function. Replace it with your actual user retrieval logic.
    user = db.get_user(username)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Assuming the user object has a 'public_key' attribute where the public key is stored
    public_key = user.pubkey

    if not public_key:
        return jsonify({'error': 'Public key not found for user'}), 404

    # Return the public key in the expected field 'pubkey'
    return jsonify({'pubkey': public_key}), 200

@app.route("/api/users/<string:username>/get_user_id", methods=["GET"])
def get_user_id(username):
    # Retrieve the user from your data store. This could be a database, etc.
    # This is just a placeholder function. Replace it with your actual user retrieval logic.
    user_id = db.get_user_id(username)
    if not user_id:
        return jsonify({'error': 'User not found'}), 404

    # Return the public key in the expected field 'pubkey'
    return jsonify({'user_id': user_id}), 200

# handles a get request to the signup page
@app.route("/signup")
def signup():
    return render_template("signup.jinja")

# handles a post request when the user clicks the signup button
@app.route("/signup/user", methods=["POST"])
def signup_user():
    #checks if the request is in json format
    if not request.is_json:
        abort(404)

    #retrieves the username and password from the json request, escaping any special characters
    username_input = request.json.get("username")
    password_input = request.json.get("password")
    role_input = request.json.get("role")
    user_code = request.json.get("user_code")
    staff_id = request.json.get("staff_id")
    username = escape(username_input)
    password = escape(password_input)
    role_input = escape(role_input)
    user_code = str(escape(user_code))
    staff_id = int(escape(staff_id))

    #creates a unique id for the user
    id = randint(1000000, 9999999)
    while db.get_id(id) is not None:
        id = randint(1000000, 9999999)
    
    #ensures the user code is correct they are not a student
    if role_input != "Student":
        if db.check_staff_code(staff_id, user_code, role_input) == False:
            return "Error: Staff code is incorrect!"

    #ensures the case is not a factor for the username, and removes accidental spaces in the username
    username = db.format_username(username)
    password = str(password)

    #inserts the user into the database if a user of the same username has not already been created
    if db.get_user(username) is None:
        db.insert_user(id, username, db.hash(password), "", role_input)
        login_user(db.get_user(username))
        resp = make_response(url_for('home', username=username, role=role_input))
        return resp
    return "Error: User already exists!"

# handler when a "404" error happens
@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404

# home page, where the messaging app is
@app.route("/home")
@login_required
def home():
    username = current_user.username
    user_id = db.get_user_id(username)
    friends = db.get_friends(user_id)
    outgoing_friends_request = db.get_outgoing_friends_request(user_id)
    incoming_friends_request = db.get_incoming_friends_request(user_id)
    user_role = db.get_user_role(user_id)
    return render_template("home.jinja", username=username, friends=friends, outgoing_friends_request=outgoing_friends_request, incoming_friends_request=incoming_friends_request, user_role=user_role)


@app.route('/articles')
def articles():
    return render_template('articles.jinja')

@app.route("/api/users/fetchchatnames", methods=["GET"])
def fetchchatnames():
    chat_names = db.get_all_group_chats()
    return jsonify({'chat_names': chat_names}), 200

# logout function that clears the sessions
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    socketio.run(app)
    # socketio.run(app, ssl_context=('./certs/mydomain.crt', './certs/mydomain.key'))