'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''
from random import random, randint

from flask import Flask, render_template, request, abort, url_for, jsonify
from flask_socketio import SocketIO
import db
import secrets

# import logging

# this turns off Flask Logging, uncomment this to turn off Logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

app = Flask(__name__)

# secret key used to sign the session cookie
app.config['SECRET_KEY'] = secrets.token_hex()
socketio = SocketIO(app)

# don't remove this!!
import socket_routes

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
def login_user():
    if not request.is_json:
        abort(404)

    username = request.json.get("username")
    password = request.json.get("password")

    #ensures the case is not a factor for the username and removes accidental spaces in the username or password
    username = db.format_username(username)
    password = db.format_password(password)

    user = db.get_user(username)
    if user is None:
        return "Error: User does not exist!"

    if db.checkpassword(password, user.password) == False:
        return "Error: Password does not match!"

    return url_for('home', username=request.json.get("username"))

@app.route("/api/users/<string:username>/set_public_key", methods=["PUT"])
def set_public_key(username):
    data = request.json
    public_key = data.get('public_key')
    if not public_key:
        print("No public key provided")
        return jsonify({'error': 'Missing public key'}), 400

    user = db.get_user(username)
    print(user.username)
    if user is None:
        print("Error: User does not exist!")
        return jsonify({'error': 'User not found'}), 404

    db.set_user_public_key(user.id, public_key)
    print("set")
    return jsonify({'message': 'Public key updated successfully'}), 200

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

# handles a get request to the signup page
@app.route("/signup")
def signup():
    return render_template("signup.jinja")

# handles a post request when the user clicks the signup button
@app.route("/signup/user", methods=["POST"])
def signup_user():
    if not request.is_json:
        abort(404)

    username = request.json.get("username")
    password = request.json.get("password")
    #creates a unique id for the friends association table to function
    id = randint(1000000, 9999999)
    while db.get_id(id) is not None:
        id = randint(1000000, 9999999)

    #ensures the case is not a factor for the username and removes accidental spaces in the username or password
    username = db.format_username(username)
    password = db.format_password(password)

    if db.get_user(username) is None:
        db.insert_user(username, id, db.hash(password))
        return url_for('home', username=username)
    return "Error: User already exists!"



# handler when a "404" error happens
@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404

# home page, where the messaging app is
@app.route("/home")
def home():
    if request.args.get("username") is None:
        abort(404)
    return render_template("home.jinja", username=request.args.get("username"))





if __name__ == '__main__':
    socketio.run(app)
