'''
db
database file, containing all the logic to interface with the sql database
'''
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *
import bcrypt
from pathlib import Path

# creates the database directory
Path("database") \
    .mkdir(exist_ok=True)

# "database/main.db" specifies the database file
# change it if you wish
# turn echo = True to display the sql output
engine = create_engine("sqlite:///database/main.db", echo=True)

# initializes the database
Base.metadata.create_all(engine)

# inserts a user to the database
def insert_user(username: str, id:int, password: str):
    with Session(engine) as session:
        user = User(username=username, id=id, password=password)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        return user

def add_friend(user_id: int, friend_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user and the friend from the database
        user = session.get(User, user_id)
        friend = session.get(User, friend_id)

        if not user or not friend:
            print("User or friend not found.")
            return

        # Add the friend to the user's list of friends
        # This establishes the friendship in one direction
        user.friends.append(friend)

        #this creates the mutual relationship, change later to make this only occur on accepting friend request
        friend.friends.append(user)

        # Commit the transaction to save changes to the database
        session.commit()

#shows the friends list of some user, change later to display it in the frontend
def get_friends(user_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user from the database
        user = session.get(User, user_id)
        string_to_send = ""
        if not user:
            string_to_send += "User not found."
            return string_to_send

        # Check if the user has friends
        if user.friends:
            string_to_send += f"Friends of {user.username}:"
            for friend in user.friends:
                string_to_send += f"\n- {friend.username}"
        else:
            string_to_send += f"{user.username} has no friends."
        return string_to_send

def set_user_public_key(user_id, public_key):
    with Session(engine) as session:
        user = session.query(User).filter(User.id == user_id).first()
        user.pubkey = public_key
        session.commit()

#hashing process for password, bcrypt is used for better security
def hash(plain_password):
    #hashes the password while adding a salt simultaneously
    #need to convert the password first to an array of bytes
    plain_password = plain_password.encode('utf-8')
    return bcrypt.hashpw(plain_password, bcrypt.gensalt())

#checks whether the password matches after hashing
def checkpassword(plain_password, hashed_password):
    #uses the bcrypt checkpw to check password (returns true or false)
    #need to convert the password first to an array of bytes
    plain_password = plain_password.encode('utf-8')
    return bcrypt.checkpw(plain_password, hashed_password)

#removes spaces and lowercases username
def format_username(username):
    username = username.lower()
    username = username.strip()
    return username

#removes spaces from password
def format_password(password):
    password = password.strip()
    return password


# Get user id function
def get_user_id(user_name):
    with Session(engine) as session:
        user = session.query(User).get(user_name)
        return user.user_id if user else None 

def get_user_public_key(user_id):
    with Session(engine) as session:
        user = session.query(User).get(user_id)
        return user.public_key if user else None

def get_id(id: int):
    with Session(engine) as session:
        return session.get(User, id)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *

from pathlib import Path

# creates the database directory

