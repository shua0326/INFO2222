'''
db
database file, containing all the logic to interface with the sql database
'''

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *

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
        return session.get(User, username)

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

        # Optionally, add the user to the friend's list of friends to make the friendship mutual
        # friend.friends.append(user)  # Uncomment this line if you want mutual friendship

        # Commit the transaction to save changes to the database
        session.commit()

def friend_list(user_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user from the database
        user = session.get(User, user_id)

        if not user:
            print("User not found.")
            return

        # Check if the user has friends
        if user.friends:
            print(f"Friends of {user.username}:")
            for friend in user.friends:
                print(f"- {friend.username}")
        else:
            print(f"{user.username} has no friends.")

def get_id(id: int):
    with Session(engine) as session:
        return session.get(User, id)
