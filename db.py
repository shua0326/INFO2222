'''
db
database file, containing all the logic to interface with the sql database
'''


from sqlalchemy import create_engine, update, select, and_
from sqlalchemy.orm import Session
from models import *
import bcrypt
from pathlib import Path

# creates the database directory
Path("database") \
    .mkdir(exist_ok=True)

engine = create_engine("sqlite:///database/main.db", echo=True)

# initializes the database
Base.metadata.create_all(engine)

# inserts a user to the database
def insert_user(id:int, username: str, password: str, pubkey: str, role: str):
    with Session(engine) as session:
        user = User(id=id, username=username, password=password, pubkey=pubkey, user_role=role)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        return user

# gets a user_name from the database
def get_username(user_id: int):
    with Session(engine) as session:
        user = session.query(User).filter_by(id=user_id).first()
        return user.username

# add friend function
def add_friend(user_id: int, friend_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user and the friend from the database
        user = session.get(User, user_id)
        friend = session.get(User, friend_id)

        if not user or not friend:
            return

        # Add the friend to the user's list of friends
        # This establishes the friendship in one direction
        user.friends.append(friend)

        #this creates the mutual relationship, change later to make this only occur on accepting friend request
        friend.friends.append(user)

        # Commit the transaction to save changes to the database
        session.commit()

# Add friend request function   
def add_friend_request(user_id: int, friend_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user and the friend from the database
        user = session.get(User, user_id)
        friend = session.get(User, friend_id)

        if not user or not friend or user_id == friend_id:
            return
        # Add the friend to the user's list of friends
        # This establishes the friendship in one direction
        user.friends_request.append(friend)
        #this creates the mutual relationship, change later to make this only occur on accepting friend request
        # Commit the transaction to save changes to the database
        session.commit()

#shows the friends list of some user, change later to display it in the frontend
def get_friends(user_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user from the database
        user = session.get(User, user_id)
        list_to_send = []
        if not user:
            return list_to_send
        # Check if the user has friends
        if user.friends:
            for friend in user.friends:
                list_to_send.append(friend.username)
        return list_to_send

# Remove friend function 
def remove_friend(user_id, friend_id):
    with Session(engine) as session:
        # Get the user and friend from the database
        user = session.get(User, user_id)
        friend = session.get(User, friend_id)

        if not user or not friend:
            return
        # Remove the friend from the user's list of friends
        # This breaks the friendship in one direction
        user.friends.remove(friend)
        #this removes the mutual relationship, change later to make this only occur on accepting friend request
        friend.friends.remove(user)
        # Commit the transaction to save changes to the database
        session.commit()

# Remove friend request function
def remove_request(friend_id, user_id):
    with Session(engine) as session:
        # Get the user and friend from the database
        stmt = friends_request.delete().where(
            and_(
                friends_request.c.user_id == user_id,
                friends_request.c.friend_id == friend_id
            )
        )
        session.execute(stmt)
        session.commit()
        

#shows the friends list of some user, change later to display it in the frontend
def get_incoming_friends_request(user_id: int):
    # Create a new session
    with Session(engine) as session:
        # Query the friends_request table
        stmt = select(friends_request.c.user_id).where(friends_request.c.friend_id == user_id)
        result = session.execute(stmt)
        friend_request_ids = [row[0] for row in result.fetchall()]
        stmt = select(User.username).where(User.id.in_(friend_request_ids))
        user_names = session.execute(stmt)
        user_names_lst = [row[0] for row in user_names.fetchall()]
        return user_names_lst

# Get outgoing friend requests
def get_outgoing_friends_request(user_id: int):
    # Create a new session
    with Session(engine) as session:
        # Retrieve the user from the database
        user = session.get(User, user_id)
        list_to_send = []
        if not user:
            return list_to_send
        # Check if the user has friends
        if user.friends_request:
            friendnames = session.query(User).filter(User.id == user_id).one()
            friends_names = friendnames.friends_request
            for i in friends_names:
                if i.id != user_id:
                    list_to_send.append(i.username)
        return list_to_send

# Update convo function
def update_convo(convo_id, encrypted_message1, encrypted_message2):
    with Session(engine) as session:
        #grabbing the corresponding encryptedconvo, encryptedconvo2, and hmac from the database
        result = session.query(Message).filter(Message.convo_id == convo_id).one_or_none()
        if result:
            # If the convo_id exists, update the message, adding the delimiter
            result.encryptedconvo1 += "+++" + encrypted_message1
            result.encryptedconvo2 += "+++" + encrypted_message2
        else:
            # If the convo_id does not exist, insert a new record
            new_message = Message(convo_id=convo_id, encryptedconvo1=encrypted_message1, encryptedconvo2=encrypted_message2)
            session.add(new_message)
        session.commit()

# Get convo function
def get_convo(convo_id, row):
    with Session(engine) as session:
        result = session.query(Message).filter(Message.convo_id == convo_id).one_or_none()
        if result:
            if row == "encryptedconvo1":
                return result.encryptedconvo1
            elif row == "encryptedconvo2":
                return result.encryptedconvo2
        else:
            return None
        
# Disconnect convo function
def get_to_disconnect_convos(user_id):
    with Session(engine) as session:
        user_id_str = str(user_id)
        convos_to_be_disconnected = session.query(Message.convo_id).filter(Message.convo_id.like(f"%{user_id_str}%")).all()
        # Create a dictionary where the keys are the convo_ids with the user_id removed and the values are the original convo_ids
        convos_dict = {str(convo[0]).replace(user_id_str, ''): str(convo[0]) for convo in convos_to_be_disconnected}
        return convos_dict

# Generate convo id function
def generate_convo_id(user_id1, user_id2):
    return f"{min(user_id1, user_id2)}{max(user_id1, user_id2)}"

# Set user public key function
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
    # Decode hashed_password if it's a bytes object
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

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
def get_user_id(username):
    user = get_user(username)
    return user.id if user else None

# Get user public key function
def get_user_public_key(user_id):
    with Session(engine) as session:
        user = session.query(User).get(user_id)
        return user.pubkey if user else None

# Get get id function
def get_id(id: int):
    with Session(engine) as session:
        return session.get(User, id)
    
# Get user role function
def get_user_role(user_id):
    with Session(engine) as session:
        user = session.query(User).filter(User.id == user_id).first()
        return user.user_role if user else None

# Check staff code function
def check_staff_code(staff_id:int, user_code:str, user_role:str):
    with Session(engine) as session:
        with Session(engine) as session:
            result = session.query(Staff).filter(Staff.staff_id == staff_id).filter(Staff.staff_role == user_role).first()
        check_result = checkpassword(user_code, result.staff_code)
        return check_result if result else False

# inserts staff to the database
def insert_staff(id:int, staff_role: str, staff_code: str):
    with Session(engine) as session:
        staff = Staff(staff_id=id, staff_role=staff_role, staff_code=staff_code)
        session.add(staff)
        session.commit()

# insert_staff(1, "Academic", hash("1"))
    
      
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *
from pathlib import Path

