'''
models
defines sql alchemy data models
also contains the definition for the room class used to keep track of socket.io rooms

Just a sidenote, using SQLAlchemy is a pain. If you want to go above and beyond, 
do this whole project in Node.js + Express and use Prisma instead, 
Prisma docs also looks so much better in comparison

or use SQLite, if you're not into fancy ORMs (but be mindful of Injection attacks :) )
'''
from flask_login import UserMixin
from sqlalchemy import String, Integer, Table, ForeignKey, Column, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, declarative_base, relationship, Session
from typing import Dict

# data models
#defining the base class using declarative_base
Base = declarative_base()

#defining an association table to create the friends list

friends_association = Table(
    'friends_association', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('friend_id', Integer, ForeignKey('user.id'), primary_key=True)
)

friends_request = Table(
    'friends_request', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('friend_id', Integer, ForeignKey('user.id'), primary_key=True)
)

# model to store user information
class User(UserMixin, Base):
    __tablename__ = "user"
    
    # looks complicated but basically means
    # I want a username column of type string,
    # and I want this column to be my primary key
    # then accessing john.username -> will give me some data of type string
    # in other words we've mapped the username Python object property to an SQL column of type String 
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)
    pubkey: Mapped[str] = Column(String)
    user_role: Mapped[str] = Column(String)

    friends = relationship("User",
                           secondary=friends_association,
                           primaryjoin=id == friends_association.c.user_id,
                           secondaryjoin=id == friends_association.c.friend_id)
    
    friends_request = relationship("User",
                        secondary=friends_request,
                        primaryjoin=id == friends_request.c.user_id,
                        secondaryjoin=id == friends_request.c.friend_id)
    messages = relationship("Message", backref="user")

                           

# stateful counter used to generate the room id

class Message(Base):
    __tablename__ = 'messages_db'
    id = Column(Integer, primary_key=True)
    convo_id = Column(Integer)
    user_id = Column(Integer, ForeignKey('user.id'))
    encrypted_convo = Column(String)

class Staff(Base):
    __tablename__ = 'uni_staff_db'
    staff_id = Column(Integer, primary_key=True)
    staff_role = Column(String)
    staff_code = Column(String)

class Counter():
    def __init__(self):
        self.counter = 0
    
    def get(self):
        self.counter -= 1
        return self.counter

# Room class, used to keep track of which username is in which room
class Room():
    def __init__(self):
        self.counter = Counter()
        # dictionary that maps the username to the room id
        # for example self.dict["John"] -> gives you the room id of 
        # the room where John is in
        self.dict: Dict[str, int] = {}

    def create_room(self, sender: str, receiver: str) -> int:
        room_id = self.counter.get()
        self.dict[sender] = room_id
        self.dict[receiver] = room_id
        return room_id
    
    def join_room(self,  sender: str, room_id: int) -> int:
        self.dict[sender] = room_id

    def leave_room(self, user):
        if user not in self.dict.keys():
            return
        del self.dict[user]

    # gets the room id from a user
    def get_room_id(self, user: str):
        if user not in self.dict.keys():
            return None
        return self.dict[user]


    
