'''
socket_routes
file containing all the routes related to socket.io
'''

from flask_socketio import join_room, emit, leave_room
from flask_login import current_user
from flask import request, session, abort

try:
    from __main__ import socketio
except ImportError:
    from app import socketio

from models import Room

import db

room = Room()

connected_users = {}

# when the client connects to a socket
# this event is emitted when the io() function is called in JS
@socketio.on('connect')
def connect():
    username = request.cookies.get("username")
    user_id = db.get_user_id(username)
    if username is None:
        return
    room_id = user_id
    room.join_room(username, room_id)
    join_room(room_id)
    update_client(user_id)
    connected_users[user_id] = True
    emit("init_room_id", room_id)

def update_client(user_id):
    if not current_user.is_authenticated:
        disconnect()
    room_id = room.get_room_id(db.get_username(user_id))
    friends = db.get_friends(user_id)
    outgoing = db.get_outgoing_friends_request(user_id)
    incoming = db.get_incoming_friends_request(user_id)
    emit('update', {'friends': friends, 'outgoing': outgoing, 'incoming': incoming}, to=room_id)
  

# event when client disconnects
# quite unreliable use sparingly
@socketio.on('disconnect')
def disconnect(username, room_id):
    user_id = db.get_user_id(username)
    if room_id is None or username is None:
        return
    emit("incoming_sys_disconnect", to=int(room_id))
    if user_id in connected_users:
        del connected_users[user_id]
    leave_room(room_id)
    room.leave_room(username)


def is_user_online(user_id):
    return connected_users.get(user_id, False)

# send message event handler
@socketio.on("send")
def send(username, message, mac, room_id):
    if not current_user.is_authenticated:
        disconnect()
    emit("incoming", (f"{username}: ", f"{message}", mac), to=room_id)
    
# join room event handler
# sent when the user joins a room
@socketio.on("join")
def join(sender_name, receiver_name):
    if not current_user.is_authenticated:
        disconnect()
    receiver = db.get_user(receiver_name)
    if receiver is None:
        return "Unknown receiver!"
    
    sender = db.get_user(sender_name)
    if sender is None:
        return "Unknown sender!"

    if not receiver.is_authenticated:
        return "Receiver is not authenticated!"

    if not is_user_online(db.get_user_id(receiver_name)):
        return "User is not online!"
    user_id = db.get_user_id(sender_name)
    friends_list = db.get_friends(user_id)
    if receiver_name not in friends_list:
        return "You are not friends with this user!"


    room_id = room.get_room_id(receiver_name)
    convo_id = db.generate_convo_id(int(db.get_user_id(sender_name)), int(db.get_user_id(receiver_name)))
    row = ""
    if int(db.get_user_id(sender_name)) > int(db.get_user_id(receiver_name)):
        row = "encryptedconvo1"
    elif int(db.get_user_id(sender_name)) < int(db.get_user_id(receiver_name)):
        row = "encryptedconvo2"
    encrypted_message = db.get_convo(convo_id, row)
    hmac = db.get_hmac(convo_id)

    # if the user is already inside of a room
        
    room.join_room(sender_name, room_id)
    join_room(room_id)

    emit("incoming_sys_init", (f"{encrypted_message}", hmac), to=room_id)
    return room_id

@socketio.on("send_convo")
def send_convo(convo1, convo2, hmac, user, sender):
    if not current_user.is_authenticated:
        disconnect()
    convo_id = db.generate_convo_id(int(db.get_user_id(user)), int(db.get_user_id(sender)))
    db.update_convo(convo_id, convo1, convo2, hmac)
# leave room event handler
@socketio.on("leave")
def leave(username, room_id):
    if not current_user.is_authenticated:
        disconnect()
    #emit("receiver_left", to=room_id)
    leave_room(room_id)
    room.leave_room(username)
    connect()
    
    
@socketio.on("add_friend_request")
def add_friend_request(user_id, friend_id):
    if not current_user.is_authenticated:
        disconnect()
    db.add_friend_request(user_id, friend_id)
    room_id = room.get_room_id(db.get_username(friend_id))
    update_client(friend_id)
    update_client(user_id)
    emit("add_friend_request", to=room_id)
    
@socketio.on("add_friend")
def add_friend(user, friend):
    if not current_user.is_authenticated:
        disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(user_id, friend_id)
    db.add_friend(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)

@socketio.on("remove_request")
def remove_request(user, friend):
    if not current_user.is_authenticated:
        disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(friend_id, user_id)
    update_client(friend_id)
    update_client(user_id)

@socketio.on("reject_request")
def remove_request(user, friend):
    if not current_user.is_authenticated:
        disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)


@socketio.on("remove_friend")
def remove_friend(user, friend):
    if not current_user.is_authenticated:
        disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_friend(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)