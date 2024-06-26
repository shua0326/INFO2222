'''
socket_routes
file containing all the routes related to socket.io
'''
import flask_socketio
from flask import request
from flask_socketio import join_room, emit, leave_room
from flask_login import current_user, AnonymousUserMixin

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
    username = current_user.username
    user_id = db.get_user_id(username)
    if username is None:
        return
    room_id = user_id
    room.join_room(username, room_id)
    join_room(room_id)
    update_client(user_id)
    sid = request.sid
    connected_users[user_id] = sid
    friends_to_be_notified = db.get_friends(user_id)
    for friend in friends_to_be_notified:
        f_id = db.get_user_id(friend)
        if not is_user_online(f_id):
            continue
        update_client(f_id)
    emit("init_room_id", room_id)

def get_userid_from_connectedusers(dictionary, target_value):
    for key, value in dictionary.items():
        if value == target_value:
            return key
    return None


def update_client(user_id):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    room_id = room.get_room_id(db.get_username(user_id))
    friends = db.get_friends(user_id)
    outgoing = db.get_outgoing_friends_request(user_id)
    incoming = db.get_incoming_friends_request(user_id)
    group_chats = db.get_group_chats(user_id)
    emit('update', {'friends': friends, 'outgoing': outgoing, 'incoming': incoming, 'group_chats': group_chats}, to=room_id)

@socketio.on('disconnect')
def handle_disconnect():
    sid = str(request.sid)
    user_id = get_userid_from_connectedusers(connected_users, sid)
    if user_id is not None and not db.get_user(db.get_username(user_id)).is_anonymous:
        del connected_users[user_id]
        room.leave_room(db.get_username(user_id))
        friends_to_be_notified = db.get_friends(user_id)
        for friend in friends_to_be_notified:
            f_id = db.get_user_id(friend)
            if not is_user_online(f_id):
                continue
            update_client(f_id)

@socketio.on('user_disconnect')
def disconnect(given_username):
    if given_username:
        username = given_username
    else:
        username = current_user.username
    room_id = room.get_room_id(username)
    if room_id is None or username is None:
        return
    del connected_users[db.get_user_id(username)]
    leave_room(room_id)
    room.leave_room(username)
    return "User disconnected!"


def is_user_online(user_id):
    if user_id in connected_users:
        return True
    else:
        return False

# send message event handler
@socketio.on("send")
def send(username, message, mac):
    if not current_user.is_authenticated:
        return "User not authenticated!"
        flask_socketio.disconnect()
    muted_status = db.get_muted_status(current_user.id)
    if muted_status:
        emit("incoming_sys_disconnect")
        return {"error_message": "You are muted from talking in group chats! Please seek assistance from your teacher or admin!", "error_code": 302}
    if not is_user_online(db.get_user_id(username)):
        return False
    friends_list = db.get_friends(db.get_user_id(current_user.username))
    if username not in friends_list:
        emit("incoming_sys_disconnect")
        return "You are not friends with this user!"
    room_id = room.get_room_id(username)
    emit("incoming", (f"{username}", f"{message}", mac), to=room_id)

# join room event handler
# sent when the user joins a room
@socketio.on("join")
def join(sender_name, receiver_name, is_group_chat):
    # various validation and error checking
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    if not is_group_chat:
        receiver = db.get_user(receiver_name)
        if receiver is None:
            return {"error_message": "Unknown receiver!", "error_code": 300}

    sender = db.get_user(sender_name)
    if sender is None:
        return {"error_message": "Unknown sender!", "error_code": 301}
    
    user_id = db.get_user_id(sender_name)
    muted_status = db.get_muted_status(user_id)
    if muted_status:
        return {"error_message": "You are muted from talking in group chats! Please seek assistance from your teacher or admin!", "error_code": 302}
    if is_group_chat:
        muted_status = db.get_muted_status(user_id)
        if muted_status:
            return {"error_message": "You are muted from talking in group chats! Please seek assistance from your teacher or admin!", "error_code": 302}
        if sender_name not in db.get_group_chat_users(receiver_name):
            return "You are not in this group chat!"
    else:
        friends_list = db.get_friends(user_id)
        if receiver_name not in friends_list:
            return {"error_message": "You are not friends with this user!", "error_code": 303}
    # sets room id and convo id
    if is_group_chat:
        convo_id = receiver_name + "-GroupChat"
        room_id = db.get_room_id(convo_id)
    else:
        convo_id = db.generate_convo_id(int(db.get_user_id(sender_name)), int(db.get_user_id(receiver_name)))
        room_id = convo_id
    if db.get_convo(convo_id, user_id) is None:
        room.join_room(sender_name, room_id)
        join_room(room_id)
        emit("incoming_sys_init", (""))
        return int(room_id)

    encrypted_message = db.get_convo(convo_id, user_id)
    # grab the hmac value if a encrypted message is found

    if encrypted_message:
        room.join_room(sender_name, room_id)
        join_room(room_id)
        # send the corresponding encrypted message to the user
        emit("incoming_sys_init", (f"{encrypted_message}"))
        print(encrypted_message)

        return int(room_id)


@socketio.on("send_convo")
def send_convo(encrypted_convo, user, receiver, is_group_chat):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    if is_group_chat:
        convo_id = receiver+"-GroupChat"
        user_id = db.get_user_id(user)
        db.update_convo(convo_id, user_id, encrypted_convo)
    else:
        convo_id = db.generate_convo_id(int(db.get_user_id(user)), int(db.get_user_id(receiver)))
        user_id = db.get_user_id(user)
        db.update_convo(convo_id, user_id, encrypted_convo)

# leave room event handler
@socketio.on("leave")
def leave(username):
    current_room = room.get_room_id(username)
    leave_room(current_room)
    room.leave_room(current_room)
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    init_room_id = db.get_user_id(username)
    room.join_room(username, init_room_id)
    join_room(init_room_id)
    emit("init_room_id", init_room_id)
    
    
@socketio.on("add_friend_request")
def add_friend_request(user_id, friend_id):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    db.add_friend_request(user_id, friend_id)
    room_id = room.get_room_id(db.get_username(friend_id))
    update_client(friend_id)
    update_client(user_id)
    emit("add_friend_request", to=room_id)
    
@socketio.on("add_friend")
def add_friend(user, friend):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(user_id, friend_id)
    db.add_friend(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)

@socketio.on("remove_request")
def remove_request(user, friend):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(friend_id, user_id)
    update_client(friend_id)
    update_client(user_id)

@socketio.on("reject_request")
def remove_request(user, friend):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_request(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)
    
@socketio.on('make_group_chat')
def make_group_chat(user_id, chat_name, users):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    db.make_group_chat(user_id, chat_name, users)
    update_client(user_id)


@socketio.on("remove_friend")
def remove_friend(user, friend):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    user_id = db.get_user_id(user)
    friend_id = db.get_user_id(friend)
    db.remove_friend(user_id, friend_id)
    update_client(friend_id)
    update_client(user_id)


@socketio.on('make_group_chat')
def make_group_chat(user_id, chat_name, users):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    db.make_group_chat(user_id, chat_name, users)
    update_client(user_id)


@socketio.on("leave_group_chat")
def leave_group_chat(chat_name):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    db.leave_group_chat(current_user.id, chat_name)
    update_client(current_user.id)


@socketio.on("add_friend_to_group")
def add_friend_to_group(friend_id, convo_id):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    db.add_friend_to_group(friend_id, convo_id)
    update_client(current_user.id)
    
    
@socketio.on("mute_user")
def mute_user(target_username, mute_type):
    if not current_user.is_authenticated:
        flask_socketio.disconnect()
    target_user_id = db.get_user_id(target_username)
    if target_user_id is None:
        return "User does not exist!"
    elif target_user_id == current_user.id:
        return "You cannot mute yourself!"
    else:
        if mute_type == "unmute":
            db.unmute_user(target_user_id)
            update_client(current_user.id)
            return "User unmuted!"
        else:
            db.mute_user(target_user_id)
            update_client(current_user.id)
            return "User muted!"