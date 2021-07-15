# python 3.7

# Demiao Chen
# z5289988

import sys
import socket
import threading
import os

# message send between server and client will use pickle fornat
from pickle import dumps, loads
from datetime import datetime

number_of_consecutive_failed_attempts = 0
blocking_time = 10         # blocking time length (seconds)
host = '127.0.0.1'         # localhost
# a list of dict, contains registered users' username and password
user_list = []

''' 
# user dict structure
user = {
    'username': username,
    'password': password,
    'failed_attempts': 0,
    'login_timestamp': 0,
    'last_block_timestamp': 0,
}
'''

#####################################################################################################
#                                                                                                   #
#                                   Helper Functions                                                #
#                                                                                                   #
#####################################################################################################


# send a message to client, specify the type and body
def send_message(client, m_type, body):
    message = {
        'type': m_type,
        'body': body,
    }
    # print(message)  # debug option
    client.send(dumps(message))


# return the log format time for current time
def log_time_format():
    return datetime.fromtimestamp(datetime.timestamp(datetime.now())).strftime("%d %b %Y %H:%M:%S")


# convert log_time_format to unix timestamp
def log_time_format_to_unix_timestamp(time_now):
    try:
        return int(datetime.strptime(time_now, "%d %b %Y %H:%M:%S").timestamp())
    except:
        return None


#####################################################################################################
#                                                                                                   #
#                                   Commands Execution                                              #
#                                                                                                   #
#####################################################################################################

# Post Messages
def execute_MSG(client, username, body):
    if body == '':
        send_message(client, 'F', 'Message body cannot be empty!')
        return None
    info = add_messagelog(username, body)
    print(
        f'{datetime.now().replace(microsecond=0)}\t{username}: {info} Content: {body}'
    )
    send_message(client, 'MSGACK', info)


# Delete Message
def execute_DLT(client, username, body):
    # DLT command format wrong, send DLT failed
    if len(body.split(' ')) != 5:
        send_message(
            client, 'DLT-F',
            'DLT failed! Please check the format of DLT command: DLT <messagenumber> <DATE MONTH(ENG) YEAR HOUR:MIN:SEC>'
        )
        return None
    messagenumber = body.split(' ')[0]
    messagetimestamp = ' '.join(body.split(' ')[1:5])
    # call dlt_messagelog to delete message, and send appropriate message to inform user
    dlt_messagelog(client, username, messagenumber, messagetimestamp)


# Edit Message
def execute_EDT(client, username, body):
    # EDT command format wrong, send EDT failed
    if len(body.split(' ')) <= 5:
        send_message(
            client, 'EDT-F',
            'EDT failed! Please check the format of EDT command: EDT <messagenumber> <DATE MONTH(ENG) YEAR HOUR:MIN:SEC> <message>'
        )
        return None
    messagenumber = body.split(' ')[0]
    messagetimestamp = ' '.join(body.split(' ')[1:5])
    message = ' '.join(body.split(' ')[5:])
    # call edt_messagelog to edit message, and send appropriate message to inform user
    edt_messagelog(client, username, messagenumber, messagetimestamp, message)


# Read Messages
def execute_RDM(client, username, body):
    # RDM command format wrong, send RDM failed
    if len(body.split(' ')) != 4:
        send_message(
            client, 'RDM-F',
            'RDM failed! Please check the format of RDM command: RDM <DATE MONTH(ENG) YEAR HOUR:MIN:SEC>'
        )
        return None
    messagetimestamp = ' '.join(body.split(' ')[0:4])
    print(messagetimestamp)
    input_timestamp_unix = log_time_format_to_unix_timestamp(messagetimestamp)
    if input_timestamp_unix == None:
        send_message(
            client, 'F', 'RDM failed! Please input valid timestamp format.')
        return None

    print(f'{datetime.now().replace(microsecond=0)}\t{username} issued RDM command')

    with open('messagelog.txt', 'r') as f:
        lines = f.readlines()

    msg_list_str = ''
    for line in lines:
        msg_timestamp = line.split('; ')[1]   # get timestamp of the line
        msg_timestamp_unix = log_time_format_to_unix_timestamp(msg_timestamp)

        # if the message is after the timestamp given
        if input_timestamp_unix <= msg_timestamp_unix:
            seq = line.split('; ')[0]          # get message number of the line
            username = line.split('; ')[2]     # get username of the line
            msg_content = line.split('; ')[3]  # get message of the line
            edited = line.split('; ')[4]       # get edited of the line
            if edited == 'yes':
                msg_type = 'edited'
            else:  # edited == 'no'
                msg_type = 'posted'
            msg_list_str += f'#{seq}, {username}: "{msg_content}", {msg_type} at {msg_timestamp}.\n'

    if msg_list_str == '':
        print('No new message since given timestamp')
        send_message(client, 'RDM', 'No new message since given timestamp')
    else:
        print('Return messages:')
        print(msg_list_str)
        send_message(client, 'RDM', msg_list_str)


# Download Active Users
def execute_ATU(client, username):

    print(f'{datetime.now().replace(microsecond=0)}\t{username} issued ATU command')

    with open('userlog.txt', 'r') as f:
        lines = f.readlines()

    print(f'Return active user list: ')

    active_list_str = ''
    for line in lines:
        name = line.split('; ')[2]
        if name != username:  # only send active users other than the client
            # get login time of the line
            active_time = line.split('; ')[1]
            # get ip address of the line
            IP_address = line.split('; ')[3]
            # get udp port number of the line, strip '\n'
            UDP_port_number = line.split('; ')[4].strip()
            active_list_str += f'{name}, {IP_address}, {UDP_port_number}, active since {active_time}.\n'

    if active_list_str == '':  # no any other active user
        send_message(client, 'ATU-N', 'No other active user.')
        print('No other active user.')
        return None

    send_message(client, 'ATU', active_list_str)
    print(active_list_str, end='')


# Log out
def execute_OUT(client, username):
    print(
        f'{datetime.now().replace(microsecond=0)}\t{username} logout the server'
    )
    send_message(client, 'OUT', f'Bye, {username}!')
    client.close()
    update_userlog(username)


# execute command user sent
def execute_command(client, command, body, username):
    if command == 'MSG':
        execute_MSG(client, username, body)
    elif command == 'DLT':
        execute_DLT(client, username, body)
    elif command == 'EDT':
        execute_EDT(client, username, body)
    elif command == 'RDM':
        execute_RDM(client, username, body)
    elif command == 'ATU':
        execute_ATU(client, username)
    elif command == 'OUT':
        execute_OUT(client, username)
    else:
        send_message(client, '', 'Error. Invalid command!')


#####################################################################################################
#                                                                                                   #
#                                     Log Files Editing                                             #
#                                                                                                   #
#####################################################################################################

# edit the message specifid by message number and message timestamp, edit if the
# user send the command is the sender of the message
# display edit inforamation in terminal and inform user deleting state
def edt_messagelog(client, username, messagenumber, messagetimestamp, message):
    with open('messagelog.txt', 'r') as f:
        lines = f.readlines()

    time_now = log_time_format()

    # check message number, timestamp and user permssion
    if check_message(lines, client, username, messagenumber, messagetimestamp, time_now, 'edit') == None:
        return None

    with open('messagelog.txt', 'w') as f:
        for line in lines:
            # get the username information in the line
            seq = line.split('; ')[0]
            if seq != messagenumber:
                f.write('; '.join(line.split('; ')))
            else:  # seq == messagenumber
                time_now = log_time_format()
                # update message and timestamp, change edited to 'yes'
                f.write(f'{seq}; {time_now}; {username}; {message}; yes\n')

    send_message(client, 'EDT-ACK',
                 f'Message #{messagenumber} edited at {time_now}.')
    print(f'{datetime.now().replace(microsecond=0)}\t{username} edited MSG #{messagenumber} "{message}" at {time_now}.')


# delete the message specifid by message number and message timestamp, delete if the
# user send the command is the sender of the message
# display delete inforamation in terminal and inform user deleting state
def dlt_messagelog(client, username, messagenumber, messagetimestamp):
    with open('messagelog.txt', 'r') as f:
        lines = f.readlines()

    time_now = log_time_format()

    # check message number, timestamp and user permssion
    dlt_msg_body = check_message(
        lines, client, username, messagenumber, messagetimestamp, time_now, 'delete')
    if dlt_msg_body == None:
        return None

    with open('messagelog.txt', 'w') as f:
        counter = 1  # count the number of lines to update sequence number
        for line in lines:
            # get the username information in the line
            seq = line.split('; ')[0]
            if seq != messagenumber:
                f.write(str(counter) + '; ' + '; '.join(line.split('; ')[1:]))
                counter += 1

    send_message(
        client, 'ACK', f'Message #{messagenumber} deleted at {time_now}.')
    print(f'{datetime.now().replace(microsecond=0)}\t{username} deleted MSG #{messagenumber} "{dlt_msg_body}" at {time_now}.')


# check if the messagenumber, messagetimestamp valid and user permssion
# return the message specified by message number if all checks pass
def check_message(lines, client, username, messagenumber, messagetimestamp, time_now, command):
    # check if message number valid
    try:
        if int(messagenumber) > len(lines) or int(messagenumber) <= 0:
            send_message(client, 'F', 'Message number invalid!')
            print(
                f'{datetime.now().replace(microsecond=0)}\t{username} attemptsto {command} MSG #{messagenumber} at {time_now}. Input fails.'
            )
            return None
    except:  # user inputs not integer
        send_message(client, 'F', 'Message number must be integer!')
        print(
            f'{datetime.now().replace(microsecond=0)}\t{username} attempts to {command} MSG #{messagenumber} at {time_now}. Input fails.'
        )
        return None

    # check if timestamp correct and permission
    for line in lines:
        seq = line.split('; ')[0]  # get message number of the line

        # if messagenumber found
        if seq == messagenumber:
            msgtime = line.split('; ')[1]  # get message timestamp of the line

            # if timestamp mathced
            if msgtime == messagetimestamp:
                msgname = line.split('; ')[2]  # get username of the line
                if msgname != username:
                    send_message(client, 'F',
                                 'Permssion failed, you are not the sender!')
                    print(
                        f'{datetime.now().replace(microsecond=0)}\t{username} attempts to {command} MSG #{messagenumber} at {time_now}. Authorisation fails.'
                    )
                    return None
                else:
                    return line.split('; ')[3]

            # timestamp not matched
            else:
                send_message(
                    client, 'F', 'Timestamp is not matched for the given message number!')
                print(
                    f'{datetime.now().replace(microsecond=0)}\t{username} attempts to {command} MSG #{messagenumber} at {time_now}. Input fails.'
                )
                return None


# add new message to messagelog.txt
def add_messagelog(username, body):
    # count lines in messagelog.txt
    try:
        with open('messagelog.txt', 'r') as f:
            num_lines = len(f.readlines())
    except:
        num_lines = 0

    # make new messagelog information string
    seq = num_lines + 1  # sequence number
    timestamp = datetime.timestamp(datetime.now())
    time = datetime.fromtimestamp(timestamp).strftime(
        "%d %b %Y %H:%M:%S")  # time
    new_log = [str(seq), str(time), username, body, 'no']
    new_log_string = '; '.join(new_log)

    # append new_log at a new line in the end of messagelog.txt
    with open('messagelog.txt', 'a') as f:
        f.write(f'{new_log_string}\n')

    return f'Message #{seq} posted at {time}.'


# remove the user log information form userlog.txt, updating following line's sequence number
def update_userlog(username):
    with open('userlog.txt', 'r') as f:
        lines = f.readlines()
    with open('userlog.txt', 'w') as f:
        counter = 1  # count the number of lines to update sequence number
        for line in lines:
            # get the username information in the line
            line_username = line.split('; ')[2]
            if username != line_username:
                # update sequence number
                f.write(str(counter) + '; ' + '; '.join(line.split('; ')[1:]))
                counter += 1


def userlog_add(user, addr, udp):
    # count lines in userlog.txt
    try:
        with open('userlog.txt', 'r') as f:
            num_lines = len(f.readlines())
    except:
        num_lines = 0

    # make new userlog information string
    seq = num_lines + 1  # sequence number
    ip = addr[0]  # ip address
    timestamp = user['login_timestamp']
    time = datetime.fromtimestamp(timestamp).strftime(
        "%d %b %Y %H:%M:%S")  # time
    new_log = [str(seq), str(time), user['username'], str(ip), str(udp)]
    new_log_string = '; '.join(new_log)

    # append new_log at a new line in the end of userlog.txt
    with open('userlog.txt', 'a') as f:
        f.write(f'{new_log_string}\n')


# clear log files: userlog.txt, messagelog.txt
def clear_logfile():
    if os.path.isfile('userlog.txt'):
        f = open("userlog.txt", "r+")
        f.truncate(0)
        f.close()
    if os.path.isfile('messagelog.txt'):
        f = open("messagelog.txt", "r+")
        f.truncate(0)
        f.close()


#####################################################################################################
#                                                                                                   #
#                                         Login                                                     #
#                                                                                                   #
#####################################################################################################

def login(client):
    while True:
        # get username and password from client
        try:
            input_pair = loads(client.recv(2048)).get('body')
        except Exception:
            return None
        input_username = input_pair.split(' ')[0]
        input_password = input_pair.split(' ')[1]

        # check username and password
        found_flag = False
        for user in user_list:

            if input_username == user.get('username'):
                found_flag = True
                current_timestamp = datetime.timestamp(datetime.now())

                # Case: the account has been blocked in last 10 secs
                if current_timestamp - user.get('last_block_timestamp') < blocking_time:
                    send_message(client, 'LOGIN-BB',
                                 '')  # account is during blocking
                    return None

                # Case: password matches username, user login
                if input_password == user.get('password'):
                    send_message(client, 'LOGIN-A', '')  # login acknowledge
                    user['login_timestamp'] = current_timestamp
                    current_time = datetime.fromtimestamp(
                        current_timestamp).replace(microsecond=0)
                    user['failed_attempts'] = 0
                    print(
                        f'{current_time}\t{input_username} login the server')
                    return user

                else:
                    user['failed_attempts'] += 1

                    # Case: run out of attempt times, block user
                    if user['failed_attempts'] >= number_of_consecutive_failed_attempts:
                        send_message(client, 'LOGIN-B', '')  # login blocked
                        user['last_block_timestamp'] = current_timestamp
                        current_time = datetime.fromtimestamp(
                            current_timestamp).replace(microsecond=0)
                        user['failed_attempts'] = 0
                        print(
                            f'{current_time}\t{input_username} is blokced for 10 secs'
                        )
                        return None

                    # Case: password wrong
                    else:
                        send_message(client, 'LOGIN-F', '')  # login failed

        # Case: username is not existed
        if found_flag == False:
            send_message(client, 'LOGIN-N', '')  # Username not found


#####################################################################################################
#                                                                                                   #
#                           Server Initialisation & Threading                                       #
#                                                                                                   #
#####################################################################################################


# thtread handle of a client
def handle(client, addr):

    # send initial message to inform client has connected
    send_message(client, '', 'Successfully connected to server')

    # login user
    user = login(client)

    # login fails, blocked
    if user == None:
        client.close()
        print(
            f'{datetime.now().replace(microsecond=0)}\tClosed connection with {addr[0]} at port {addr[1]}'
        )
        return None

    # login successes, get the udp port number from client
    # update userlog.txt
    udp = loads(client.recv(2048))['body']
    userlog_add(user, addr, udp)
    username = user.get('username')

    # wating for client to send command
    while True:
        try:
            response = loads(client.recv(2048))
        except Exception:
            print(
                f'{datetime.now().replace(microsecond=0)}\tClosed connection with {addr[0]} at port {addr[1]}'
            )
            return None
        command = response.get('type')
        body = response.get('body')
        execute_command(client, command, body, username)


# read username with password in credentials.txt to user_list
def read_data():
    with open('credentials.txt') as f:
        for line in f.readlines():
            user = {
                'username': line.split(' ')[0].strip(),
                'password': line.split(' ')[1].strip(),
                'failed_attempts': 0,
                'login_timestamp': 0,
                'last_block_timestamp': 0,
            }
            user_list.append(user)


def run_server(server_port):

    # establish server socket, and bind it with specified port number
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, server_port))
    print(f'Server is running on {host}:{server_port}')

    server_socket.listen(100)
    print('Server is listening, waiting for clients to connect...')

    # clear logfile and read registered user inforamation after server running
    clear_logfile()
    read_data()

    # waiting for clients to connect
    while True:
        try:
            client, addr = server_socket.accept()
            print(
                f'{datetime.now().replace(microsecond=0)}\tConnected to {addr[0]} at port {addr[1]}'
            )
            t = threading.Thread(target=handle, args=(client, addr))
            t.daemon = True  # release memory after client logout
            t.start()
        except Exception as e:
            client.close()

    client.close()
    server_socket.close()


#####################################################################################################
#                                                                                                   #
#                                     Code Start                                                    #
#                                                                                                   #
#####################################################################################################


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(
            'Usage: python3 server.py <server_port>  <number_of_consecutive_failed_attempts>'
        )
        exit()

    server_port = int(sys.argv[1])
    number_of_consecutive_failed_attempts = int(sys.argv[2])
    if number_of_consecutive_failed_attempts < 1 or number_of_consecutive_failed_attempts > 5:
        print(
            'Please choose <number_of_consecutive_failed_attempts> as an integer between 1 and 5'
        )
        exit()

    run_server(server_port)
