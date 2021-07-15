# python 3.7

# Demiao Chen
# z5289988

import sys
import socket
import time
import os
import threading
from pickle import dumps, loads


# a list to store user info obtained from ATU command
user_list = []
# buffer size for udp transfer
BUFF_SIZE = 4096

host = '127.0.0.1'  # localhost

#####################################################################################################
#                                                                                                   #
#                                   Helper Functions                                                #
#                                                                                                   #
#####################################################################################################


def is_user_in_user_list(username):
    for user in user_list:
        if username == user['username']:
            return True
    return False


def get_user_by_username(username):
    for user in user_list:
        if username == user['username']:
            return user
    return None


def send_message(client, m_type, body):
    message = {
        'type': m_type,
        'body': body,
    }
    client.send(dumps(message))


#####################################################################################################
#                                                                                                   #
#                                     UDP Functions                                                 #
#                                                                                                   #
#####################################################################################################


# execute UPD command, establish udp client socket to send file to server
def execute_UPD(client_username, body):
    if len(body.split(' ')) != 2:
        print(
            'UPD Failed! Please check the format of UPD command: UPD <username> <filename>')
        return None

    username = body.split(' ')[0]   # get the username from body
    filename = body.split(' ')[1]   # get the filename from body

    if not is_user_in_user_list(username):
        print(f'{username} is offline or does not exist! Please use ATU command to download user information.')
        return None

    if not os.path.isfile(filename):
        print(f'{filename} is not in the current directory!')
        return None

    # get receiver's ip address and receiving port
    user = get_user_by_username(username)
    ip_addr = user['ip_addr']
    port_number = int(user['port_number'])

    # create udp socket for uploading
    upload_sokcet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_addr = (ip_addr, port_number)

    try:
        # send sender's username
        upload_sokcet.sendto(client_username.encode(), send_addr)
    except:
        print(f'{username} is offline!')
        return None

    # add client username as prefix for filename send to server
    client_filename = client_username + '_' + filename
    upload_sokcet.sendto(client_filename.encode(), send_addr)

    f = open(filename, "rb")
    data = f.read(BUFF_SIZE)
    while (data):
        if(upload_sokcet.sendto(data, send_addr)):
            data = f.read(BUFF_SIZE)
    upload_sokcet.close()
    f.close()

    print(f'{filename} has been uploaded.')


# handle listen from client
def udp_handle(udp_socket):
    while True:

        data, client_addr = udp_socket.recvfrom(BUFF_SIZE)

        sender_name = data.decode()

        data, addr = udp_socket.recvfrom(BUFF_SIZE)
        recv_filename = data.decode()
        filename = '_'.join(recv_filename.split('_')[1:])

        f = open(recv_filename, 'wb')
        data, addr = udp_socket.recvfrom(BUFF_SIZE)
        try:
            while data:
                f.write(data)
                # set timeout for incoming udp datagram
                udp_socket.settimeout(2)
                data, addr = udp_socket.recvfrom(BUFF_SIZE)
        except Exception:
            f.close()
            # cancel timeout when whole packets is received
            # waiting for next file
            udp_socket.settimeout(None)
            print(f'Reveived {filename} from {sender_name}.')


# set up udp server socket waiting for incoming udp connection
def udp_setup(client_udp_server_port):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((host, client_udp_server_port))
    server_thread = threading.Thread(target=udp_handle, args=(udp_socket, ))
    server_thread.daemon = True
    server_thread.start()


#####################################################################################################
#                                                                                                   #
#                                    Client Initialisation                                          #
#                                                                                                   #
#####################################################################################################


def login(client):
    while True:
        username = input('Username: ').strip()
        password = input('Password: ').strip()
        login_message = username + ' ' + password
        send_message(client, 'LOGIN', login_message)
        login_response = loads(client.recv(2048))['type']
        if login_response == 'LOGIN-A':
            return username
        elif login_response == 'LOGIN-N':
            print('Username does not exist, please input a valid username')
        elif login_response == 'LOGIN-B':
            print(
                'Invalid Password. Your account has been blocked. Please try again later')
            return None
        elif login_response == 'LOGIN-F':
            print('Invalid Password. Please try again')
        elif login_response == 'LOGIN-BB':
            print(
                'Your account is blocked due to multiple login failures. Please try again later')
            return None


def run_client(server_IP, server_port, client_udp_server_port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_IP, server_port))
        initial_response = loads(client.recv(2048))['body']
        print(initial_response)
    except Exception:
        print('Connection failed, please check sever IP adress and port number. Or server is not running.')
        exit()

    # account has been blocked, exit terminal
    client_username = login(client)
    if client_username == None:
        client.close()
        exit()

    # set up udp socket waiting fot p2p file transfer
    udp_setup(client_udp_server_port)

    # send client_udp_server_port to server after logging in
    send_message(client, 'UDP_PORT', client_udp_server_port)

    print(f'Welcome to TOOM, {client_username}! '
          f'(the client should upload the UDP port number {client_udp_server_port})')

    while True:
        message = input(
            'Enter one of the following commands (MSG, DLT, EDT, RDM, ATU, OUT): \n').split(' ')
        command = message[0]
        body = ' '.join(message[1:])

        # upd command is independent of server
        if command == 'UPD':
            execute_UPD(client_username, body)
            continue
        else:
            send_message(client, command, body)

        response = loads(client.recv(2048))
        print(response['body'].strip())

        # add user information got from ATU command to user_list
        if response['type'] == 'ATU':
            for line in response['body'].strip().split('\n'):

                # get user's info from response
                # get the username of the line
                username = line.split(', ')[0]
                # get the ip address of the line
                ip_addr = line.split(', ')[1]
                # get the port number of the line
                port_number = line.split(', ')[2]

                # check if a user in user_list, update user's info if it's been added
                is_user_added = False
                for user in user_list:
                    if user['username'] == username:
                        user['ip_addr'] = ip_addr
                        user['port_number'] = port_number
                        is_user_added = True

                # if user is not in user_list, add the user
                if not is_user_added:
                    new_user = {
                        'username': username,
                        'ip_addr': ip_addr,
                        'port_number': port_number
                    }
                    user_list.append(new_user)

        if response['type'] == 'OUT':
            client.close()
            exit()


#####################################################################################################
#                                                                                                   #
#                                     Code Start                                                    #
#                                                                                                   #
#####################################################################################################


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: python3 client.py <server_IP> <server_port> <client_udp_server_port>')
        exit()
    server_IP = sys.argv[1]
    server_port = int(sys.argv[2])
    client_udp_server_port = int(sys.argv[3])

    run_client(server_IP, server_port, client_udp_server_port)
