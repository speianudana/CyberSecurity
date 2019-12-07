import socket
import select
from base64 import b64decode
import DSA_Algorithm
import RSA_Algorithm

HEADER_LENGTH = 10
y = None
p = None
q = None
g = None

IP = "127.0.0.1"
PORT = 1234
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))

server_socket.listen()

sockets_list = [server_socket]

clients = {}

text_io = open("private_keys.txt", "w")
text_io.close()
f = open("private_keys_DSA.txt", "w")

p, q, g = DSA_Algorithm.generate_params()
x, y = DSA_Algorithm.generate_keys(g, p, q)

f.write(str(x))
f.close()
print(f'Listening for connections on {IP}:{PORT}...')


def receive_message(client_socket):
    global y
    global p
    global q
    global g
    try:

        message_header = client_socket.recv(HEADER_LENGTH)

        if not len(message_header):
            return False

        message_length = int(message_header.decode('utf-8').strip())

        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:

        return False


while True:

    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    for notified_socket in read_sockets:
        if notified_socket == server_socket:

            client_socket, client_address = server_socket.accept()
            user = receive_message(client_socket)
            file = open("private_keys.txt", "r")
            user_name_data = user['data'].decode().split('|')
            is_user_authenticated=False
            for line in file:
                line_split = line.split("|")
                if line_split[0] == user_name_data[0]:
                    private_key_from_file = line_split[1].replace("\n", "")
                    username_received_from_client = b64decode(user_name_data[0])
                    decoded_username = RSA_Algorithm.decode(username_received_from_client,
                                                            RSA_Algorithm.str_to_key(private_key_from_file), 1)
                    user['data'] = decoded_username.encode()
                    print(decoded_username)
                    user['header'] = f"{len(decoded_username):<{HEADER_LENGTH}}".encode('utf-8')
                    is_user_authenticated=True
            if user is False and not is_user_authenticated:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user
            print(user)
            dsa_keys = str(y) + "|" + str(p) + "|" + str(q) + "|" + str(g)
            dsa_keys_header = f"{len(dsa_keys):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(dsa_keys_header + dsa_keys.encode())
            print('Accepted new connection from {}:{}, username: {}'.format(*client_address,
                                                                            user['data'].decode('utf-8')))

        else:
            message = receive_message(notified_socket)

            print(message)
            data = message["data"].decode('utf-8').split("|")
            r = data[0]
            s = data[1]
            message_data = data[2]

            if message is False and not DSA_Algorithm.verify(message_data, r, s, p, q, g, y):
                print('Closed connection from: {}'.format(clients[notified_socket]['data']))

                sockets_list.remove(notified_socket)

                del clients[notified_socket]

                continue

            user = clients[notified_socket]

            print(f'Received message from {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')

            for client_socket in clients:

                if client_socket != notified_socket:

                    client_socket.send(user['header'] + user['data'] + message['header'] + message_data.encode())

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)

        del clients[notified_socket]
