import socket
from base64 import b64encode
from threading import Thread
import DSA_Algorithm
import RSA_Algorithm
from RSA_Algorithm import keygen

HEADER_LENGTH = 10
client_socket = None

y = None
p = None
q = None
g = None

# Connects to the server
def connect(ip, port, my_username, error_callback):
    global client_socket
    global y
    global p
    global q
    global g

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
    except Exception as e:
        error_callback('Connection error: {}'.format(str(e)))
        return False

    pubkey, privkey = keygen(2 ** 64)
    encrypted_username = RSA_Algorithm.encode(my_username, pubkey, 1)
    f = open("private_keys.txt", "a")
    encrypted_username_decoded_string = b64encode(encrypted_username).decode()
    f.write(encrypted_username_decoded_string + "|" + RSA_Algorithm.key_to_str(privkey) + '\n')
    f.close()
    public_key = RSA_Algorithm.key_to_str(pubkey)
    username_param = encrypted_username_decoded_string + "|" + public_key
    username_header = f"{len(username_param):<{HEADER_LENGTH}}".encode('utf-8')
    print("username header:",username_header)
    client_socket.send(username_header + username_param.encode())

    dsa_keys_header = client_socket.recv(HEADER_LENGTH)
    print("dsa keys header", dsa_keys_header)
    dsa_keys_length = int(dsa_keys_header.decode('utf-8').strip())
    dsa_keys = client_socket.recv(dsa_keys_length).decode('utf-8')
    print(dsa_keys)

    dsa_keys = dsa_keys.split('|')
    y = int(dsa_keys[0])
    p = int(dsa_keys[1])
    q = int(dsa_keys[2])
    g = int(dsa_keys[3])
    return True


def send(message):

    message = message.encode('utf-8')
    file = open("private_keys_DSA.txt", "r")
    x = int(file.read())
    print("Type of x:",type(x))
    print(x)
    r, s = DSA_Algorithm.sign(message, p, q, g, x)
    message_with_digital_signature = (str(r) + "|" + str(s) + "|" + message.decode())
    message_header = f"{len(message_with_digital_signature):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message_with_digital_signature.encode())

def start_listening(incoming_message_callback, error_callback):
    Thread(target=listen, args=(incoming_message_callback, error_callback), daemon=True).start()


def listen(incoming_message_callback, error_callback):
    while True:

        try:
            while True:

                username_header = client_socket.recv(HEADER_LENGTH)

                if not len(username_header):
                    error_callback('Connection closed by the server')

                username_length = int(username_header.decode('utf-8').strip())

                username = client_socket.recv(username_length).decode('utf-8')

                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = client_socket.recv(message_length).decode('utf-8')

                incoming_message_callback(username, message)

        except Exception as e:
            error_callback('Reading error: {}'.format(str(e)))
