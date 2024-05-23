import socket, sys, threading, datetime, os
import traceback, configparser, argparse, logging
import json, base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
# SECURITY FLAWS: 
# 1) Chat uses AES.MODE_ECB with no iv, meaning that all identical messages, will have the same encrypted version. SOLVED: an iv can be transmitted in plain along with a ciphertext as long as it comes out random.
# 2) There is not a way to tell how big the encryted message is gonna be for a receipent - SOLVED: I can simply send the length of the encrypted message in plain, since, if an evesdropper is listenning, he will know the length of the ENCRYPTED MESSAGE anyway.

# For some reason, if name length is less than 9 (jakesssss), it gets padded in a weird (if 'jake', then it spaces up vastly to the right) - SOLVED: simply need to remove the padding calling the 'unpad' method from Crypto.Util.Padding.

class Server:

    def __init__(self, key_dir_path='', log_file_path='') -> None:
        """ Starts the server and initiates default variables

        Args:
            * key_dir (str): A path to a folder where the server keys pair will be stored; i.e '~/Desktop/server_keys/'
            * log_file (str): An optional argument indicating a path to server's logging file; i.e '~/Desktop/serverlog.txt'
        """

        if key_dir_path:
            key_dir_path = os.path.expanduser(r'' + key_dir_path)
            if os.path.isdir(key_dir_path)==False:
                try:
                    os.mkdir(key_dir_path)
                except Exception as e:
                    print(f'Wrong path to the keypair directory ({e})')
                
        if log_file_path:
            log_file_path = os.path.expanduser(log_file_path)
            if os.path.isfile(log_file_path)==False:
                try:
                    open(log_file_path, 'a').close()
                except Exception as e:
                    print(f'Wrong path to a logging file ({traceback.format_exc()})')

        self.clients = {} # {clientsocket : (publicKey, sessionKey, nickname, authorized(True/False))}
        self.private_key = RSA.generate(2048)
        try:
            with open(key_dir_path + 'server_private_key.pem', 'wb') as f:
                f.write(self.private_key.export_key())
            self.OAEP_cipher = PKCS1_OAEP.new(self.private_key)
            self.digital_signature = pkcs1_15.new(self.private_key)

            self.public_key = self.private_key.public_key()
            with open(key_dir_path + 'server_public_key.pem', 'wb') as f:
                f.write(self.public_key.export_key())
        except Exception:
            print(f'[!] Failed to start the server ({traceback.format_exc()})')
            sys.exit(0)
        self.thread_lock = threading.Lock()

    def start(self):
        '''Creates a server socket, writes the private_key and public_key'''

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print('[*] Starting the server...')
        server_socket.bind((IP, PORT))

        server_socket.listen()
        print(f'[*] Server is listenning on {IP, PORT}')

        try:
            while True:
                client_socket, addr = server_socket.accept()

                print(f'[+] New connection from {addr}')

                self.recv_msg_thread = threading.Thread(target=self.recv_msg, args=(client_socket, addr))
                self.recv_msg_thread.start()
        except KeyboardInterrupt:
            print('[*] Shutting down the server...')
        
        sys.exit(0)
    

    def handshake(self, clientsocket, addr):
        """Initializes the client-server handshake accordingly:

        1) Client connects to the server, which immediately sends the pubKey keyword and its own pubKey
        2) Server receives client's pubKey as well as the sessKey encoded by the server's pubKey, decrypts it
        3) Server appends the clientsocket, client_pubkey and client_sessKey to the clients list
        4) The server asks for a client's nickname by an unencrypted keyword (encryption method still in development)
        5) Server receives the AES-encoded nickname, decrypts it with client's sessKey, appends it to the clients list
        6) Server notifies everyone that the client has connected under a certain name

        Args:
            * clientsocket (socket): A socket of the client, attempting to connect to the server;
            * addr (str): Client's IPv4 address provided by socket.accept()

        Return:
            * (bool): True or False depending on the authentication status of a client
        """
        try:
            clientsocket.send('%SPUBLKEY%'.encode(FORMAT))                              # Sends a keyword to the client, so the client knows what size to receive
            clientsocket.send(self.public_key.export_key('PEM'))                        # Sends the actual public key to the client
            client_pubkey = clientsocket.recv(2048)                                     # Receives the public key of the client
            client_sessKey = self.OAEP_cipher.decrypt(clientsocket.recv(256))           # Decrypts the client-encoded sessionKey
            self.thread_lock
            self.clients[clientsocket] = [client_pubkey, client_sessKey, None, False]          # Adds the session key in coherrance with the clientsocket

            clientsocket.send(KEY_TAGS['auth_begin'].encode(FORMAT))
            while True:
                response = clientsocket.recv(10).decode(FORMAT)
                if response == KEY_TAGS['auth_begin']:
                    nickname_len = int(clientsocket.recv(HEADERSIZE).decode(FORMAT))
                    # Receive the encoded nickname => remove the added padding for the CBC mode => decode it
                    iv, enc_nickname = self.unpack_msg(clientsocket.recv(nickname_len))
                    dec_cipher = AES.new(client_sessKey, AES.MODE_CBC, iv)
                    nickname = unpad(dec_cipher.decrypt(enc_nickname), AES.block_size).decode(FORMAT)
                    
                    if nickname in [nick[2] for nick in self.clients.values()]:
                        clientsocket.send('%NICKTAKN%'.encode(FORMAT))
                        clientsocket.send(KEY_TAGS['auth_begin'].encode(FORMAT))

                    elif any(x in SPECIAL_SYMS for x in [*nickname]) == False and len(nickname) <= 20:
                        self.clients[clientsocket][2] = nickname.strip()
                        clientsocket.send(KEY_TAGS['auth_accept'].encode(FORMAT))
                        self.clients[clientsocket][3] = True
                        print(f'[+] Client {addr} is now <{nickname}>')
                        self.broadcast_msg(message=f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] <{nickname}> has just connected!")
                        return True
                    else:
                        return False
                else:
                    print(f'[!] Client {addr} has failed to authenticate.')
                    clientsocket.close()
                    del self.clients[clientsocket]
                    return False

        except Exception as e:
            print(f'[!] Client {addr} has failed to connect. ({traceback.format_exc()})')
            clientsocket.close()
            del self.clients[clientsocket]
    

    def buffer_msg(self, clientsocket, msg='') -> bytes:
        """Encrypts a plain message with the session(AES) key and adds the encoded text's length at the beggining:

        (len        {'iv':'dssdwqW2==', 'data':'SDuhdwiw2231-s<_dsa'})

        Args:
            * clientsocket(socket): A socket of a client for obtaining its sessKey
            * msg(str): A message needed to be sent to a socket
        
        Returns:
            * message(bytes): A buffered, FORMAT-encoded message.
        """
        client_sessKey = self.clients[clientsocket][1]

        aes_enc_cipher = AES.new(client_sessKey, AES.MODE_CBC)
        enc_msg = aes_enc_cipher.encrypt(pad(msg.encode(FORMAT), AES.block_size))
        iv = base64.b64encode(aes_enc_cipher.iv).decode(FORMAT)
        enc_msg_send = base64.b64encode(enc_msg).decode(FORMAT)
        message = json.dumps({'iv':iv, 'data': enc_msg_send})
        message_send = f'{str(len(message)):<{HEADERSIZE}}' + message
        return message_send.encode(FORMAT)
    
    def unpack_msg(self, recved_msg=bytes()):
        """This method unpacks the json-composited message containing iv and data

        Args:
            * recved_msg(bytes): A message received from a client
        
        Returns:
            * tuple(recved_iv(bytes), recved_data(bytes)): All that's needed for decoding the recved_data with the corresponding sessKey.
        """
        recved_iv = base64.b64decode(json.loads(recved_msg)['iv'])
        recved_data = base64.b64decode(json.loads(recved_msg)['data'])
        return recved_iv, recved_data

    def recv_msg(self, clientsocket, addr):
        auth = self.handshake(clientsocket, addr)
        client_sessKey = self.clients[clientsocket][1]
        if auth == True:
            try:
                while True:
                    msg_len = clientsocket.recv(HEADERSIZE)
                    if msg_len:
                        timestamp = datetime.datetime.now().strftime('%Y-%M-%d %H:%M:%S')
                        msg_len = int(msg_len)
                        recved_msg = clientsocket.recv(msg_len)
                        iv, enc_message = self.unpack_msg(recved_msg=recved_msg)
                        aes_cipher = AES.new(client_sessKey, AES.MODE_CBC, iv)
                        message = unpad(aes_cipher.decrypt(enc_message), AES.block_size).decode(FORMAT)
                        if message == '/q':
                            clientsocket.send(KEY_TAGS['disconnect'].encode(FORMAT))
                            print(f'[-] Client <{self.clients[clientsocket][2]}> has just disconnected.')
                            self.broadcast_msg(message=f'[-] Client <{self.clients[clientsocket][2]}> has just disconnected.')
                            break
                        message = (f'[{timestamp}] <{self.clients[clientsocket][2]}>: {message}')
                        print(message)
                        self.broadcast_msg(message=message, clientsocket=clientsocket)
                
                del self.clients[clientsocket]
                clientsocket.close()
            
            except KeyboardInterrupt:
                print('[*] Shutting down the server...')
            
            except ConnectionResetError:
                print(f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected (No client response received).')
                self.broadcast_msg(message=f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected (No client response received).')

            except Exception as e:
                print(f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected ({traceback.format_exc()}).')
                self.broadcast_msg(message=f'[!] Client <{self.clients[clientsocket][2]}> has been disconnected ({traceback.format_exc()}).')
                del self.clients[clientsocket]
                clientsocket.close()

            sys.exit(0)

    
    def broadcast_msg(self, clientsocket=None, message=''):
        """Transmitts a buffered message to all connected clients

        Args:
            * clientsocket (socket): An optional argument specifying a client to whom the message should not be broadcast
            * message (bytes): A buffered message for broadcasting to the clients
        """
        for client in list(self.clients.keys()):
            if self.clients[client][3] == True: # checks whether the client is authorized
                if client == clientsocket: # message from the server is not sent to the client which has sent this message
                    client_msg = self.buffer_msg(client, message.replace(self.clients[client][2], '<You>'))
                    client.send(client_msg)
                try:
                    message_send = self.buffer_msg(client, message)
                    client.send(message_send)
                except BrokenPipeError as e:
                    print(f'[!] {self.clients[client][2]} has been disconnected ({e})')
                    del self.clients[client]
            else:
                continue
    
if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('conf.ini')
    IP = config['DEFAULTS']['IP']
    PORT = int(config['DEFAULTS']['PORT'])
    FORMAT = config['DEFAULTS']['FORMAT']
    HEADERSIZE = int(config['DEFAULTS']['HEADERSIZE'])
    KEYPAIR_DIR = config['DEFAULTS']['KEYPAIR_DIR']
    LOGGING_DIR = config['DEFAULTS']['LOGGING_FILE']

    KEY_TAGS = {'auth_begin':'%AUTHINIT%', 'auth_accept':'%AUTHACCP%', 'disconnect':'%DISCONNT%'}
    SPECIAL_SYMS = [",", ".", "/", "|", "{", "}", "'", "[", "]", "<", ">", "$", "%"]

    Server(key_dir_path=KEYPAIR_DIR, log_file_path=LOGGING_DIR).start()
    
