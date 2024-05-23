import os, sys, socket, threading, traceback, argparse, logging
import json, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Client:
    def __init__(self, key_dir='', log_dir=''):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.nickname = ''
        self.recv_msg_thread = threading.Thread(target=self.recv_msg,)
        self.send_msg_thread = threading.Thread(target=self.send_msg,)

        if log_dir:
            logging.basicConfig(filename=os.path.expanduser(log_dir), encoding='utf-8', level=logging.INFO,)

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.public_key()
        try:
            if key_dir.endswith('/') == False:
                key_dir += '/'
            with open(key_dir + 'private_key.pem', 'wb') as f:
                f.write(self.private_key.export_key("PEM"))
            with open(key_dir + 'public_key.pem', 'wb') as f:
                f.write(self.public_key.export_key("PEM"))
        except:
            print(f'[!] Failed to write keypair files ({traceback.format_exc()})')
        

        self.session_key = get_random_bytes(16)

    def main(self):
        try:
            print(f'Trying to connect to {ADDRESS}')
            logging.info(f'Trying to connect to {ADDRESS}')
            self.client_socket.connect(ADDRESS)
            print(f'Successfully connected to {ADDRESS}')
            logging.info(f'Successfully connected to {ADDRESS}')
            self.handshake()
        except Exception as e:
            print(f'Connection has failed ({e})...')
            logging.error(f'Connection has failed ({e})...')
            self.client_socket.close()
    
    def buffer_msg(self, msg='') -> bytes:
        """Encrypts a plain message with the session(AES) key and adds the encoded text's length at the beggining.

        Args:
            msg(str): A message needed to be sent to a socket
        
        Returns:
            message(bytes): A buffered, FORMAT-encoded message.
        """

        aes_enc_cipher = AES.new(self.session_key, AES.MODE_CBC)
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

    def handshake(self):
        global SPECIAL_SYMS
        global KEY_TAGS
        print('[*] Initiating the handshake..')
        logging.info('[*] Initiating the handshake..')
        try:
            while True:
                print('[*] Waiting for a server response..')
                logging.info('[*] Waiting for a server response..')

                response = self.client_socket.recv(HEADERSIZE).decode(FORMAT)
                print(f'[i] Server response: {response}')
                logging.info(f'[i] Server response: {response}')
                if response == '%SPUBLKEY%':
                    server_pubkey = self.client_socket.recv(2048)
                    print('[i] Server pubKey has been received..')
                    logging.info('[i] Server pubKey has been received..')
                    self.OAEP_encr_server = PKCS1_OAEP.new(RSA.import_key(server_pubkey))
                    print('[i] Sending client PubKey..')
                    logging.info('[i] Sending client PubKey..')
                    self.client_socket.send(self.public_key.export_key())
                    print('[i] Sending client SessionKey..')
                    logging.info('[i] Sending client SessionKey..')
                    self.client_socket.send(self.OAEP_encr_server.encrypt(self.session_key))
                    print('[i] Client Session Key has been sent.')
                    logging.info('[i] Client Session Key has been sent.')
                if response == '%AUTHINIT%':
                    while True:
                        self.nickname = input('[+] Enter your preffered name (20 characters or less): ')
                        if len(self.nickname) <= 20 and any(x in SPECIAL_SYMS for x in [*self.nickname]) == False: ## '[*somevariable]' just converts the variable into a list of its symbols
                            self.client_socket.send('%AUTHINIT%'.encode(FORMAT))
                            self.client_socket.send(self.buffer_msg(self.nickname))
                            break
                        else:
                            print('[!] The name should be 20 characters or less and shouldn not contain special characters')
                if response == '%NICKTAKN%':
                    print('[!] This nickname is taken. Try another one.')
                if response == '%AUTHACCP%':
                    self.send_msg()
        except Exception as e:
            print(f'Connection has failed ({traceback.format_exc()})...')
            self.client_socket.close()

    def send_msg(self):
        """This method is responsible for handling user's input and rendering it into the protocol-accepted version."""
        self.recv_msg_thread.start()
        try:
            while True:
                message = input(f'')
                message_send = self.buffer_msg(message)
                self.client_socket.send(message_send)
        except BrokenPipeError:
            sys.exit(0)

    def recv_msg(self):
        try:
            while True:
                msg_len = self.client_socket.recv(HEADERSIZE).decode(FORMAT)
                if msg_len:
                    msg_len = int(msg_len)
                    recved_message = self.client_socket.recv(msg_len)
                    iv, enc_message = self.unpack_msg(recved_message)
                    aes_cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
                    message = unpad(aes_cipher.decrypt(enc_message), AES.block_size).decode(FORMAT)
                    if message == '%DISCONNT%':
                        break
                    print(f'{message}')
            print('[-] You have been disconnected')
            sys.exit(0)
        except ConnectionResetError as e:
            print(f'[!] The connection has been abrupted ({e})')
            sys.exit(0)
        except BrokenPipeError:
            print('[!] The server is not reachable.')
            sys.exit(0)

if __name__ == '__main__':
    FORMAT = 'utf-8'
    HEADERSIZE = 10
    SPECIAL_SYMS = []
    parser = argparse.ArgumentParser('client.py', description='The StealthPyChat Client Application')
    parser.add_argument("-i", "--IP", type=str, required=True, help="(str)Defines an IPv4 address of the server, i.e 127.0.0.1")
    parser.add_argument("-p", "--PORT", type=int, required=True, help='(int)Defines a port of the server, i.e 5555')
    parser.add_argument("-k", "--keydir", type=str, required=True, help='(str)Specifies the path to the keypair directory, i.e ~/Desktop/client_keys/')
    parser.add_argument("-l", "--logfile", type=str, required=False, help='Optional: (str)Specifies a logfile directory.')
    args = parser.parse_args()
    ADDRESS = (args.IP, args.PORT)
    KEY_DIR = os.path.expanduser(args.keydir)
    if os.path.isdir(KEY_DIR) == False:
        try:
            os.mkdir(KEY_DIR)
        except Exception:
            print(f'[!] Failed to initialize the connection ({traceback.format_exc()})')

    if args.logfile:
        LOG_DIR = os.path.expanduser(args.logfile)
        if os.path.isfile(LOG_DIR) == False:
            try:
                open(LOG_DIR, 'w').close()
            except:
                print(f'[!] Failed to initialize the connection ({traceback.format_exc()})')
        else:
            open(LOG_DIR, 'w').close()
    else:
        LOG_DIR = ''

    Client(key_dir=KEY_DIR, log_dir=LOG_DIR).main()
