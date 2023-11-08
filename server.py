import socket
from termcolor import colored
from threading import Thread
from Crypto.Cipher import AES
import rsa
from random import choices

def handle_connection(client : dict, addr):
    global clients
    conn = client["conn"]
    conn.settimeout(1)
    while True:
        try:
            text = recv_message(client)

        except (TimeoutError, socket.timeout):
            continue

        except Exception as e:
            print(e.with_traceback(None))
            conn.close()
            clients.remove(client)
            print(f"{addr} - {client['private_addr']} disconnected")
            return

        if not text: continue
        with open(f"{addr}.txt", "a") as f:
            f.write(text)
            f.flush()
        

def exchange_keys(conn : socket.socket):
    global public_key, aes_key

    try:
        conn.sendall( public_key.save_pkcs1() )
        client_key = rsa.PublicKey.load_pkcs1( conn.recv(1024) )

        conn.sendall( rsa.encrypt(aes_key, client_key) )

        private_ip = recv_message( {"conn": conn} )
    
    except ConnectionResetError:
        return None
    
    client = {
        "conn": conn,
        "addr": None,
        "private_addr": private_ip,             # nickname is defined in handle_connection()
        "key": client_key
    }

    # clients.append(client)
    return client
    
def recv_message(client : dict) -> str:
    return aes_decrypt( 
        client["conn"].recv(1024)
    )

def generate_aes_key() -> bytes:
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.,*/?!$&%()'
    return "".join( choices(chars, k=16) ).encode()

def aes_encrypt(message : str) -> bytes:
    global aes_key
    if "str" in str(type(message)):
        message = message.encode()
    iv = b"fw%Su!ap6#RppD(6"
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message)
    return (iv + ciphertext)

def aes_decrypt(ciphertext : bytes) -> str:
    global aes_key
    if "str" in str(type(ciphertext)):
        ciphertext = ciphertext.encode()
    # iv = b"fw%Su!ap6#RppD(6"
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:]).decode('utf-8', errors='ignore')
    return plaintext

def main():
    HOST = ""
    PORT = 54321

    global RSA_KEY_LEN
    RSA_KEY_LEN = 1024

    global clients
    clients = []

    global aes_key
    aes_key = generate_aes_key()

    global public_key, private_key
    public_key, private_key = rsa.newkeys(RSA_KEY_LEN)
 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print(colored("=> Server started", "green"))
        s.settimeout(2)
        try:
            s.listen(1)
            while True:
                try:
                    conn, addr = s.accept()
                except (TimeoutError, socket.timeout):
                    continue
                
                client = exchange_keys(conn)
                if not client:
                    continue

                clients.append(client)
                print(f"{addr[0]} - {client['private_addr']} connected")
                Thread(target=handle_connection, args=(client,addr[0])).start()

        except KeyboardInterrupt:
            pass

    print(colored("=> Server stopped", "red"))
    exit(0)

if __name__ == '__main__':
    main()