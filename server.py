import hashlib
import socket
import os
from aes import AES_decrypt

from rsa import open_key, rsa_decrypt 

def server_hash_md5(message):
    md5_hash = hashlib.md5()
    md5_hash.update(message.encode('utf-8'))
    digest = md5_hash.hexdigest()
    return digest


def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port)
    server_socket.bind(server_address)
    server_socket.listen(1)
    print(f"Server listening on port {port}")
    connection, client_address = server_socket.accept()

    while True:

        #print(f"Connection from {client_address}")
        print("Client has joined")
        
        received_data = connection.recv(1024)
        if not received_data:
            break

        # Loading of RSA keys
        folder_cert = "cert"
        path_send_pub = os.path.join(folder_cert,"sender_public_key.pem")
        #path_send_priv = os.path.join(folder_cert,"sender_private_key.pem")
        path_rec_pub = os.path.join(folder_cert,"reciever_public_key.pem")
        path_rec_priv = os.path.join(folder_cert, "reciever_private_key.pem")

        send_pub = open_key(path_send_pub)
        #send_priv = open_key(path_send_priv)
        rec_pub = open_key(path_rec_pub)
        rec_priv = open_key(path_rec_priv)

        print(f"RSA_public_reciever={bytes.hex(rec_pub.export_key())}")
        print(f"RSA_private_reciever={bytes.hex(rec_priv.export_key())}")
        print(f"RSA_public_sender={bytes.hex(send_pub.export_key())}")
        print(f"ciphertext={bytes.hex(received_data)}")



        # Decrypting 
        AES_cipher = received_data[:-256]
        RSA_AES_key = received_data[-256:]
        print(f"RSA_AES_key={bytes.hex(RSA_AES_key)}")
        print(f"AES_cipher={bytes.hex(AES_cipher)}")
        decrypted_AES_key = rsa_decrypt(RSA_AES_key, rec_priv)
        #decrypted_AES_key = custom_unpadding(decrypted_AES_key_padded)
        decrypted_data = AES_decrypt(AES_cipher, decrypted_AES_key).decode()

        message = decrypted_data[:-32]
        client_message_hash_md5 = decrypted_data[-32:]
        client_message_hash_md5 = client_message_hash_md5.encode()

        print(f"text_hash={message+str(client_message_hash_md5)}")
        print(f"plaintext={message}")
        print(f"MD5={client_message_hash_md5}")

        # Verifying the hash
        client_message_hash_md5 = client_message_hash_md5.decode()

        server_message_hash_md5 = server_hash_md5(message)
        if server_message_hash_md5 == client_message_hash_md5:

            print("The integrity of the message has not been compromised.”")
        else:
            print("The integrity of the report has been compromised")
