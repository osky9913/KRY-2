#author : xosval03
import socket
import hashlib
import os
from aes import AES_generate_key,AES_encrypt
from rsa import custom_padding, open_key,rsa_encrypt

def client_hash_md5(message):
    md5_hash = hashlib.md5()
    md5_hash.update(message.encode('utf-8'))
    digest = md5_hash.hexdigest()
    return digest


def start_client(port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('localhost', port)

    try:
        client_socket.connect(server_address)
        print(f"Successfully connected server")
    except socket.error as msg:
        print ("Couldnt connect with the socket-server: %s\n terminating program" % msg)
        exit(1)


    #Loading of RSA keys
    folder_cert = "cert"
    path_send_pub = os.path.join(folder_cert,"sender_public_key.pem")
    path_send_priv = os.path.join(folder_cert,"sender_private_key.pem")
    path_rec_pub = os.path.join(folder_cert,"reciever_public_key.pem")
    #path_rec_priv = os.path.join(folder_cert, "reciever_private_key.pem")

    send_pub = open_key(path_send_pub)
    send_priv = open_key(path_send_priv)
    rec_pub = open_key(path_rec_pub)
    #rec_priv = open_key(path_rec_priv)

    
    print(f"RSA_public_key_sender={bytes.hex(send_pub.export_key()) }")
    print(f"RSA_private_key_sender={bytes.hex(send_priv.export_key())}")
    print(f"RSA_public_key_receiver={bytes.hex(rec_pub.export_key())}")
    while True:
        message = input("Enter input: ")
        AES_key = AES_generate_key(16)
        print(f"AES_key={bytes.hex(AES_key)}")
        AES_key_padding = custom_padding(AES_key)
        print(f"AES_key_padding={bytes.hex(AES_key_padding)}")
        

        client_message_hash_md5 = client_hash_md5(message)
        client_message_hash_md5 = client_message_hash_md5.encode()
        print(f"MD5={bytes.hex(client_message_hash_md5)}")
        padded_client_message_hash_md5 = custom_padding(client_message_hash_md5)
        print(f"MD5_padding={bytes.hex(padded_client_message_hash_md5)}")


        RSA_MD5_hash = rsa_encrypt(padded_client_message_hash_md5,send_priv)
        print(f"RSA_MD5_hash={bytes.hex(RSA_MD5_hash)}")
        AES_cipher = AES_encrypt((message+client_message_hash_md5.decode()).encode(),AES_key)
        print(f"AES_cipher={bytes.hex(AES_cipher)}")
        RSA_AES_key = rsa_encrypt(AES_key_padding,rec_pub)
        print(f"RSA_AES_key={bytes.hex(RSA_AES_key)}")
        """
        experiments
        

        decrypted_AES_key_padded = rsa_decrypt(RSA_AES_key, rec_priv)
        print(f"decrypted_AES_key_padded={bytes.hex(decrypted_AES_key_padded)}")
        decrypted_AES_key = custom_unpadding(decrypted_AES_key_padded)
        print(f"decrypted_AES_key={decrypted_AES_key}")

        end of experiments
        """
        ciphertext = AES_cipher+RSA_AES_key
        print(f"ciphertext={bytes.hex(ciphertext)}")
        client_socket.sendall(ciphertext)



        # clean up
        #client_socket.close()




