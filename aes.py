# author: xosval03

import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


#https://stackoverflow.com/questions/64203881/implementing-aes-ecb-pkcs5-padding-in-python
def custom_padding(message, block_size):
    padding_size = block_size - (len(message) % block_size)
    padding = bytes([padding_size]) * padding_size
    return message + padding

def custom_unpadding(message):
    padding_size = message[-1]
    padding = message[-padding_size:]
    for byte in padding:
        if byte != padding_size:
            raise ValueError("Invalid padding.")
    return message[:-padding_size]

#16 use /dev/urandom about lenght of 16 bajts
def AES_generate_key(lenght):
    return os.urandom(lenght)

#https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples
def AES_encrypt(plaintext, key):
    # Generate a random 16-byte initialization vector
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(custom_padding(plaintext, AES.block_size))
    return iv + ciphertext

def AES_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = custom_unpadding(cipher.decrypt(ciphertext[16:]))
    return plaintext

