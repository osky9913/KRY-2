from Crypto.PublicKey import RSA
import random 

#Opening keys from key path and return it as a object
def open_key(key_path):
    with open(key_path, "rb") as k:
        key = RSA.importKey(k.read())
        return key
    
# padding in RSA  basiccaly append bytes before the message unless the lenght is 2048//8   
def custom_padding(m, key_length=2048//8):
    padding_length = key_length - len(m) - 3
    pad = b''
    while len(pad) < padding_length:
        random_byte = random.randint(1, 255)
        pad += bytes([random_byte])
    
    padded_message = b'\x00\x02' + pad + b'\x00' + m
    return padded_message

"""
NOT using moved to rsa decrypt 
def custom_unpadding(padded_message):
    padding_index = padded_message.index(b'\x00', 2)
    message = padded_message[padding_index + 1:]
    return message
"""

# RSA encrypt based of pow 
def rsa_encrypt(m, public_key):
    padded_m_int = int.from_bytes(m, byteorder='big')
    ciphertext = pow(padded_m_int, public_key.e, public_key.n)
    ciphertext_bytes = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, byteorder='big')
    return ciphertext_bytes

#Rsa decrypt based on pow  also adding unpadding for RSA
def rsa_decrypt(ciphertext, private_key):
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
    padded_message_int = pow(ciphertext_int, private_key.d, private_key.n)
    padded_message = padded_message_int.to_bytes((padded_message_int.bit_length() + 7) // 8, byteorder='big')
    padding_index = padded_message.index(b'\x00', 2)
    message = padded_message[padding_index+1:]
    return message

