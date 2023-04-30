from Crypto.PublicKey import RSA
import os
key = RSA.generate(2048)

private_key = key.export_key()
with open(os.path.join('cert','sender_private_key.pem'), 'wb') as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open(os.path.join('cert','sender_public_key.pem'), 'wb') as f:
    f.write(public_key)



key = RSA.generate(2048)

private_key = key.export_key()
with open(os.path.join('cert','reciever_private_key.pem'), 'wb') as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open(os.path.join('cert','reciever_public_key.pem'), 'wb') as f:
    f.write(public_key)
    
