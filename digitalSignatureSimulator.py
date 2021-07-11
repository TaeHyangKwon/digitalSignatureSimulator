from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

AlicePrivKey = RSA.generate(2048)
f = open('AlicePrivKey.pem', 'wb')
f.write(AlicePrivKey.export_key('PEM', passphrase="!@#$"))
f.close()
f = open('AlicePubKey.pem', 'wb')
f.write(AlicePrivKey.public_key().export_key('PEM'))
f.close()

f = open('AlicePrivKey.pem', 'r')
AlicePrivKey = RSA.import_key(f.read(), passphrase="!@#$")
f.close()

message = 'To be signed'
h = SHA256.new(message.encode('utf-8'))
signature = pkcs1_15.new(AlicePrivKey).sign(h)
print("Alice sent (", message, signature, ") to Bob.")

f = open('AlicePubKey.pem', 'r')
AlicPubKey = RSA.import_key(f.read())
f.close()

print("Bob received message (", message, signature, ") from Alice.")
h = SHA256.new(message.encode('utf-8'))
try:
    pkcs1_15.new(AlicPubKey).verify(h, signature)
    print("The signature is valid")
except(ValueError, TypeError):
    print("The signature is not valid")
