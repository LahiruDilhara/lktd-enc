from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# print(Fernet(base64.urlsafe_b64decode("asdfasdfasdf")))

kdf = PBKDF2HMAC(
    # the algorithm is used to hash the password and salt to produce a key.
    algorithm=hashes.SHA512(),
    length=32,
    salt=b"hello",
    # Iterations refer to the number of times the KDF function performs its operations. Increasing the number of iterations makes the key derivation process slower, which increases resistance to brute-force attacks.
    iterations=10000,
    backend=default_backend()
)
kdf1 = PBKDF2HMAC(
    # the algorithm is used to hash the password and salt to produce a key.
    algorithm=hashes.SHA512(),
    length=32,
    salt=b"hello",
    # Iterations refer to the number of times the KDF function performs its operations. Increasing the number of iterations makes the key derivation process slower, which increases resistance to brute-force attacks.
    iterations=10000,
    backend=default_backend()
)

key = kdf.derive(b"hello world")
key1 = kdf1.derive(b"hello nano")
print(key)
print(base64.urlsafe_b64encode(key))

encdec = Fernet(base64.urlsafe_b64encode(key))
encdec1 = Fernet(base64.urlsafe_b64encode(key1))
data = encdec.encrypt(b"lahiru")
data1 = encdec1 .encrypt(b"asdfasdfsdfsd")
# print(encdec.decrypt(data1))

file = "/home/lahiru.dilhara.enc.enc"
print(os.path.basename(file).replace(".enc","",1))