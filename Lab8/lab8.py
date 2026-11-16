import hashlib
import uuid
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto import Random
from cryptography.fernet import Fernet 

# Part A
# password = input("Enter a password: ")
# hash_object = hashlib.md5(password.encode())
# print("SHA-256 hash:", hash_object.hexdigest())

# def hash_password(password):
#     salt = uuid.uuid4().hex
#     hashed = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
#     return hashed + ":" + salt

# def check_password(stored_password, user_input):
#     hashed, salt = stored_password.split(":")
#     return hashed == hashlib.sha256(salt.encode() + user_input.encode()).hexdigest()

# password = input("Enter password: ")
# stored = hash_password(password)
# print("Stored:", stored)
# verify = input("Re-enter password: ")
# print("Match:", check_password(stored, verify))


# Part B
# key = "mycipher".encode("utf8")  # 8 bytes
# message = "hello".encode("utf8")  # 8 bytes

# message = message.ljust(8, b' ')

# cipher = DES.new(key, DES.MODE_ECB)
# cipher_text = cipher.encrypt(message)
# print("Encrypted:", cipher_text)

# plain_text = cipher.decrypt(cipher_text)
# print("Decrypted:", plain_text.decode())


# Part C
# AES-128 requires a 16-byte key
# key = "secret-key-".encode("utf8").ljust(16, b' ')
# iv = "This is an IV".encode("utf8").ljust(16, b' ')

# cipher = AES.new(key, AES.MODE_CBC, iv)
# # Data must be a multiple of 16 bytes
# message = "This is a secret message for ".encode("utf8")
# message = message.ljust((len(message) + 15) // 16 * 16, b' ')

# cipher_text = cipher.encrypt(message)
# print(f"AES Encrypted: {cipher_text.hex()}")

# # Decrypt using the same IV
# decipher = AES.new(key, AES.MODE_CBC, iv)
# plain_text = decipher.decrypt(cipher_text)
# print(f"Decrypted: {plain_text.decode().strip()}")


# Part D 
# password = "mypassword"
# salt = Random.new().read(16)
# salt = b'fixedsalt123456'

# key = PBKDF2(password, salt, dkLen=16, count=100000)
# print("Key:", key)


# Part E
# key = Fernet.generate_key()
# cipher = Fernet(key)

# message = "Secret message".encode()
# encrypted = cipher.encrypt(message)
# print("Encrypted:", encrypted)

# # Generate a new key (considered as modified)
# key = Fernet.generate_key()
# cipher = Fernet(key)

# decrypted = cipher.decrypt(encrypted)
# print("Decrypted:", decrypted.decode())


# Part F1
# target_hash = "81dc9bdb52d04dc20036dbd8313ed055"

# print("Starting Brute Force Attack...")

# for i in range(10000):
#     pin = str(i).zfill(4)
#     hashed_pin = hashlib.md5(pin.encode()).hexdigest()

#     if hashed_pin == target_hash:
#         print("PIN found:", pin)
#         break


# Part F2
key = "security".encode("utf8")
cipher = DES.new(key, DES.MODE_ECB)

# Encrypting two separate data packets
packet_1 = "DATA_REQ".encode("utf8")
packet_2 = "DATA_REQ".encode("utf8")

print(f"Packet 1 Ciphertext: {cipher.encrypt(packet_1).hex()}")
print(f"Packet 2 Ciphertext: {cipher.encrypt(packet_2).hex()}")