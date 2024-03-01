# import crypt # just in Unix

# plain_pass = input("What is the password? ")
# salt = input("what is the salt? ")

# print("MD5    :{0}", format(crypt.crypt(plain_pass, "$1$" + salt)) )
# print("Blowfish    :{0}", format(crypt.crypt(plain_pass, "$2$" + salt)) )
# print("eksblofish   :{0}", format(crypt.crypt(plain_pass, "$2a$" + salt)) )
# print("SHA-256    :{0}", format(crypt.crypt(plain_pass, "$5$" + salt)) )
# print("SHA-512    :{0}", format(crypt.crypt(plain_pass, "$6$" + salt)) )

#-----------------------------------------------------------------------------#


# import argparse
# import hashlib

# password = input("Enter password: ")
# salt = input("Enter salt: ")

# parser = argparse.ArgumentParser(description="Hash Passwords")
# parser.add_argument("password", help="the password to hash")
# parser.add_argument("salt", default="sha256", choices=["md5", "sha256", "sha512"])
# args = parser.parse_args()

# password =args.password
# salt = args.salt



# x =getattr(hashlib, salt)()
# x.update(password.encode())

# print("salt: " + salt)
# print(x.hexdigest())

#----------------------------------------------------------------------#

# import hashlib

# # Prompt the user for password and salt
# password = input("Enter password: ")
# salt = input("Enter salt: ")

# # Choose a hashing algorithm (e.g., SHA-256)
# hash_algorithm = hashlib.sha512()

# # Update the hash with the password and salt
# hash_algorithm.update(password.encode() + salt.encode())

# # Print the salt and the hashed password
# print("Salt:", salt)
# print("Hashed Password:", hash_algorithm.hexdigest())

#----------------------------------------------------------------------#

# from passlib.hash import pbkdf2_sha512

# password = input("Enter password: ")
# hashed_pass = pbkdf2_sha512.hash(password)

# print(hashed_pass)
#----------------------------------------------------------------------#

import hashlib, binascii, os

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    password_hash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    password_hash = binascii.hexlify(password_hash)
    return (salt + password_hash).decode('ascii')

def verify_password(stored_password, user_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    password_hash = hashlib.pbkdf2_hmac('sha512', user_password.encode('utf-8'), salt.encode('ascii'), 100000)
    password_hash = binascii.hexlify(password_hash).decode('ascii')
    return password_hash == stored_password

stored_password = hash_password('Mypassword')
print(stored_password)
print(verify_password(stored_password, 'Mypassword'))
print(verify_password(stored_password, 'Mispassword'))
    