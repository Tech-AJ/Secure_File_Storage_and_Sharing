# Secure_File_Storage_and_Sharing
This is implemented as part of CS628A Assignment.

This includes designing and implementation of cryptographically secure file storage and sharing (encrypted Dropbox/ GoogleDrive).  
Also users can revoke the share access.

Supported Functionalities :\
-> User Creation and Login  
-> Storing Files\
-> Loading Files\
-> Efficiently Appending to Files\
-> Give Acess to your file to someone else - 'share access'\
-> Revoke 'share access' from someone you previously shared the file with

Cryptographic primitives used are -  
-> AES encryption (for confidentiality)  
-> RSA encryption and signature verification (for authentication)  
-> HMAC (for Integrity)  
-> Argon2key for password hashing(to prevent brute force attack )

This is implemented in Golang.

Check Design Document for more details.
