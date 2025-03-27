# File Encryption Send Receive
In this project, I developed a program that simulates a secure message send and receive processes. In the first step, an asymmetric key exchange using the Needham-Schroeder Key-Exchange model occurs through a "Key Distribution Center" process. These symmetric keys are used by Amal (the sender process) and Basim (the receiver process). Using AES-256 in Cipher Block Chaining mode with a 128-bit Initialization Vector, Amal securely encrypts the file to be sent. The file is sent to Basim via pipe, where it is received and decrypted. This was a team project that was developed for my Information Security (CS-457) class at JMU.

## My Contributions
In this project, I developed the file encryption and decryption functions in the myCrypto.c file, the receipt and processing of messages in the basim.c file, the construction and sending of the encryption message in the kdc.c file, and a portion of the dispatcher.c file involving forking children processes, execing amal, basim, and the KDC, and setting up pipes between the processes for inter-process communication.

## Other Contributors
This project was designed by my CS-457 Professor, Dr. Mohamed Aboutabl. Dr. Aboutabl designed the structure of the project as a whole, created the majority of the dispatcher.c file, myCrypto.h header file, and the wrappers.c and wrappers.h files. Additionally, he wrote the makefile and provided guiding comments throughout the project files.
This was a team project. My partner, Mason Puckett, wrote many of the message construction and receipt utility functions in the myCrypto.c file and the creation and sending of messages in the amal.c file.

## Skills demonstrated
1. C Programming Language
2. OpenSSL Cryptography Library
3. Confidentiality (Symmetric/Asymmetric key encryption and decryption) and Integrity (Digital Signature)
4. Process creation and inter-process communication
5. Systems Application Development