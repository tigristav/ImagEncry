# ImagEncry
A script that utilizes LSB-steganography to hide encrypted messages in images.

Disclaimer: this script was not made with the intention of being efficient/serious or even well thought out. Choices made were based on learning and implementing what I've learned.

RSA encryption was chosen purely for learning purposes and does not work with larger messages since it is limited by the modulus of it's public key. Current value is 2048 which would allow for a message limit of 245 bytes (excluding padding which brings it to 256 bytes). The current implementation also uses base64 encoding to hide the message before encrypting it, however this increases the size of the message of approx ~33% so in reality the available message size is less than 245 bytes. 
