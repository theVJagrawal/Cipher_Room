# Cipher_Room
Chat room command-line application with secure communication using Sockets, handled multiple client connections via Multi-threading for increased responsiveness, and ensured robust confidentiality using AES and RSA algorithms.
This project's main objective for me was to learn the basics of the Public Key cryptography utilized in our day-to-life, primarily utilizing online chatting and web interactions.

# Dependencies

## PyCryptodome
This library is used for RSA, AES encryption. Official API documentation: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

***All other libraries utilized in the project are python-built-in. You can find a complete list in requirements.txt***

# Demonstration
1) Starting the server with the following command: ```python3 server.py```
<img width="400" alt="Screenshot 2022-11-23 at 4 53 48 PM" src="https://user-images.githubusercontent.com/102734242/203565103-641941b7-946e-4ea5-ae63-0ebbdeada9d0.png">
2) After the server started listenning on certain IP address and port, we can connect the client script by executing this command: ```python3 client.py -i 127.0.0.1 -p 5555 -k ~/Desktop/client_keys``` (the variables can change depending on your conf.ini values)
<img width="521" alt="Screenshot 2022-11-23 at 4 54 35 PM" src="https://user-images.githubusercontent.com/102734242/203566335-e64c03ec-c52c-433d-837e-57271c88ddb8.png">
<img width="520" alt="Screenshot 2022-11-23 at 4 55 07 PM" src="https://user-images.githubusercontent.com/102734242/203566572-75e4d478-9a67-4f68-a07d-08b6af750bcf.png">
3) Server output will look the following way after a client has successfully authorized:<img width="499" alt="Screenshot 2022-11-23 at 4 55 19 PM" src="https://user-images.githubusercontent.com/102734242/203566603-7cd04bc8-e772-4b3f-b131-84e8d3df85e3.png">
