# **Game Protection Module**
## **Overview**
Interceptor-extender for the game client, in order to encrypt outgoing traffic and block unwanted software.

1) interception of network traffic functions, processing some data to perform the accompanying logic
2) improved security, new stream traffic encryptor client<->server https://ru.wikipedia.org/wiki/Rabbit
3) checking for data substitution/checking execution outside the context of the calling thread
4) sending CPU/HDD/MAC numbers to the server
5) ping-pong status with the server
6) protection from debuggers/dumpers etc.
7) method of replacing encryption and inserting a new key when a character moves from server to server (hook)
