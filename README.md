# mineid-authserver
It's a fake Minecraft server that authenticates connections with Mojang's session
server and works as an authentication tool to prove a Minecraft account belongs
to you. This relies on no currently existing Minecraft protocol libraries and 
is completely open and free to use. The aim of this project is to be stable and to
be secure. 

The software supports 1.8+ (protocol no. 47) clients.

## Debugging
The following flag allows you to view slf4j debug entries: 
```
-Dorg.slf4j.simpleLogger.defaultLogLevel=debug
```
Use it to make your life easier


This project was crafted with love by mineid.org (coming soon!)