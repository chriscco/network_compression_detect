# Network Compression Detection
## By Chris

## Introduction
### Client Server Model
This project is a simple network compression detection system. 
It is a client-server model. 
The client sends the configuration data to the server with TCP.
Then the client sends 6000 low-entropy data to the server with UDP,
after 15 seconds of the inter-measurement interval, 
the client sends another 6000 high-entropy data to the server.
The server analyzes the time taken in between the first and the last packet received, disregarding the dropped packets, in each entropy level.
The server will send its finding, compression detected or not, back to the client.
The default threshold to determine whether compression exist is 100ms.
### Standalone
The standalone project is very similar to the client-server model, except the compression detection relies 
on the time taken to receive RST segments from the closed port, to which the program sends SYN segments 
before and after each entropy level of data transmission.
> Note: The standalone project requires root privilege to set up raw sockets.
## How To Compile
Make sure you have `cJSON.c`, `cJSON.h` and  `config.h` on both client and server ends.
`myconfig.json` is also required to exist in the same directory as the client end.
### Client End:
```sh
gcc -g compdetect_client.c cJSON.c -o compdetect_client
```
### Server End:
```sh
gcc -g compdetect_server.c cJSON.c -o compdetect_server
```
### Standalone:
```sh
gcc -g standalone.c cJSON.c -o standalone
```
## How To Execute
### Client End
```sh
./compdetect_client myconfig.json
```
### Server End
`7777` is the default TCP pre-probing port number
```sh
./compdetect_server 7777
```
### Standalone
```sh
sudo ./standalone
```