HARSHAVARDHAN SRINIVAS - 00001481552
VIEW THE WEB VERSION OF THIS README HERE: https://gist.github.com/harshasrinivas/6fafb3135fe53b32772e69da763430f5

FILES:
Running this application requires only 2 files - server.py and client.py (Python 3+)

USAGE:

ENVIRONMENT SETUP:
setup python3
Use the above command to setup Python 3.4 version in both Client and Server systems.

SERVER:
python3 server.py 16 129.210.16.84 129.210.16.85 129.210.16.86
This command will start the server and also display the details of server IP, hostname and Port
NOTE: Machine IP range must be between 129.210.16.71 to 129.210.16.95 - those are the only SSH-accessible Linux systems on the SCU Design Center.

CLIENT:
python3 client.py <server-ip/hostname> <port>
This command will start the client application. Use the server IP/hostname and Port from the output of server command

EXAMPLE FORMAT (CLIENT):
python3 client.py 129.210.16.83 47119
(or)
python3 client.py linux60813.dc.engr.scu.edu 47119

AVAILABLE COMMANDS ON CLIENT:
1. upload user/object
2. download user/object
3. delete user/object
4. list user
5. add disk (supports ip/hostname)
6. remove disk (supports ip/hostname)
7. exit

LOGGING:
1. Client side logs are stored in a file named "client.log", created in the same folder where you run the Client
2. Server side logs are stored in a file named "server.log", created in the same folder where you run the Server

FEATURES SUMMARIZED:
1. Automatic available port finding
2. Supports both hostname and IP address
3. Displays output on both client and server windows
4. Coding Standard - PEP8
5. Automation for Client and Server side
6. Display file content on download command
7. Add and Remove disks
8. Original and backup auto-retrieval

