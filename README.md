# Web Chat Server

Incredibly simple web chat server created in Java using the HTTP protocol. Users log into the session using a _csv_ file inside the directory. Programs creates and establishes cookies between users to remember session states.

### Running The Program

1. Unpack the zip.
2. In the top level directory, run `javac HTTPChatServer.java` and `java HTTPChatServer <port>`
3. Run a test client using one of the test python files.

Example: `python3 client_test_1.py <address> <port> <username> <password> <message>`

4. Or run your own command with own chat.

