import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class HTTPChatServer {

    final static boolean DEBUG = false;

    static int cookie = 1000;

    public static void main(String[] args){

        // parse the port number from the command line input
        int port = parsePortNumber(args);

        // attempt to set up a server socket
        try {

            ServerSocket serverSocket = new ServerSocket(port);

            ArrayList<String> chatLog = new ArrayList<String>();
            Map<String, String> cookieMap = new HashMap<String, String>();

            System.out.println("--- CS 352 Chat Server ---");	    

            // begin server loop
            while(true){

                try {

                    // wait for a client connection
                    Socket client = serverSocket.accept();

                    if(DEBUG) System.out.println("debug -> connected to a client");

                    // pass the client to the handler function
                    handleClient(client, chatLog, cookieMap);
                    // test(client);

                    if(DEBUG) System.out.println("debug -> disconnecting from the client");
                    client.close();

                } catch(Exception exception){

                    if(DEBUG) System.out.println("debug -> warning: exception occured in server loop\n" + exception);

                }

            }

        } catch(Exception exception){

            System.out.println(exception);
            System.exit(1);

        }

    }

    /**
     * This function handles any requests from the client
     * 
     * @param client a socket object for a client
     * @throws IOException 
     */
    public static void handleClient(Socket client, ArrayList<String> chatLog, Map<String, String> cookieMap) throws IOException {

        // setup a reader for the input stream
        BufferedReader input = new BufferedReader(new InputStreamReader(client.getInputStream()));

        // setup the output stream
        DataOutputStream output = new DataOutputStream(client.getOutputStream());

        StringBuilder requestBuilder = new StringBuilder();
        String line;

        // read in the first line
        line = input.readLine();

        // loop while the line is not blank
        while (!line.isBlank()) {

            // append the current line to the string in the request builder
            requestBuilder.append(line + "\r\n");

            // read in the next line
            line = input.readLine();
        }

        // output the request
        String request = requestBuilder.toString();

        if(DEBUG) System.out.println("debug -> server got the following request:\n" + request);

        // spilt up the request by line
        String[] requestsLines = request.split("\r\n");

        // tokenize the first line using single spaces
        String[] requestLine = requestsLines[0].split(" ");

        // store the values for the first line
        String method = requestLine[0];
        String path = requestLine[1];
        String version = requestLine[2];

        // tokenize the second line and then store the host
        String host = requestsLines[1].split(" ")[1];

        // create a list to store the headers
        List<String> headers = new ArrayList<>();

        // loop through the remaining lines in the request
        for (int h = 2; h < requestsLines.length; h++) {

            // store the current header in the list
            String header = requestsLines[h];
            headers.add(header);

        }

        // store and then output access information
        String accessLog = String.format("Client %s, method %s, path %s, version %s, host %s, headers %s",
                client.toString(), method, path, version, host, headers.toString());
        if(DEBUG) System.out.println("debug -> access log data\n" + accessLog);

        // figure out which handler to call
        if(method.toLowerCase().equals("get")){

            // check which page is being requested
            if(path.contains("login")) {

                handleGetLoginPageRequest(output);

            } else if(path.contains("chat")) {

                handleGetChatPageRequest(output, chatLog);

            } else {

                // unexpected path provided. report error and ingore request
                System.out.println("Error: unexpected path detected. ignoring this request.");
                System.out.println("\tpath = " + path);

            }

        } else if(method.toLowerCase().equals("post")){

            System.out.println("attempting to get payload...");

            // post requests should come with a payload, read it from the socket
            String payload = readInPayload(input, parsePayloadLength(headers));
    
            System.out.println("... got it!");

            // parse the payload string
            String[][] parsedPayload = parsePayload(payload);

            // check which page is being requested
            if(path.contains("login")) {

                String username = "";
                String password = "";

                // payload should contain a username and password
                for(int index = 0; index < parsedPayload.length; index++){

                    // assign the username or password if either is found
                    if(parsedPayload[index][0].equals("username")) username = parsedPayload[index][1];
                    if(parsedPayload[index][0].equals("password")) password = parsedPayload[index][1];

                }

                handlePostLoginPageRequest(output, username, password, cookieMap);

            } else if(path.contains("chat")) {

                String message = "";

                // payload should contain the message to be posted
                for(int index = 0; index < parsedPayload.length; index++){

                    // assign the username or password if either is found
                    if(parsedPayload[index][0].equals("message")) message = parsedPayload[index][1];

                }

                // call the cookie parser and pass to the handler
                String clientCookie = parseCookie(headers);

                // make sure the message is not empty
                if(!message.isEmpty()){
                    handlePostChatPageRequest(output, message, clientCookie, cookieMap, chatLog);
                } else {
                    System.out.println("Error: message passed to the server is blank. ignoring this request");
                }

            } else {

                // unexpected path provided. report error and ingore request
                System.out.println("Error: unexpected path detected. ignoring this request.");
                System.out.println("\tpath = " + path);

            }

        } else {

            // unexpected request type
            System.out.println("Error: unexpected request method detected. ignoring this request.");
            System.out.println("\tmethod = " + method);

        }

    }

    public static void handleGetLoginPageRequest(DataOutputStream output){

        System.out.println("handling a get login page request");

        try{

            // read the file contents into a string variable
            File loginPage = new File("login/login.html");
            String data = Files.readString(loginPage.toPath());

            // construct the response
            String response = "HTTP/1.1 200 OK\r\n" +
            "ContentType: text/html\r\n" +
            "\r\n" +
            data;

            // send it
            output.writeBytes(response);

        } catch(Exception exception) {

            System.out.println(exception);

        }

        System.out.println("Done.");

    }

    public static void handlePostLoginPageRequest(DataOutputStream output, String username, String password,
        Map<String, String> cookieMap){

        //check if credentials are valid
	    if(validCredentials(username, password)) {
		
            cookieMap.put(String.valueOf(cookie), username); //Map username to cookie
            
            //return chat page
            try {
                File chatPage = new File("chat/chat.html");
                String data = Files.readString(chatPage.toPath());

                //construct message
                String response = "HTTP/1.1 200 OK\r\n" +
                    "ContentType: text/html\r\n" + "Set-Cookie: " + String.valueOf(cookie) + "\r\n" + "\r\n" +  data;
                    // "ContentType: text/html\r\n" + "Set-Cookie: client_id=" + String.valueOf(cookie) + "\r\n" + "\r\n" +  data;

                //send data
                output.writeBytes(response);
            } catch (Exception e) {
                System.out.println("error with chat file");
            }

	    } else {

            try {
                File errorPage = new File("login/error.html");
                String data = Files.readString(errorPage.toPath());

                //construct message
                String response = "HTTP/1.1 401 Unauthorized\r\n" + "\r\n" + data;

                //send it
                output.writeBytes(response);

            } catch (Exception e) {
                System.out.println("error with login error file");
            }

	    }

        cookie++; //inc cookie

        System.out.println("Done.");

    }

    public static void handlePostChatPageRequest(DataOutputStream output, String message, String clientCookie, Map<String, String> cookieMap, ArrayList<String> chatLog ){

        System.out.println("handling a post chat page request");
        System.out.println("message = " + message);
        System.out.println("clientCookie = " + clientCookie);

        if(cookieMap.containsKey(clientCookie)){

            // pull the username
            String username = cookieMap.get(clientCookie);

            // add the message to the chatlog
            chatLog.add((username + " : " + message));

            //return chat page
            try {
                File chatPage = new File("chat/chat.html");
                String data = Files.readString(chatPage.toPath());

                //construct message
                String response = "HTTP/1.1 200 OK\r\n" +
                    "ContentType: text/html\r\n" + "Set-Cookie: client_id=" + String.valueOf(cookie) + "\r\n" + "\r\n" +  data;

                //send data
                output.writeBytes(response);
            } catch (Exception e) {
                System.out.println("error with chat file");
            }

        } else {

            try {
                File errorPage = new File("login/error.html");
                String data = Files.readString(errorPage.toPath());

                //construct message
                String response = "HTTP/1.1 401 Unauthorized\r\n" + "\r\n" + data;

                //send it
                output.writeBytes(response);

            } catch (Exception e) {
                System.out.println("error with login error file");
            }

        }

        System.out.println("Done.");

    }

    public static void handleGetChatPageRequest(DataOutputStream output, ArrayList<String> chatLog){

        System.out.println("handling a get chat page request");

        try{

            // read the file contents into a string variable
            File loginPage = new File("chat/chat.html");
            String data = Files.readString(loginPage.toPath());
            
            // split the html file
            int insertIndex = data.indexOf("<div id=\"chat-window\">") + "<div id=\"chat-window\">".length();
            String begining = data.substring(0, insertIndex).replace("\r", "").replace("\n", ""); 
            String end = data.substring(insertIndex + 1).replace("\r", "").replace("\n", "");

            // load the chat messages
            String messages = "";
            for(int i = 0; i < chatLog.size(); i++){
                messages += ("<p>" + chatLog.get(i) + "</p>");
            }

            // construct the response
            String response = "HTTP/1.1 200 OK\r\n" +
            "ContentType: text/html\r\n" +
            "\r\n" +
            begining +
            messages +
            end; 

            // send it
            output.writeBytes(response);

        } catch(Exception exception) {

            System.out.println(exception);

        }

        System.out.println("Done.");

    }

    // ------------------------------------------------------------------------------------
    // --------------------------------- helper functions ---------------------------------
    // ------------------------------------------------------------------------------------

    /**
     * parses the command line input
     * 
     * @param args the args string array from the main method
     * @return port an integer indicating the port to connect to
     */
    public static int parsePortNumber(String[] args){

        // make sure an argument was provided
        if(args.length != 1){

            System.out.println("error: incorrect number of arguments provided to the server");
            System.exit(1);  

        }

        // initial port number to avoid compiler error
        int port = -1;

        try {
        
            // attempt to parse the port number from the command line
            port = Integer.parseInt(args[0]);

        } catch(NumberFormatException exception){

            System.out.println("error: the provided argument string does not contain a parsable integer for the port number.");
            System.exit(1);

        }

        // this line will only run if the port is successfully parsed
        return port;

    }

    public static String parseCookie(List<String> headers){
 
        String cookieId = "";
 
        // loop through the list of headers for the cookie
        for(int index = 0; index < headers.size(); index++){
 
            // check each header for the content length
            if(headers.get(index).startsWith("Cookie: ")){
 
                // store the length as an integer
                // Cookie: client_id=the_cookie_number_we_want
                // Cutoff all excess string except for the cookie value
                cookieId = headers.get(index).substring(18);
            }
        }
        System.out.println("cookie ID: = " + cookieId);
 
        return cookieId;

    }

    public static int parsePayloadLength(List<String> headers){

        int payloadLength = 0;

        // loop through the list of headers for the content-length
        for(int index = 0; index < headers.size(); index++){

            // check each header for the content length
            if(headers.get(index).startsWith("Content-Length: ")){

                // store the length as an integer
                payloadLength = Integer.valueOf(headers.get(index).substring(16));

            }

        }

        System.out.println("payload length = " + String.valueOf(payloadLength));

        return payloadLength;
    }

    public static String readInPayload(BufferedReader input, int payloadLength){

        String payload = "";

        try{

            for(int character = 0; character < payloadLength; character++){
                String new_char = String.valueOf((char)input.read());
                if(new_char.equals("+")) new_char = " ";
                payload +=  new_char;
            }

        } catch(Exception exception){

        }

        System.out.println("payload = " + payload);
        System.out.println(payload.length());

        return payload;

    }

    /**
     * This function takes the payload string the from the http request and breaks it into
     * multiple string arrays, one per key-value pair. each of these string arrays contains
     * two elements with index 0 holding the key string and index 1 holding the value string.
     * All of the new 2 element arrays are then stored in an array called parsedPayload.
     * 
     * the key-value data can be accessed like this:
     * 
     *  for(int pairIndex = 0; pairIndex < parsedPayload.length; pairIndex++){
     *      System.out.println("key = " + parsedPayload[pairIndex][0] + " -> value = " + parsedPayload[pairIndex][1]);
     *  }
     * 
     * @param payload the payload string the from the http request
     * @return parsedPayload returns a 2d string array containing an array 2 element string arrays
     */
    public static String[][] parsePayload(String payload){

        // spilt the payload into key values pairs in this format: key=value
        String[] keyValuePairs = payload.split("&");

        // declare and initialize the 2d output array
        String[][] parsedPayload = new String[keyValuePairs.length][2];

        // loop through the key values pairs
        for(int index = 0; index < keyValuePairs.length; index++){

            // seperate the keys from the values and store in the 2d output array
            // parsedPayload[index] = {current key, current value}
            parsedPayload[index] = keyValuePairs[index].split("=");

        }
        
        return parsedPayload;

    }

    /**
     * given the credentials, this function will search the credentials.txt file
     * for matching credentials. it will return true if a match is found, false otherwise.
     * 
     * @param username
     * @param password
     * @return validCredentials a boolean indicating if the credentials were found in the file
     */
    public static boolean validCredentials(String username, String password){

        boolean validCredentials = false;

        // the credentials are stored as "username,password" so we can compare 
        // this credential string to each file line to see if we find a match
        String credentials = username + "," + password;

        try{

            // open up the credential file
            File credentialsFile = new File("login/credentials.txt");

            // create a scanner to read from the file
            Scanner fileReader = new Scanner(credentialsFile);

            // loop until the end of the file or we find the credentials
            while(fileReader.hasNextLine() && (!validCredentials)){

                if(fileReader.nextLine().equals(credentials)){
                    validCredentials = true;
                }

            }

            if(DEBUG) System.out.println("cred search: " + credentials + " exist => " + String.valueOf(validCredentials));

        } catch(FileNotFoundException exception){

            System.out.println("Error: unable to open the credentials file");

        } catch(Exception exception){

            System.out.println("Error: unexpected exception occured in validCredentials()");

        }

        return validCredentials;

    }

}
