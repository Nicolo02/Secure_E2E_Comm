import java.io.*;
import java.net.*;

public class Server {
       
    public static final String USAGE = "Usage: java Server [serverPort>1024]";
    public static final int DEFAULT_PORT = 9999;
    public static final int N_CLIENTS = 2; // number of client expected
    public static final int SOCKET_TIMEOUT = 60000;    

    public static void main(String[] args) throws IOException{

        int port = -1;

        /*
         *  Argument check
         */
        try{
            if(args.length == 1){
                port = Integer.parseInt(args[0]);
                if (port < 1024 || port > 65535) {
                    System.err.println("Server Error: port is outside the range of valid ports. [1024-65535]");
                    System.out.println(USAGE);
                    System.exit(1);
                }
            }else if(args.length == 0){
                System.out.println("Using deafault port: " + DEFAULT_PORT);
                port = DEFAULT_PORT;
            }else{
                System.out.println(USAGE);
                System.exit(1);
            }
        }catch (NumberFormatException e) {
			System.err.println("Server Error: port's parsing error!");
			System.out.println(USAGE);
			System.exit(1);
		}

        /*
        * Sockets creation 
        */

        ServerSocket serverSocket = null;
        Socket clientSocket [] = new Socket[N_CLIENTS];

        try{
            serverSocket = new ServerSocket(port);
            serverSocket.setReuseAddress(true);
            System.out.println("Server activated!");
            System.out.println("Created server socket: " + serverSocket);
        }catch (Exception e) {
            System.err.println("Server Error: errors during server socket creation " + e.getMessage());
            e.printStackTrace();
            serverSocket.close();
            System.exit(1);
        }

        /*
        * Accepting connection's requests
        */
        try{
            int i = 0;
            while(i < 2){
                System.out.println("Server: waiting for connections requests");

                try{
                    clientSocket[i] = serverSocket.accept();
                    clientSocket[i].setSoTimeout(SOCKET_TIMEOUT);
                    System.out.println("Connection accepted: " + clientSocket[i]);
                    i++;
                }catch (IOException e) {
					System.err.println("Server Error: Problems during conncetion's acceptance: " + e.getMessage());
					e.printStackTrace();
					continue;
				}
            }

            // Da migliorare
            System.out.println("Server: " + N_CLIENTS + " clients connected, starting threads...");
            new ServerThread(clientSocket[0], clientSocket[1]).start(); 
            new ServerThread(clientSocket[1], clientSocket[0]).start(); 

        } catch (Exception e) {
			System.err.println("Server Error: server's fatal error!\n Shutting down the Server...");
			e.printStackTrace();
			System.exit(2);
		}
    }
}
