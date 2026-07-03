import java.io.*;
import java.net.*;

import dh.DiffieHellman;

public class ServerThread extends Thread{
    
    private Socket clientSocket_input = null;
    private Socket clientSocket_output = null;

    public ServerThread(Socket to, Socket from){
        super();
        this.clientSocket_input = from;
        this.clientSocket_output = to;
    }

    public void run(){

        DataInputStream inSocket;
        DataOutputStream outSocket;

        try {
			inSocket = new DataInputStream(clientSocket_input.getInputStream());
			outSocket = new DataOutputStream(clientSocket_output.getOutputStream());
		} catch (IOException ioe) {
			System.err.println("Thread-" + getName() + " Error: Problems during i/o streams creation.");
			ioe.printStackTrace();
			return;
		}

        /*
         * Communication
         */
        byte [] mex = null;

        try{

            /*
             * Key exchang for Diffie-Hellman: receiving public key
             * from the other client and sending its own public key.
             */
            int lenReceivingKey = inSocket.readInt();
            byte[] receivedKey = new byte[lenReceivingKey];
            inSocket.readFully(receivedKey, 0, lenReceivingKey);
            System.out.println("Received public key: " + DiffieHellman.decodePublicKey(receivedKey));

            outSocket.writeInt(lenReceivingKey);
            outSocket.write(receivedKey, 0, lenReceivingKey);
            System.out.println("Sent public key: " + DiffieHellman.decodePublicKey(receivedKey));

            while(true){
                int len = inSocket.readInt();
                mex = new byte[len];
                inSocket.readFully(mex);
                System.out.println("Received: " + mex);

                outSocket.writeInt(len);
                outSocket.write(mex);
                System.out.println("Sending: " + mex);
            }
		} catch (Exception e) {
			System.err.println("Thread-" + getName() + " Fatal Error!");
			e.printStackTrace();
		}


        /*
         * Child terminated => Closing sockets
         */
		try {
            clientSocket_input.shutdownInput();
            clientSocket_output.shutdownOutput();
			clientSocket_input.close();
            clientSocket_output.close();
		} catch (IOException ioe) {
			System.err.println("Thread-" + getName() + " Error: Problems occured during i/o streams closure.");
			ioe.printStackTrace();
			System.out.println("Ending...");
		}
    }
}
