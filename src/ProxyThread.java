import java.io.*;
import java.net.*;
import java.util.Arrays;

import dh.DiffieHellman;
import protocol.Message;

public class ProxyThread extends Thread{
    
    private Socket clientSocket_input = null;
    private Socket clientSocket_output = null;

    public ProxyThread(Socket to, Socket from){
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

            String senderName = inSocket.readUTF();
            outSocket.writeUTF(senderName);
            System.out.println("Thread-" + getName() + " Relaying name: " + senderName);

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

                if (len > Message.SEQ_NUMBER_SIZE) {
                    byte[] aad = Arrays.copyOfRange(mex, 0, Message.SEQ_NUMBER_SIZE);
                    try {
                        long seqNumber = Message.aadToSeqNumber(aad);
                        System.out.println("Thread-" + getName() + " Forwarding message from " + senderName + " with seq=" + seqNumber + " (" + len + " byte payload)");
                    } catch (IllegalArgumentException iae) {
                        System.out.println("Thread-" + getName() + " Forwarding malformed packet (" + len + " byte payload)");
                    }
                } else {
                    System.out.println("Thread-" + getName() + " Forwarding packet too short to contain a sequence number (" + len + " byte payload)");
                }

                outSocket.writeInt(len);
                outSocket.write(mex);
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