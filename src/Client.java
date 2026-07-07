import java.net.*;
import java.security.*;

import cipher.SecureCipher;
import cipher.SymmKeyGen;
import utils.ConvertingUtils;
import dh.DiffieHellman;
import protocol.Message;
import auth.SASCalculator;

import java.io.*;
import javax.crypto.SecretKey;

public class Client {

    public static final String USAGE = "Usage: java Client serverAddr serverPort yourName";
    public static final int SOCKET_TIMEOUT = 60000 * 30;
    public static final String ANON = "Anonymous User";

    public static void main(String[] args) {

        /*
         *  Arguments check
         */
        InetAddress addr = null;
        int port = -1;
        String myName = null;
        try{
            if(args.length == 3){
                addr = InetAddress.getByName(args[0]);
                port = Integer.parseInt(args[1]);
                if (port < 1024 || port > 65536){
                    System.err.println("Port is outside the range of valid ports. [1024-65535]");
					System.out.println(USAGE);
                    System.exit(1);
                }                
                myName = args[2];
            } else if(args.length == 2){
                addr = InetAddress.getByName(args[0]);
                port = Integer.parseInt(args[1]);
                if (port < 1024 || port > 65536){
                    System.err.println("Port is outside the range of valid ports. [1024-65535]");
					System.out.println(USAGE);
                    System.exit(1);
                }                
                myName = ANON;
            } else{
                System.out.println(USAGE);                
                System.exit(1);
            }
        }catch (NumberFormatException e) {
			System.err.println("Server port not valid: ");
			e.printStackTrace();
			System.out.println(USAGE);
			System.exit(2);
		} catch (UnknownHostException e) {
			System.err.println("Server's IP address not valid: ");
			e.printStackTrace();
			System.out.println(USAGE);
			System.exit(2);
		} catch (SecurityException e) {
			System.err.println("Server's IP address not valid: ");
			e.printStackTrace();
			System.out.println(USAGE);
			System.exit(2);
		} 

        System.out.println("Client application started...");

        /*
        * Connection to the Server and socket creation
         */ 
        Socket socket = null;
        DataInputStream inputSocket = null;
        DataOutputStream outputSocket = null;

        try{
            socket = new Socket(addr, port);
            socket.setSoTimeout(SOCKET_TIMEOUT);
            System.out.println("Connection created! Socket: " + socket);
        }catch (SocketException e) {
			System.err.println("Protocol problems in socket creation: ");
			e.printStackTrace();
			System.exit(3);
		} catch (IOException e) {
			System.err.println("Problems during socket creation: ");
			e.printStackTrace();
			System.exit(3);
		} catch (Exception e) {
			System.err.println("Problems during socket creation: ");
			e.printStackTrace();
			System.exit(3);
		}

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String message = null;

        try{
            inputSocket = new DataInputStream(socket.getInputStream());
            outputSocket = new DataOutputStream(socket.getOutputStream());
        }catch (IOException e) {
            System.err.println("Problems during streams creation: ");
            e.printStackTrace();
            System.exit(2);
		}

        /*
         * Communication
         */

        System.out.println("Chat started: ");
        try{
            outputSocket.writeUTF(myName);
            String peerName = inputSocket.readUTF();
            System.out.println("Communicating with: " + peerName);
            KeyPair dhKeyPair = DiffieHellman.generateDHKeyPair();
            PublicKey pubKey = dhKeyPair.getPublic();
            PrivateKey privKey = dhKeyPair.getPrivate();
            System.out.println("Generated Diffie-Hellman Key Pair: \n PubKey ->" + pubKey + "\n PrivKey ->" + privKey);

            byte[] encodedPubKey = DiffieHellman.getEncodedPubKey(pubKey);
            outputSocket.writeInt(encodedPubKey.length);
            outputSocket.write(encodedPubKey);
            System.out.println("Sent public key...");
            
            int receivedKeyLen = inputSocket.readInt();
            byte [] receivedPubKey_Bytes = new byte[receivedKeyLen];
            inputSocket.readFully(receivedPubKey_Bytes);
            PublicKey peerPubKey = DiffieHellman.decodePublicKey(receivedPubKey_Bytes);
            System.out.println("Received public key: " + peerPubKey);

            byte[] sharedSecret = DiffieHellman.computeSharedSecret(privKey, peerPubKey);
            System.out.println("Shared secret computed: " + ConvertingUtils.toHexString(sharedSecret));

            /*
            * Verification of the identity through Short Authentication String (SAS)
            */
            if (!myName.equals(ANON) && !peerName.equals(ANON)) {
                String sas = SASCalculator.computeSAS(myName, encodedPubKey, peerName, receivedPubKey_Bytes, sharedSecret);
                System.out.println("\n=== VERIFICATION CODE (SAS) ===");
                System.out.println("Check this code with " + peerName + " via a different channel (phone, in person, etc.): " + sas);
                System.out.println("If it does NOT match the one shown to " + peerName + ", the connection might be intercepted (Man-in-the-Middle): terminate the chat.");
                System.out.print("Does the code match? Type 'Y' to continue, anything else to exit: ");
                String confirmation = stdIn.readLine();
                if (confirmation == null || !confirmation.trim().equalsIgnoreCase("y")) {
                    System.out.println("Verification failed or cancelled. Closing the connection.");
                    socket.close();
                    System.exit(1);
                }
            } else {
                System.out.println("\nSAS Verification skipped (one or both users are anonymous).");
            }

            /*
             * AES-GCM Cipher initialization
             * The cipher is initialized with the shared secret as key
             */
            SecretKey aesKey = SymmKeyGen.generateSymmetricKey(sharedSecret);
            System.out.println("Derived AES Key: " + aesKey);
            SecureCipher cipher = new SecureCipher(aesKey);

            /*
             * Starting Client communications
             */
            MessageReceiver messageReceiver = new MessageReceiver(inputSocket, cipher, peerName);
            messageReceiver.start();
            //System.out.println("MessageReceiver thread started...");
            long seqCounter = 0;

            while((message = stdIn.readLine()) != null){

                // Build message with sequence number and payload
                Message outMessage = new Message(seqCounter++, ConvertingUtils.toByteArray(message));
                byte[] aad = outMessage.seqNumberToAAD();

                // Payload encryption with AES-GCM, using the sequence number as AAD (Additional Authenticated Data)
                byte[] encryptedPayload = cipher.encrypt(outMessage.getPayload(), aad);

                // Message on the socket: [ AAD (seq, in chiaro) | IV + ciphertext+tag ]
                byte[] packet = new byte[aad.length + encryptedPayload.length];
                System.arraycopy(aad, 0, packet, 0, aad.length);
                System.arraycopy(encryptedPayload, 0, packet, aad.length, encryptedPayload.length);

                //System.out.println("[Encrypted message -> " + ConvertingUtils.toHexString(packet)+"]");
                outputSocket.writeInt(packet.length);
                outputSocket.write(packet);
            }
        }catch (Exception e) {
			System.err.println("Errors: ");
			e.printStackTrace();
			System.err.println("Shutting down the connection!");
			System.exit(1);
		}

        /*
         * Closing sockets
         */
        try{
            System.out.println("\n\n Closing the Client.");
            socket.shutdownInput();
            socket.shutdownOutput();
            socket.close();
        }catch (Exception e) {
			System.err.println("Errors: ");
			e.printStackTrace();
			System.err.println("Shutting down the connection!");
			System.exit(1);
		}
    }
}