/** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Description: A simple multithreaded Chat Server program that uses           * 
 *              PKI & Secret key encryption to deliver chat messages to        *   
 *              the client                                                     * 
 *                                                                             *
 *  @author Krishnan Subramanian for ISA656                                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/**
 * required imports for the program
 */

import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Random;

/**
 * Implements the Serializable interface (for object stream to be sent through
 * sockets) and Runnable Interface (for multithreading)
 * 
 * @author Krishnan
 * 
 */

public class Server implements Serializable, Runnable {
	/**
	 * Required for a serializable class
	 */
	private static final long serialVersionUID = 1L;
	private String serverPath = "";
	private ServerSocket servSock = null;
	private int noConns = 0;
	private int g_port = 0;

	/**
	 * Constructor to initialize the Server
	 * 
	 * @param port
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws ClassNotFoundException
	 */
	public Server(int port,String file) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			ClassNotFoundException {
		servSock = new ServerSocket(port);
		g_port = port;
		serverPath = file;
		newThreadStart();
	}

	/**
	 * Starts a new client thread module
	 */
	private void newThreadStart() {
		(new Thread(this)).start();
	}

	/**
	 * The run() method inherited abstract method from the runnable interface
	 */
	@Override
	public void run() {
		System.out.println("Server initialized, running on port: " + g_port);
		Socket socket = null;
		/**
		 * A sequence variable
		 */
		int seq = 0;
		try {
			socket = servSock.accept();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		newThreadStart();
		/**
		 * number of client connections
		 */
		++noConns;
		System.out.println("Client connected: " + socket.getInetAddress() + ":"
				+ socket.getPort());

		ServerAuth sa = null;
		/**
		 * Create an object for the Server Authentication Module
		 */
		try {
			sa = new ServerAuth(serverPath);			
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (CertificateException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		ObjectOutputStream out = null;
		ObjectInputStream in = null;
		String currentUser = null;
		while (true) {
			try {
				/**
				 * increment the sequence number
				 */
				++seq;
				out = new ObjectOutputStream(socket.getOutputStream());
				in = new ObjectInputStream(socket.getInputStream());
				/**
				 * First sequence: try to authenticate the user by looking for
				 * the public in the server.key keystore
				 */
				if (seq == 1) {
					byte[] cusr = (byte[]) in.readObject();
					byte[] busr = sa.DecryptPKI(cusr);
					String msg = new String(busr);
					String usr = "pub_" + msg.trim();
					currentUser = msg.trim();
					/**
					 * Check if the user's public key exists on the server's
					 * keystore
					 */
					boolean flg = sa.CheckUser(usr);
					if (!flg) {
						String errcode = "404";
						/**
						 * Tell the user if authentication is unsuccessful
						 */
						System.out.println("Client  " + socket.getInetAddress()
								+ ":" + socket.getPort() + " User \""
								+ currentUser
								+ "\" not registered: Authentication Failed");
						// Write the bytestream as ObjectStream data
						out.writeObject(errcode);
						out.flush();
						break;
					} else {
						/**
						 * Authentication was successful
						 */
						String authcode = "200";
						out.writeObject(authcode);
						out.flush();
						continue;
					}
				}
				/**
				 * Second sequence: Initialize the chat session using DES key
				 * supplied by the client
				 */
				else if (seq == 2) {
					byte[] msg = (byte[]) in.readObject();
					byte[] dec = sa.DecryptPKI(msg);
					sa.SetDESKey(dec);
					String cmsg = "200";
					out.writeObject(cmsg);
					out.flush();
					continue;
				}
				/**
				 * The chat message: echo back the captialized message and send
				 * it back to the client with the username. The whole message is
				 * encrypted using the DES key supplied by the Client
				 */
				byte[] cmsg = (byte[]) in.readObject();
				String ptxt = sa.DecryptDES(cmsg);
				String fromServer = currentUser + ": " + ptxt.toUpperCase();
				byte[] enc = sa.EncryptDES(fromServer);
				out.writeObject(enc);
				out.flush();

			} catch (SocketException e) {
				System.out.println("Connection was reset/closed by Client "
						+ socket.getInetAddress() + ":" + socket.getPort());
				break;
			} catch (NullPointerException e) {
				System.out.println("Connection was closed by Client "
						+ socket.getInetAddress() + ":" + socket.getPort());
				break;
			} catch (EOFException e) {
				System.out.println("Connection was closed by Client "
						+ socket.getInetAddress() + ":" + socket.getPort());
				break;
			} catch (Exception e) {
				System.out.println("Oops.. an exception occured ");
				e.printStackTrace();
				break;
			}
		}
		try {
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public static void main(String args[]) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			ClassNotFoundException {
		/**
		 * Generate a Random port number between 1035 and 65530
		 */
		int port = new Random().nextInt(65530 - 1035) + 1;
		String file = "server.key";
		/**
		 * Check for program syntax
		 */
		if (args.length > 2) {
			System.out
					.println("More than two arguments passed to the Server program");
			System.out.println("Usage: <port> <serverkeyfile path>");
			System.exit(0);
		} else if (args.length == 2) {
			try {
				port = Integer.parseInt(args[0]);
				file = args[1].trim();
			} catch (Exception e) {
				System.out
						.println("An Exception occured while trying to parse the port number/file");
				System.exit(0);
			}
		} else if(args.length<2){
			System.out
					.println("Too few arguments specified");
			System.out.println("Usage: <port> <serverkeyfile path>");
			System.exit(0);
		}
		
		new Server(port,file);
	}
}
