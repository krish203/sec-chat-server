/** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Description: A Chat client program that uses PKI & Secret key               	*
 *              encryption to send messages to the Chat Server                 	*
 *                                                                             	*
 * @author      Krishnan Subramanian                                 			*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * */

/**
 * required imports for the program
 */

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Implements the Serializable interface (for object stream to be sent through
 * sockets)
 * 
 * @author Krishnan
 * 
 */

public class Client implements Serializable {
	/**
	 * Required for a serializable class
	 */
	private static final long serialVersionUID = 1L;
	private String clientPath = "";
	/**
	 * 
	 * @param server
	 * @param servPort
	 * @param usr
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws ClassNotFoundException
	 */
	public Client(String server, int servPort, String usr,String file) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			ClassNotFoundException {
		Socket socket = null;
		clientPath = file;
		/*
		 * Connect to the server & bind the socket to the server port - report
		 * any errors during the process
		 */
		try {
			socket = new Socket(server, servPort);
		} catch (ConnectException e) {
			System.out
					.println("Error occured while trying to bind socket, please check the port number for the server");
			System.exit(0);
		} catch (Exception e) {
			System.out.println("Error occured while trying to bind socket");
			System.exit(0);
		}
		ClientAuth ca = new ClientAuth(clientPath);		
		int seq = 0;
		ObjectOutputStream out = null;
		ObjectInputStream in = null;
		System.out.println("Client initialized, connected to server  "
				+ socket.getInetAddress() + ":" + socket.getPort());
		while (true) {
			try {
				++seq;
				out = new ObjectOutputStream(socket.getOutputStream());
				in = new ObjectInputStream(socket.getInputStream());
				String input = null;
				BufferedReader br = new BufferedReader(new InputStreamReader(
						System.in));
				/**
				 * First sequence: Send the username encrypted using the
				 * server's public key [PKI-RSA]
				 */
				if (seq == 1) {
					byte[] cusr = ca.EncryptPKI(usr.getBytes());
					out.writeObject(cusr);
					out.flush();
					String cmsg = (String) in.readObject();
					int code = Integer.parseInt(cmsg.trim());
					/*
					 * Parse response code from the Server and notify the status
					 * message to the user
					 */
					if (code == 404) {
						System.out
								.println("Sorry, could not authenticate User: \""
										+ usr + "\" to the server");
						break;
					} else if (code == 200) {
						System.out.println("Trying to authenticate \"" + usr
								+ "\" to the server");
						continue;
					} else {
						System.out
								.println("An error occured while trying to authenticate to the server");
						break;
					}
				}
				/**
				 * Second sequence: After authentication, generate a fresh DES
				 * key to send all future messages to the server
				 */
				if (seq == 2) {
					KeyGenerator kg = KeyGenerator.getInstance("DES");
					kg.init(56);
					SecretKey symmkey = kg.generateKey();
					byte[] DESKey = symmkey.getEncoded();
					byte[] enckey = ca.EncryptPKI(DESKey);
					ca.SetDESKey(DESKey);
					out.writeObject(enckey);
					out.flush();
					String cmsg = (String) in.readObject();
					int code = Integer.parseInt(cmsg);
					// Try to exchange the key with the Server and throw any
					// errors during this process
					if (code == 200) {
						System.out
								.println("Encrypted Key Exchange(EKE) successful with Server");
						System.out
								.println("At any point type \"exit\" to quit");
						continue;
					} else {
						System.out
								.println("Sorry, error occured while Encrypted Key Exchange(EKE) with Server");
						break;
					}

				}
				/**
				 * Read input from the user and send to the server
				 */
				input = br.readLine();
				if (input.equals("exit")) {
					break;
				}
				byte[] enc = ca.EncryptDES(input);
				out.writeObject(enc);
				out.flush();
				byte[] cmsg = (byte[]) in.readObject();
				String ptxt = ca.DecryptDES(cmsg);
				System.out.println(ptxt);

			} catch (SocketException e) {
				System.out.println("Connection reset/closed by Server");
				break;
			} catch (NullPointerException e) {
				System.out.println("Connection was closed by Server");
				break;
			} catch (EOFException e) {
				System.out.println("Connection was closed by Client");
				break;
			} catch (Exception e) {
				System.out.println("Oops.. an exception occured: ");
				e.printStackTrace();
				break;
			}
		}
		socket.close();
		System.out.println("BYE");
	}

	public static void main(String args[]) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			ClassNotFoundException {
		String server = "127.0.0.1";
		int servPort = 1595;
		String usr = "krish";
		String file = "";
		/**
		 * Check program syntax
		 */
		if (args.length > 4) {
			System.out
					.println("More than four arguments passed to the Client program");
			System.out
					.println("Usage: <server hostname/IP> <port> <username> <clientkeyfile path>");
			System.exit(0);
		} else if (args.length < 4) {
			System.out
					.println("Too few arguments specified for the client to start");
			System.out
					.println("Usage: <server hostname/IP> <port> <username> <clientkeyfile path>");
			System.exit(0);
		} else if (args.length == 4) {
			try {
				server = args[0].trim();
			} catch (Exception e) {
				System.out
						.println("Error occured while trying to parse Server Name/IP");
				System.exit(0);
			}

			try {
				servPort = Integer.parseInt(args[1].trim());
			} catch (Exception e) {
				System.out
						.println("Error occured while trying to parse port number");
				System.exit(0);
			}

			try {
				usr = args[2].trim();
			} catch (Exception e) {
				System.out
						.println("Error occured while trying to get user name");
				System.exit(0);
			}

			try {
				file = args[3].trim();		
			} catch (Exception e) {
				System.out
						.println("Error occured while trying to get user name");
				System.exit(0);
			}
		} else {
			System.out
					.println("Usage: <server hostname/IP> <port> <username> <clientkeyfile path>");
			System.exit(0);
		}
		
		new Client(server, servPort, usr,file);

	}
}
