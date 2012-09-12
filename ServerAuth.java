/** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Description: Server authentication module that contains all the necessary   *
 *              Authentication features required by the Server Program         * 
 *                                                                             *
 *  @author Krishnan Subramanian for ISA656                                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/**
 * required imports for the program
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerAuth {
	/**
	 * Change to the server program working path if required
	 */
	private String serverPath = "";
	private KeyStore ks = null;
	private SecretKey DESSecretKey = null;	

	
	/**
	 * Try to load the keystore into memory from server.key keystore file
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public void LoadKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		String fname = serverPath;
		File file = new File(fname);
		FileInputStream fis = new FileInputStream(file);
		char[] pwd = "ree123456".toCharArray();
		ks.load(fis, pwd);

	}

	/**
	 * Check if a username alias exists in the server keystore
	 * 
	 * @param usr
	 * @return
	 * @throws KeyStoreException
	 */
	public boolean CheckUser(String usr) throws KeyStoreException {
		return ks.isCertificateEntry(usr);
	}

	/**
	 * Decrypt the secret key exhanged by the Client using PKI - Server private
	 * key
	 * 
	 * @param ctxt
	 * @return
	 * @throws Exception
	 */
	public byte[] DecryptPKI(byte[] ctxt) throws Exception {
		char[] kpwd = "ree123456".toCharArray();
		Key privateKey = ks.getKey("server", kpwd);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] cbytes = cipher.doFinal(ctxt);
		// String cleartxt = new String(cbytes,"UTF8");
		return cbytes;
	}

	/**
	 * Set the DES key supplied by the client program for the session
	 * 
	 * @param key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void SetDESKey(byte[] key) throws NoSuchAlgorithmException,
			InvalidKeySpecException {
		SecretKeySpec secretspec = new SecretKeySpec(key, "DES");
		DESSecretKey = secretspec;
	}

	/**
	 * Encrypt a plain text message to cipher block bytes using DES
	 * 
	 * @param ptxt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] EncryptDES(String ptxt) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher ecipher = Cipher.getInstance("DES");
		ecipher.init(Cipher.ENCRYPT_MODE, DESSecretKey);
		byte[] ptxtEncoded = ptxt.getBytes("UTF8");
		byte[] enc = ecipher.doFinal(ptxtEncoded);
		return enc;

	}

	/**
	 * Decrypt a cipher block bytes to plain text using DES
	 * 
	 * @param dec
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public String DecryptDES(byte[] dec) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException {
		Cipher dcipher = Cipher.getInstance("DES");
		dcipher.init(Cipher.DECRYPT_MODE, DESSecretKey);
		byte[] ptxtEncoded = dcipher.doFinal(dec);
		String ptxt = new String(ptxtEncoded, "UTF8");
		return ptxt;
	}

	/**
	 * Constructor
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public ServerAuth(String path) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {
		serverPath = path;
		LoadKeyStore();
	}

}