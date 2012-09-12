/** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Description: Server authentication module that contains all the necessary   *
 *              Authentication features required by the Client Program         * 
 *                                                                             *
 *  @author Krishnan Subramanian for ISA656                                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ClientAuth {

	private KeyStore ks = null;
	private SecretKey DESSecretKey = null;
	/**
	 * Change to the client program working path if required
	 */
	private String clientPath = "";

	
	/**
	 * Try to load the keystore into memory from username.key keystore file
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public void LoadKeyStore() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {

		ks = KeyStore.getInstance(KeyStore.getDefaultType());		
		String fname = clientPath;
		File file = new File(fname);
		FileInputStream fis = new FileInputStream(file);
		char[] pwd = "football".toCharArray();
		ks.load(fis, pwd);
	}

	/**
	 * Get the Server's public key certificate from the keystore
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public byte[] EncryptPKI(byte[] key) throws Exception {
		X509Certificate servPubCert;
		servPubCert = (X509Certificate) ks.getCertificate("pub_server");
		PublicKey servPubKey = servPubCert.getPublicKey();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, servPubKey);
		byte[] enc = cipher.doFinal(key);
		return enc;
	}

	/**
	 * Set the DES key to be used for a session with the Server
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
	public ClientAuth(String path) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {
		clientPath = path;
		LoadKeyStore();
	}

}