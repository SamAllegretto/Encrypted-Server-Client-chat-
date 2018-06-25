import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;

public class AESHelper {
	 private static final String ALGORITHM = "RSA";

	

	public String encrypt( String plaintext ) throws Exception {
		return encrypt( generateIV(), plaintext );
	}

	public String encrypt( byte [] iv, String plaintext ) throws Exception {

		byte [] decrypted = plaintext.getBytes();
		byte [] encrypted = encrypt( iv, decrypted );

		StringBuilder ciphertext = new StringBuilder();

		ciphertext.append( Base64.getEncoder().encodeToString( iv ) );
		ciphertext.append( ":" );
		ciphertext.append( Base64.getEncoder().encodeToString( encrypted ) );
		
		return ciphertext.toString();

	}

	public String decrypt( String ciphertext ) throws Exception {
		String [] parts = ciphertext.split( ":" );
		byte [] iv = Base64.getDecoder().decode( parts[0] );
		byte [] encrypted = Base64.getDecoder().decode( parts[1] );
		byte [] decrypted = decrypt( iv, encrypted );
		return new String( decrypted );
	}

	private Key key;

	public AESHelper( Key key ) {
		this.key = key;
	}



	public Key getKey() {
		return key;
	}

	public void setKey( Key key ) {
		this.key = key;
	}

	public static byte [] generateIV() {
		SecureRandom random = new SecureRandom();
		byte [] iv = new byte [16];
		random.nextBytes( iv );
		return iv;
	}

	

	public byte [] encrypt( byte [] iv, byte [] plaintext ) throws Exception {
		Cipher cipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
		cipher.init( Cipher.ENCRYPT_MODE, key, new IvParameterSpec( iv ) );
		return cipher.doFinal( plaintext );
	}

	public byte [] decrypt( byte [] iv, byte [] ciphertext ) throws Exception {
		Cipher cipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
		cipher.init( Cipher.DECRYPT_MODE, key, new IvParameterSpec( iv ) );
		return cipher.doFinal( ciphertext );
	}
	

	//Decrypting the symmetric key with the private key of the server
	   public static byte[] decrypt_symm(byte[] privateKey, byte[] inputData)
	            throws Exception {

	        PrivateKey key = KeyFactory.getInstance(ALGORITHM)
	                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));

	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        cipher.init(Cipher.PRIVATE_KEY, key);

	        byte[] decryptedBytes = cipher.doFinal(inputData);

	        return decryptedBytes;
	    }

}