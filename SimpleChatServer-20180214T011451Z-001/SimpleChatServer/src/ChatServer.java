import java.rmi.*;
import java.rmi.server.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;
import java.security.Signature;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
 
public class ChatServer {
	public static Key symmkey;
public static void main (String[] argv) {
    try {
    	CryptoHelper crypto = new CryptoHelper();
		
		String path = System.getProperty("user.dir");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		
		keyGen.initialize(1024);
		KeyPair generatedKeyPair = keyGen.genKeyPair();
		crypto.SaveKeyPair(path, generatedKeyPair);
		System.out.println("Generated Key Pair");

	 	String password = null;
	 	Boolean confidentiality = false;
		Boolean integrity = false;
		Boolean authentication = false;
		int operation_mode = 0;
		String encodedpubKey = Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded());
	
    	System.setSecurityManager(new SecurityManager());
    	// Check which setting should be applied
    	Scanner s=new Scanner(System.in);
    	System.out.println("Setup your Chat Server:");
    	System.out.println("Do you want to encrypt your messages [Confidentiality] ? Y/N:");
    	String confi=s.nextLine().trim();
    	if(confi.equals("Y")) {
    		confidentiality = true;
    	}
    	System.out.println("Do you want to ensure the Integrity of you messages [Integrity] ? Y/N:");
    	String integ=s.nextLine().trim();
    	if(integ.equals("Y")) {
    		integrity = true;
    	}
    	System.out.println("Do you want to Autheticate yourself [Authentication] ? Y/N:");
    	String authen=s.nextLine().trim();
    	if(authen.equals("Y")) {
    		authentication = true;
    	}
    	System.out.println("Your overview:"+confi+integ+authen);
    	System.out.println("Confidentiality:"+confidentiality.toString());
    	System.out.println("Integrity:      "+integrity.toString());
    	System.out.println("Authentication: "+authentication.toString());
    	// Map the selections to one code AIC -> 000 -> 0 100 ->4 111->7
    	if(confidentiality) {
    		operation_mode = 1;
    		if (integrity) {
    			operation_mode = 3;
    			if(authentication) {operation_mode = 7;}
    		}else if (authentication) { operation_mode = 5;}	
    		
    	}else if(integrity) {
    		operation_mode = 2;
    		if(authentication) { operation_mode = 6;}
    		
    	}else if(authentication) { operation_mode = 4;}
    	
	    System.out.println("Enter Your Server name and press Enter:");
	    String name=s.nextLine().trim();
 
	    Chat server = new Chat(name);	
	    
	    //Sams Password stuff
	    Console console = System.console();
        		if (console == null) {
           			System.out.println("Couldn't get Console instance");
            		System.exit(0);
        		}
	    
	    while(authentication){
	    	
        	char passwordArray[] = console.readPassword("Enter the Server chat password: ");
	   		password = new String(passwordArray);
	   		password = password + "server";

			String passwordToHash = password;
        	String hashPassword = null;
        	try {
            	// Create MessageDigest instance for MD5
           		MessageDigest md = MessageDigest.getInstance("MD5");
            	md.update(passwordToHash.getBytes());
            	byte[] bytes = md.digest();
            	StringBuilder sb = new StringBuilder();
            	
            	for(int i=0; i< bytes.length ;i++){
                		sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            	}
            //Get complete hashed password in hex format
            	hashPassword = sb.toString();
        	}
        	catch (NoSuchAlgorithmException e)
        	{
            e.printStackTrace();
        	}
        
        	//System.out.println(hashPassword);

        	File file = new File("./Protected/hash.txt");

        	try {
            	Scanner scan = new Scanner(file);
            		//now read the file line by line...
           		int Num = 0;
            	while (scan.hasNextLine()) {
             		String line = scan.nextLine();
                	Num++;
                		
                	if(hashPassword.equals(line)) { 
                		System.out.println("password accepted");
                		authentication = false;
                	}	
            	}
            	if(authentication){
            		System.out.println("password incorrect, try again");
            		
            	}
            		       
        	} catch(FileNotFoundException e) { 
            //handle this
            	System.out.println("file not found");
        	}

	    }
	    
	    Naming.rebind("rmi://localhost/ABC", server);
	    byte[] keyBytes = generatedKeyPair.getPublic().getEncoded();
	    server.send_pubkey(keyBytes);
	    server.send_opmode(operation_mode);//Sets operation mode.
	    
	    System.out.println("[System] Chat Remote Object is ready:");
	    // Wait for symmetric Key
	    	
	    while(server.getsymmkey() == null) {
	    	try        
	    	{
	    	    Thread.sleep(100);
	    	} 
	    	catch(InterruptedException ex) 
	    	{
	    	    Thread.currentThread().interrupt();
	    	}
			System.out.printf(".");
		}
		System.out.println("Symmetric Key received");
	    byte[] symmkey_enc = AESHelper.decrypt_symm(generatedKeyPair.getPrivate().getEncoded(), server.getsymmkey());
	    symmkey = new SecretKeySpec(symmkey_enc, "AES");
	    AESHelper txtencryper = new AESHelper(symmkey);
		//set up signer and verifyer object
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(generatedKeyPair.getPrivate());
		server.set_verifyier(server.getClient().getpubserkey());
		
	    server.send_opmode(operation_mode);
	    while(true){
	    	
	    	String msg=s.nextLine().trim();
	    	if (server.getClient()!=null){
				ChatInterface client=server.getClient();
				msg="["+server.getName()+"] "+msg;
				if(integrity){
					//sign message
					signer.update(msg.getBytes());
					client.setSignature(signer.sign());
				}
				if(operation_mode == 1 || operation_mode == 5 || operation_mode == 3){
					client.send(txtencryper.encrypt(msg), true,integrity); //send encrypted message to Server
				}
				else{
					client.send(msg, false,integrity); //send message cleartext
				}
	    		//System.out.println("Server enrypted"+txtencryper.encrypt(msg));
			}	
		}
 
		}catch (Exception e) {
			System.out.println("[System] Server failed: " + e);
		}
	}
}