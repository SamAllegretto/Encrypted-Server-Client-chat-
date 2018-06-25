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
import javax.crypto.spec.SecretKeySpec;

 
public class ChatClient {
	public static Key symmkey;
	public static void main (String[] argv) {
		try {
	    	CryptoHelper crypto = new CryptoHelper();
			
				String path = System.getProperty("user.dir");
	 
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //generate Public and Private key
				
				keyGen.initialize(1024);
				KeyPair generatedKeyPair = keyGen.genKeyPair();
				crypto.SaveKeyPair(path, generatedKeyPair); //store generated Keys in file
				System.out.println("Generated Key Pair");
		
				// Flags for functions
				String password;
	    	 	Boolean confidentiality = false;
	    		Boolean integrity = false;
	    		Boolean authentication = false;
	    		int operation_mode = 0; // operation_mode changes depending wich functions are selected 
	    
				
				
	    		//String encodedpubKey = Base64.getEncoder().encodeToString(generatedKeyPair.getPublic().getEncoded());
	    	
		    	System.setSecurityManager(new SecurityManager());
		    	// Check which setting should be applied
		    	Scanner s=new Scanner(System.in);
		    	System.out.println("Setup your Chat Client:");
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
		    	
		    	//Scanner s=new Scanner(System.in);
		    	System.out.println("Enter Your Client Name and press Enter:");
		    	String name=s.nextLine().trim();		    		    	
		    	ChatInterface client = new Chat(name);
				byte[] keyBytes = generatedKeyPair.getPublic().getEncoded();
				client.send_pubkey(keyBytes);
		    	ChatInterface server = (ChatInterface)Naming.lookup("rmi://localhost/ABC");
		    	String msg="["+client.getName()+"] got connected";
		    	server.send(msg,false,false);
		    	System.out.println("[System] Chat Remote Object is ready:");
		    	server.setClient(client);
		    	//Checks operation mode with server if it's the same -> quit when different
		    	
		    	// Wait for Server sending his public Key
		    	while(server.getpubserkey() == null) {}
		    	System.out.println("Server Public Key received");
				
				//set up signature and verifyer objects
				Signature signer = Signature.getInstance("SHA256withRSA");
				signer.initSign(generatedKeyPair.getPrivate());
				client.set_verifyier(server.getpubserkey());
				
		    	// Generate and Encrypt the Symmetric Key for sending encrypted messages
		    	symmkey = AESHelper.generateSymmetricKey();
		    	byte [] symmkeyenc = AESHelper.encrypt_symm(server.getpubserkey(), symmkey.getEncoded());
		    	server.send_symmkey(symmkeyenc); //send the symmetric encrypted key to the Server
		    	
		    	//Checks operation mode with server if it's the same -> quit when different
		    	if(server.getOpMode()!=operation_mode){
		    		System.out.println("Server and Clients security properties do not match, rejecting session");
		    		System.exit(0);
		    	}

		    	//System.out.println(symmkeyenc.toString());
		    	AESHelper txtencryper = new AESHelper(symmkey);

		    	Console console = System.console();
		    	
		    	if (console == null) {
           			System.out.println("Couldn't get Console instance");
            		System.exit(0);
        		}

        		while(authentication){
	    	
        			char passwordArray[] = console.readPassword("Enter the Server chat password: ");
	   				password = new String(passwordArray);
	   				password = password + "client";
	   				//System.out.println(password);
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
        		

		    	while(true){
		    		msg=s.nextLine().trim(); //get keyboard input
		    		msg="["+client.getName()+"] "+msg;		//append the Clients name    		
	    			if(integrity){
						//sign the message
						signer.update(msg.getBytes());
						server.setSignature(signer.sign());
					}
					if(confidentiality){
						server.send(txtencryper.encrypt(msg), true, integrity); //send encrypted message to Server
					}
					else{
						server.send(msg, false,integrity); //send message in cleartext
					}
					
					
		    	}
 
	    	}catch (Exception e) {
	    		System.out.println("[System] Server failed: " + e);
	    	}
	}		
}