import java.rmi.*;
import java.rmi.server.*;
import java.security.Key;
import java.security.Signature;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
 
public class Chat extends UnicastRemoteObject implements ChatInterface  {
 
	public String name;
	public ChatInterface client=null;
	//public byte[] received_buffer;
	//public byte[] symmetric_key;
	Signature verifyer;
	public byte[] pubserv_key; // buffer for the received Public Key of the Server
	public byte[] symm_key; // buffer for sending the symm_key only used in Servers Chat.java
	public int OpMode = 0;
	public boolean OpConfirm = false;
	public String password;
	public byte[] signature;
 
	public Chat(String n)  throws RemoteException { 
		this.name=n;   
	}
	public String getName() throws RemoteException {
		return this.name;
	}
	public byte[] getpubserkey() throws RemoteException {
		return this.pubserv_key;
	}
 
	public void setClient(ChatInterface c){
		client=c;
	}
 
	public ChatInterface getClient()throws RemoteException{
		return client;
	}
	public void setSignature(byte[] sig)throws RemoteException{
		this.signature = sig;
	}
	public byte[] getSignature()throws RemoteException{
		return this.signature;
	}
	public byte[] getsymmkey() throws RemoteException {
		return this.symm_key;
	}
	public int getOpMode() throws RemoteException {
		return this.OpMode;
	}
	public boolean getOpCon() throws RemoteException {
		return this.OpConfirm;
	}

	public String pass_get()throws RemoteException{
		return this.password;
	}

  // sen message is also the receive part f messages
	public void send(String s, boolean enc, boolean verify) throws RemoteException{
		AESHelper txtencryper = new AESHelper(ChatClient.symmkey); //Insantiate a new Encyption Helper and use the calculated symmetric key
		try {
			String msg;
			if(enc) {
				msg = txtencryper.decrypt(s);// decrypt the message with the symmetric key
			} else{
				msg = s;
			}
			System.out.println(msg);
			if(verify){
				//verify message
				verifyer.update(msg.getBytes());
				if(!verifyer.verify(this.signature)){
					System.out.println("The signature doesnt match the message");
				}
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}	
	public void send_pubkey(byte [] data)throws RemoteException{
		pubserv_key = data;
	}
	public void send_symmkey(byte [] data)throws RemoteException{
		symm_key = data;
	}
	public void send_opmode(int op)throws RemoteException{
		OpMode = op;
	}
	public void confirm_opmode(boolean oc)throws RemoteException{
		OpConfirm = oc;
	}
	public void pass_set(String ps)throws RemoteException{
		password = ps;
	}
	public void set_verifyier(byte[] key){
		//generate verifyer object
		try{
			Signature verifyer = Signature.getInstance("SHA256withRSA");	
			verifyer.initVerify(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key)));
			this.verifyer = verifyer;
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}

}