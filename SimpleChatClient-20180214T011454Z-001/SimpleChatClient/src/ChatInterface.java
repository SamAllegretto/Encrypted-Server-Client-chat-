import java.rmi.*;
import java.security.Signature;

public interface ChatInterface extends Remote{
	public String getName() throws RemoteException;
	public byte[] getpubserkey() throws RemoteException;
	public byte[] getsymmkey() throws RemoteException;
	public void send(String s, boolean enc, boolean verify) throws RemoteException;
	public void send_pubkey(byte[] data) throws RemoteException;
	public void send_symmkey(byte[] data) throws RemoteException;
	public void setClient(ChatInterface c)throws RemoteException;
	public ChatInterface getClient() throws RemoteException;
	public void send_opmode(int op)throws RemoteException;
	public int getOpMode() throws RemoteException;
	public void confirm_opmode(boolean oc)throws RemoteException;
	public boolean getOpCon() throws RemoteException;
	public void pass_set(String ps)throws RemoteException;
	public String pass_get()throws RemoteException;
	public void set_verifyier(byte[] key)throws RemoteException;
	public void setSignature(byte[] sig)throws RemoteException;
	public byte[] getSignature()throws RemoteException;
}