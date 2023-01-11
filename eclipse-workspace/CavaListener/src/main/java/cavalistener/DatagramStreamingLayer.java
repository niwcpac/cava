package cavalistener;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Streaming layer for outputing event data via a UDP socket as 
 * UDP datagrams. 
 * 
 * @author Sunny J. Fugate
 */
public class DatagramStreamingLayer implements StreamingLayer {
	DatagramSocket serverSocket;
	InetAddress destAddress;
	int srcPort;
	int destPort;
	private boolean isValid=true;
	private boolean isRunning;
	private boolean isReady;
	
	LinkedBlockingQueue<String> dataQueue=new LinkedBlockingQueue<String>();
	
	public DatagramStreamingLayer(String address, int dport, int sport) throws UnknownHostException {
		this.destAddress=InetAddress.getByName(address);
		this.destPort=dport;
		this.srcPort=sport;		
	}
	
	@Override
	public void sendData(String data) throws StreamingLayerException {
		if(!isValid) {
			throw new StreamingLayerException("sendData called on invalid DatagramStreamingLayer");
		}
		if(!isReady) {
			throw new StreamingLayerException("sendData called before thread was ready. call init()");
		}
		if(this.serverSocket == null) {
			throw new StreamingLayerException("Socket was null");
		}
		
		this.dataQueue.add(data);
		
	}

	@Override
	public String getStreamingLayerInfo() {
		String str_srcPort = String.valueOf(srcPort);
		String str_destPort = String.valueOf(destPort);
		String str_destAddress = String.valueOf(destAddress);
			
		return "UDP: "+str_srcPort+" -> "+str_destAddress+":"+str_destPort;
	}
	
	/**
	 * Return the source port
	 * @return source UDP port
	 */
	public int getSrcPort() {
		return srcPort;
	}
	
	/**
	 * Return the destination port
	 * @return destination UDP port
	 */
	public int getDestPort() {
		return destPort;
	}
	
	/**
	 * Return the IP address
	 * @return the Internet Protocol address
	 */
	public InetAddress getInetAddress() {
		return destAddress;
	}

	@Override
	public void destroy() {
		// Disconnect, close, and dispose of the socket
		System.out.println("DatagramStreamingLayer is disconnecting.");
		stop();
		this.serverSocket.disconnect();
		this.serverSocket.close();
		this.serverSocket = null;
		
		// Set isValid to false to prevent attempted future uses of the the socket
		this.isValid = false;
	}

	@Override
	public boolean isValid() {
		return isValid;
	}

	@Override
	public boolean init() {
		try {
			serverSocket = new DatagramSocket(srcPort);
			return true;
		} catch (SocketException e) {
			System.err.println("SocketException in DatagramStreamingLayer");
			e.printStackTrace();
			return false;
		}

	}
	
	@Override
	public void stop() {
		isRunning = false;
	}
	
	@Override
	public void run() {
		if(!isValid) { return; }
		
		isReady=init();
		
		if(!isReady) {
			System.err.println("Unable to initialize DatagramStreamingLayer");
			return;
		}
		
		isRunning = true;
		
		while(isRunning) {
			try {
				String data = dataQueue.take();
								
				byte[] bytes = data.getBytes();
				DatagramPacket packet = new DatagramPacket(bytes,bytes.length,destAddress, destPort);
								
				serverSocket.send(packet);

			} catch (IOException e) {
				System.err.println("IOException in DatagramStreamingLayer");
				e.printStackTrace();
			} catch (InterruptedException e) {
				System.err.println("InterruptedException in DatagramStreamingLayer");
				e.printStackTrace();
			}
			
		}
	}


}
