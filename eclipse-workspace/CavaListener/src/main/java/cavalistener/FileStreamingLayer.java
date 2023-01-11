package cavalistener;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Streaming layer for outputting events to a field.
 * 
 * @author Sunny J. Fugate
 */
public class FileStreamingLayer implements StreamingLayer {
	
	private boolean isValid=true;
	private String fileName="";
	private boolean isRunning=false;
	private boolean isReady=false;
	private PrintWriter printer=null;
	
	LinkedBlockingQueue<String> dataQueue=new LinkedBlockingQueue<String>();

	public FileStreamingLayer(String outputFile) {
		this.fileName = outputFile;
	}
	
	@Override
	public void run() {
		if(!isValid) { return; }
		
		isReady=init();
		
		if(!isReady) {
			System.err.println("Unable to initialize FileStreamingLayer");
			return;
		}
		
		isRunning = true;
		
		while(isRunning) {
			try {
				String data = dataQueue.take();
				//System.out.println("fileStreamingLayer: Sending data to file...");
				printer.println(data);
				boolean isError = printer.checkError();
				if (isError) {
					System.err.println("Printer object in FileStreamingLayer has encountered an error");
				}
			} catch (InterruptedException e) {
				System.err.println("InterruptedException in FileStreamingLayer");
				e.printStackTrace();
			}
			
		}
	}

	@Override
	public boolean isValid() {
		return isValid;
	}

	@Override
	public void sendData(String data) throws StreamingLayerException {
		if(!isValid) {
			throw new StreamingLayerException("sendData called on invalid FileStreamingLayer");
		}

		this.dataQueue.add(data);
	}

	@Override
	public String getStreamingLayerInfo() {
		return "File: "+fileName;
	}

	@Override
	public void destroy() {
		
		if (printer == null) {return;}
		
		printer.close();
	}

	@Override
	public void stop() {
		isRunning=false;
	}

	@Override
	public boolean init() {
		try {
			printer = new PrintWriter(new FileWriter(new File(fileName),true));
		} catch (IOException e) {
			System.err.println("Failed creating printing object");
			e.printStackTrace();
			return false;
		}
		return true;
	}

}
