package cavalistener;

/**
 * A streaming layer for piping events to standard output.
 * 
 * @author Sunny J. Fugate
 */
public class StdOutStreamingLayer implements StreamingLayer {
	
	
	/**
	 * Prints data to standard output
	 */
	@Override
	public void sendData(String data) throws StreamingLayerException {
		System.out.println(data);
	}

	/**
	 * Returns a string name of the streaming layer.
	 * 
	 * @return returns the string "stdout"
	 */
	@Override
	public String getStreamingLayerInfo() {
		return "stdout";
	}

	/**
	 * StdOut StreamingLayer is always valid.
	 * 
	 * @return always returns true for StdOut streaming layer
	 */
	@Override
	public boolean isValid() {
		return true; 
	}

	/**
	 * Method has no effect for StdOut streaming layer.
	 */
	@Override
	public void destroy() {
		return;
	}

	/**
	 * Method has no effect for StdOut streaming layer.
	 */
	@Override
	public void run() {
		return;
	}

	/**
	 * Method has no effect for StdOut streaming layer. 
	 */
	@Override
	public void stop() {
		return;
	}

	/**
	 * StdOut streaming layer does not need initialized.
	 * 
	 * @return always returns true for StdOut streaming layer
	 */
	@Override
	public boolean init() {
		return true;
	}


}
