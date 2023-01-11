package cavalistener;

/**
 * Interface for StreamingLayers for transmitting event data to 
 * various data consumers. Streaming layers are independent threads
 * handling output to file and network-based data consumers.
 * 
 * @author Sunny J. Fugate
 */
public interface StreamingLayer extends Runnable {
		
		/**
		 * Returns whether this streaming layer is valid. 
		 * 
		 * Invalid streaming layers should be discarded as they 
		 * have already been disposed of.
		 * 
		 * @return boolean True if valid, False if disposed/invalid
		 */
		public boolean isValid();
		
		/**
		 * Sends data via the streaming layer implementation
		 * 
		 * @param data to be sent
		 * @throws StreamingLayerException
		 */
		public void sendData(String data) throws StreamingLayerException;

		/**
		 * Returns a string representation of the streaming layer configuration
		 * 
		 * @return string representation of the streaming layer configuration
		 */
		public String getStreamingLayerInfo();

		/**
		 * Destroys and disposes of the streaming layer. 
		 * 
		 * After a call to destroy() all future calls to 
		 * isValid should return false. 
		 */
		public void destroy();

		/**
		 * Stop the thread, but do not destroy
		 */
		void stop();

		/**
		 * Initialize the streaming layer
		 * 
		 * @return true if initialized
		 */
		boolean init();
		
}
