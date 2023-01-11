package cavalistener;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * This class is used for determining a user's performance while doing RE. Currently, it computes the graph distance between two
 * given addresses. One address is a "vulnerable" location defined in the metadata file, and the other is wherever the
 * reverse engineer clicked in Ghidra. These events are added to a queue and then the graph distances are found in a thread.
 * 
 * @author Jeremy Johnson
 */
public class CavaPerformanceMetrics implements Runnable{
	private static LinkedBlockingQueue<PluginEvent> performanceMetricQueue=null;
	
	//This is 4 depth, but we could find it on the depth of 4, which means we get 5.
	private static int maxFunctionDepth = 4;
	private static double secondsPerSearch = 2.5;
	private static int taskID = 0;
	private static String[][] keyAddress = new String[2][];
	private static boolean release = true;
	
	/**
	 * Constructor for performance metrics with an output queue 
	 * @param queue
	 */
	public CavaPerformanceMetrics(LinkedBlockingQueue<PluginEvent> queue) {
		performanceMetricQueue = queue;
	}
	public static int getTaskID() {
		return taskID;
	}
	public static String[][] getKeyAddress() {
		return keyAddress;
	}
	public static void setTaskID(int newTaskID) {
		taskID = newTaskID;
	}
	public static void setKeyAddresses(String[][] newKeyAddresses) {
		keyAddress = newKeyAddresses;
	}
	
	/**
	 * <p>This run loop executes in an infinite loop pulling items off the "LinkingBlockingQueue". The items are added to this queue
	 * from the file "CavaListenerPlugin.java" in the function "ProcessEvent". When the "GhidraLocationChangedEvent" happens
	 * the ProcessEvent function executes and the "PluginEvent" is added to the queue.</p><br/>
	 * 
	 * <p>The "PluginEvent" is absolutely key for anything in this file to work. It provides complete access to all ghidra API calls
	 * in the relevant binary. Access to all functions, assembly instructions, references, etc. Please refer to the *extremely* 
	 * helpful ghidra docs for additional information:<a href="https://ghidra.re/ghidra_docs/api/">https://ghidra.re/ghidra_docs/api/</a></p></br>
	 * 
	 * <p>Lastly, we know the task ID of the POI triage and analysis tasks are above a certain value, and we only want to execute this code in that phase. The 
	 * taskID is set in the file "CavaEventDisplayProvider.java" when the task changes.</p>
	 */
	@Override
	public void run() {
		while(true) {
			try {
				//Blocking wait for next event on queue
				PluginEvent event = performanceMetricQueue.take();
				
				String allKeyAddrs[][] = CavaPerformanceMetrics.getKeyAddress();//{"0x40797e"};
				//Any time there are key addresses given for a task we will try to compute the distances.
				if(allKeyAddrs.length > 0) {
					computeGraphDistance(event);
				}				

			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	//Function used to determine if more than X.X seconds have elapsed.
	private boolean runTimeElapsed(long initialTime) {
		long currTime = System.nanoTime();
		long timeElapsed = currTime - initialTime;
		//This code runs in milliseconds, divide by 1,000,000 to turn nano time into milliseconds.
		timeElapsed = timeElapsed/1000000;
		if(timeElapsed > secondsPerSearch*1000) {
			if(!release) {
				System.out.print("Took more than " + secondsPerSearch + " seconds to find the path. User is *very* far away.\n");
			}
			return true;
		}
		return false;
	}
	
	/**
	 * <p>This method loops over the assembly instructions in a given block. For each instruction we pull out the address as a string
	 * and add it to an ArrayList. </p><br/>
	 * 
	 * <p>We use this in one of two ways. The simple use case is to know how many instructions are in the given block. This is also
	 * the most common use as we iterate through all blocks in a function. The other way is when we know an address of interest is in the
	 * block, we will search for the address and calculate how many instructions from the start or end it is.</p><br/>
	 * 
	 * @param myProg
	 * @param blockAddrSet - The AddressSet for the block we are interested in.
	 * 
	 * @return ArrayList<String> - an array of strings, each one the address of the line of assembly.
	 * 
	 * @author Jeremy Johnson
	 */
	private ArrayList<String> getBlockAssemblyAddresses(Program myProg, AddressSet blockAddrSet) {
		InstructionIterator blockIter = myProg.getListing().getInstructions(blockAddrSet, true);
		ArrayList<String> allAddrs = new ArrayList<String>();
		Instruction currInstr;
		while(blockIter.hasNext()) {
			currInstr = blockIter.next();
			allAddrs.add(currInstr.getAddressString(false, false));
		}		
		return allAddrs;
	}
	
	/**
	 * <p>This method identifies the number of assembly instructions and blocks away two addresses are. Before calling this function the startByteAddr
	 * must be guaranteed to be a lower numerical value than the endByteAddr. The code initially finds the distance from the startByteAddr to the end
	 * of the block it is in. When adding new blocks to the queue, all paths are considered as long as the block name is not in the hash set already.
	 * Each block that is added increments the block counter by one.</p><br/>
	 * 
	 * <p>If the startByteAddr is in an "if()" and the endByteAddr is in the corresponding "else()" statement, the code path from one to the other will be
	 * impossible (unless this is in a loop of some sort). In the event we fail to find the distance from one point to the other the code will return null.</p>
	 * 
	 * <br/><br/>
	 * <h3>Optimizations</h3>
	 * <p>A valid optimization the code makes is maintaining a hash set of visited block names during the search. Once w =====e have examined a block in the function
	 * there is never a reason to visit it again, this greatly cuts down on run time and prevents infinite loops.</p>
	 * 
	 * <p>The code can not stop looking for the endByteAddr function block just because the addresses in a block are larger than it. Loops in ghidra can be
	 * complex and can return us back up any function block, so we must exhaustively search through all blocks from the start until all 
	 * reachable blocks have been examined.</p>
	 * <br/><br/>
	 * 
	 * <h3> Path Taken </h3>
	 * <p>The path we find is the first path we discover from the two addresses. This is not guaranteed to be the shortest path by assembly instructions.
	 * We could easily change the functionality to find the shortest path, however how can we know if the user would take the optimal path to begin with?
	 * The code does, however, find the shortest block distance between the two addresses given. Both approaches have their pros and cons, for the moment
	 * this is how I made it.</p>
	 * <br/><br/>
	 * 
	 * <h3>Debugging</h3>
	 * <p>To make debugging easier I created a full stack trace that is printed once the path is found, and only when it is found. Unfortunately
	 * this function is called from a variety of places and the prints will happen many times. This makes debugging difficult when the function
	 * distance is larger than one, I strong recommend only using them when clicking in the same function as the vulnerable address.</p>
	 * 
	 * <br/><br/>
	 * @param startByteAddr - The initial byte address we are starting the search from.
	 * @param endByteAddr - The goal byte address we are ending the search on.
	 * @param myProg
	 * @param extraAssembly - When we search from one address to another this is false. When we check XREFs we count the initial assembly instruction, this argument is true.
	 * @return ArrayList<Object> - First item is the address that we are returning at
	 * 							 - Second, third, and fourth is the assembly distance, block distance, and function distance, respectively.
	 * 							 - Will return null if it fails to find the path or critical error happens.
	 * @author Jeremy Johnson
	 */	
	private ArrayList<Integer> findAddressDistances(Address startByteAddr, Address endByteAddr, Program myProg, boolean extraAssembly) {
		//Potential TODO: This code does a BFS and returns the shortest block path. If we wanted to find the shortest assembly distance,
		//				  we could turn this into an exhaustive search through all the paths in the function and keep a "min path" found.
		//				  The shortest block path and shortest assembly distance both have their merits, for now leaving as is.
		int assemblyDistance = 0;
		int blockDistance = 0;
		String startAddr = startByteAddr.toString();
		String endAddr = endByteAddr.toString();
		//We need to get the funcAddrSet for determining which branches to take later.
		Function func = myProg.getFunctionManager().getFunctionContaining(startByteAddr);
		if(func == null) {
			return null;
		}
		Address minFuncAddress = func.getBody().getMinAddress();
		Address maxFuncAddress = func.getBody().getMaxAddress();
		AddressSet funcAddrSet = new AddressSet(minFuncAddress, maxFuncAddress);
		
		//Now get blocks and find the "startAddr".
		ArrayList<ArrayList<Object>> blockQueue = new ArrayList<ArrayList <Object>>();
		BasicBlockModel bbm = new BasicBlockModel(myProg, false);
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		CodeBlock initialBlock;
		try {
			initialBlock = bbm.getFirstCodeBlockContaining(startByteAddr, monitor);
			if(initialBlock == null) {
				return null;
			}
			Address minBlockAddr = initialBlock.getMinAddress();
			Address maxBlockAddr = initialBlock.getMaxAddress();
			AddressSet currBlockAddrSet = new AddressSet(minBlockAddr, maxBlockAddr);
			ArrayList<String> allBlockInstructions = getBlockAssemblyAddresses(myProg, currBlockAddrSet);
			
			//Two cases, either both addresses are in this block or only the startAddr is.
			if(currBlockAddrSet.contains(endByteAddr)) {
				int distance = 0;
				boolean foundStart = false;
				for(int i = 0; i < allBlockInstructions.size(); i++){
					String instruction = allBlockInstructions.get(i);
					if(instruction.equals(startAddr)) {
						foundStart = true;				
					}
					if(instruction.equals(endAddr)) {
						assemblyDistance += distance;
						break;
					}
					if(foundStart) {
						distance += 1;
					}
				}
				if(!release) {
					//NOTE: This code is commented out. Unless you are debugging this code, do not put it in. It causes far too much output to make any sense of it.
					//System.out.print("[[DISTANCE]]\nAddresses in same block. Start Addr: " + startByteAddr + " | End Addr: " + endByteAddr + " | Assembly Distance: " + assemblyDistance + "\n");
				}
				ArrayList<Integer> distances = new ArrayList<Integer>();
				distances.add(assemblyDistance);
				distances.add(blockDistance);
				return distances;
			}
			//Otherwise we get the distance from the address clicked to the end of the block.
			for(int i = 0; i < allBlockInstructions.size(); i++){
				String instruction = allBlockInstructions.get(i);
				if(instruction.equals(startAddr)) {
					//NOTE 1: We make this value NEGATIVE! Because in the first iteration of the loop below we add the instructions.size(), which effectively gets me the assembly instructions
					//		from the instruction clicked to the end of the block. The -1 removes the assembly instruction we are on. Exactly what we wanted.. Trust me this is right! 
					assemblyDistance = assemblyDistance - i - 1;
					//NOTE 2: When coming from an XREF, we actually want to count the very first assembly instruction in the block. This normally causes an off by one error, fixed here.
					//		When calling this function, this argument is only true if you are checking distance from address to minAddress of function!
					if(extraAssembly) {
						assemblyDistance += 1;
					}
					break;
				}
			}
			ArrayList<String> visitedBlocks = new ArrayList<String>();
			String initialBlockInfo = "[[DISTANCE]]\nStart Addr: " + startByteAddr + " | Was " + assemblyDistance + " from end of block. Block name: " + initialBlock.getName() + "\n";
			visitedBlocks.add(initialBlockInfo);
			ArrayList<Object> blockEntry = new ArrayList<Object>();
			blockEntry.add(initialBlock);
			blockEntry.add(assemblyDistance);
			blockEntry.add(blockDistance);
			blockEntry.add(visitedBlocks);
			blockQueue.add(blockEntry);
		} catch (Exception e) {
			System.out.println("Clicked addr not inside a block.. exception: " + e);
			return null;
		}
		Set<String> visitedBlocks = new HashSet<String>();
		visitedBlocks.add(initialBlock.getName());
		//Loop while there are new blocks that are not yet seen.
		while(blockQueue.size() > 0) {
			//First we need to check to see if address is in this block. If it is not, get total assembly instructions and add them up
			//	If it is, we need to find how many instructions to that address. 
			ArrayList<Object> blockInfo = blockQueue.get(0);
			//Get the block and the distances traveled so far.
			CodeBlock currentBlock = (CodeBlock) blockInfo.get(0);
			int currAssemblyDistance = (int) blockInfo.get(1);
			int currBlockDistance = (int) blockInfo.get(2);
			@SuppressWarnings("unchecked")
			ArrayList<String> blockHistory = (ArrayList<String>) blockInfo.get(3);
			//remove it from the queue. This consumes it so we don't use it again.
			blockQueue.remove(0);
			Address minBlockAddr = currentBlock.getMinAddress();
			Address maxBlockAddr = currentBlock.getMaxAddress();
			AddressSet currBlockAddrSet = new AddressSet(minBlockAddr, maxBlockAddr);
			//load all of the instructions in the block. 
			ArrayList<String> allBlockInstructions = getBlockAssemblyAddresses(myProg, currBlockAddrSet);
			//Check to see if the goal address is in this block.
			if(currBlockAddrSet.contains(endByteAddr)) {
				int additionalAssemblyDistance = 0;
				for(int i = 0; i < allBlockInstructions.size(); i++){
					String instruction = allBlockInstructions.get(i);
					if(instruction.equals(endAddr)) {
						additionalAssemblyDistance = i;				
						break;
					}
				}
				if(!release) {
					/*
					 *NOTE: This code is commented out. Unless you are debugging this code, do not put it in. It causes far too much output to make any sense of it.
					String finalHistory = "Found the block: " + currentBlock.getName() + " | Goal addr was " + additionalAssemblyDistance + " from start of block. Total assembly distance: " + (currAssemblyDistance + additionalAssemblyDistance) + " | Total block distance: " + currBlockDistance + "\n"; 
					for(int i = 0; i < blockHistory.size(); i++) {
						System.out.print(blockHistory.get(i));
					}
					System.out.print(finalHistory);
					*/
				}
				ArrayList<Integer> distances = new ArrayList<Integer>();
				distances.add(currAssemblyDistance + additionalAssemblyDistance);
				distances.add(currBlockDistance);				
				return distances;
			}
			try {
				CodeBlockReferenceIterator destBlocks = currentBlock.getDestinations(monitor);
				while(destBlocks.hasNext()) {
					CodeBlockReference blockRef = destBlocks.next();
					CodeBlock nextBlock = blockRef.getDestinationBlock();
					//The block reference returns the address of where that block begins. If it isn't IN the overall function, we don't want it.
					if(funcAddrSet.contains(blockRef.getReference())) {
						//If we have not visited this block before, add it to our ArrayList and hash map.
						if(!visitedBlocks.contains(nextBlock.getName())) {
							ArrayList<Object> blockEntry = new ArrayList<Object>();
							//Document the new block information, address distance, etc for debugging.
							@SuppressWarnings("unchecked")
							ArrayList<String> newBlockHistory = (ArrayList<String>) blockHistory.clone();
							String newHistory = "New block name: " + nextBlock.getName() + " | New assembly size: " +  (currAssemblyDistance + allBlockInstructions.size()) + " | Added " + allBlockInstructions.size() + " from prev block. Block distance: " + currBlockDistance + "\n";
							newBlockHistory.add(newHistory);
							blockEntry.add(nextBlock);
							blockEntry.add(currAssemblyDistance + allBlockInstructions.size());
							blockEntry.add(currBlockDistance + 1);
							blockEntry.add(newBlockHistory);
							blockQueue.add(blockEntry);				
							visitedBlocks.add(nextBlock.getName());
						}
					}
				}
			} catch (Exception e) {
				System.out.print("[ERROR] Error getting dest blocks or something else: " + e + "\n");
				continue;
			}
		}
		if(!release) {
			//Prints too frequently, leaving it out unless specifically debugging this code.
			//System.out.print("Failed to find goal, logic makes it impossible.\n");			
		}
		return null;
	}

	/**
	 * <p>This method finds function distances when we are given an address and it is not in the function of the keyByteAddr (vulnerable address specified in
	 * the metadata.json file). The goal is to know how many functions you need to traverse to find the function of interest with the keyByteAddr.
	 * The path forward is not immediately clear. Was the user in the correct function with the vulnerability then double click a function and 
	 * leave it? Or did the user look at the XREFs to the vulnerable and go "back" a function? Only way to know is to try them both!</p>
	 * 
	 * <p>We initially check the XREFs. We find the distance from the byteAddress to the start of the function, as this is considered distance
	 * in how far they would be after entering from the XREF. We then add all XREF calls to a queue.</p>
	 * 
	 * <p>We then start at the beginning of the function and loop through all blocks in the function. In each block we look for function calls, adding
	 * them to the queue as well.</p>
	 * 
	 * <p>After both of these tasks is complete I have a new group of functions to examine. We perform a breadth first search with the queue, ensuring that
	 * we find traverse the shortest number of functions needed to find our target function.</p>
	 * 
	 * <p>The code keeps track of what functions have been visited in a hash set, removing duplicate work. When looking at called functions, I do not 
	 * allow system calls to be placed on the queue. They provide a "back door" to the vulnerable function if used in the vulnerable function and 
	 * causes the incorrect length to be reported. isThunk() is utilized to determine if it is a system call or not.</p>
	 * 
	 * <p>Each time we add a function to the queue we check to see if the keyByteAddr is in this function or not. When it is, we immediately return with
	 * the distances needed to get to that point. </p>
	 * <br/><br/>
	 * 
	 * <h3>Path Taken</h3>
	 * 
	 * <p>The path we find isn't always the "correct" path that someone is thinking. For example if function B is called from function A 
	 * in two locations, the algorithm will use the distances associated with the first function call to B and ignore the second. This
	 * may be right, but it also might be wrong. Currently we are satisfied with the functionality and are leaving it as it is.</p>
	 * <br/><br/>
	 * 
	 * <h3>Debugging</h3>
	 * 
	 * <p>To make debugging easier we created a full stack trace that is printed once the path is found, and only when it is found. This
	 * can be used to hand verify the path and distances taken.</p>
	 * 
	 * @param keyByteAddr - Address containing the vulnerability
	 * @param byteAddress - Address given that was just interacted with.
	 * @param myProg
	 * @return ArrayList<Object> - First item is the address that we are returning at
	 * 							 - Second, third, and fourth is the assembly distance, block distance, and function distance, respectively.
	 * 							 - Will return null if it fails to find the path or critical error happens.
	 *
	 * @author Jeremy Johnson
	 */	
	private ArrayList<Object> findFunctionDistance(Address keyByteAddr, Address byteAddress, Program myProg) {
		long startTime = System.nanoTime();
		BasicBlockModel bbm = new BasicBlockModel(myProg, false);
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		AddressFactory addrFact = myProg.getAddressFactory();
		ArrayList<ArrayList<Object>> functionQueue = new ArrayList<ArrayList <Object>>();
		int assemblyDistance = 0;
		int blockDistance = 0;
		int functionDistance = 0;
		ArrayList<Object> functionEntry = new ArrayList<Object>();
		ArrayList<String> visitedHistory = new ArrayList<String>();
		visitedHistory.add("[[START BACKTRACE]]\nStarting at address: " + byteAddress + "\n");
		functionEntry.add(byteAddress);
		functionEntry.add(assemblyDistance);
		functionEntry.add(blockDistance);
		functionEntry.add(functionDistance);
		functionEntry.add(visitedHistory);
		functionQueue.add(functionEntry);
		while(functionQueue.size() > 0) {
			ArrayList<Object> funcInfo = functionQueue.get(0);
			//This address could EITHER be the minAddress for the function or some address on a function call.
			Address prevGivenAddr = (Address) funcInfo.get(0);
			int currAssemblyDistance = (int) funcInfo.get(1);
			int currBlockDistance = (int) funcInfo.get(2);
			int currFunctionDistance = (int) funcInfo.get(3);
			//This is always an array list of strings, no need for the warning.
			@SuppressWarnings("unchecked") 
			ArrayList<String> nodeHistory = (ArrayList<String>) funcInfo.get(4); 
			functionQueue.remove(0);
			//TWO THINGS TO CHECK:
			//	1) Function calls that call the function we are in.
			//	2) Function calls FROM the function we are in.
			//First we check (1). If the address given is minAddress, done. Otherwise we have to get distance from the start, as a function that called 
			//the one we are in would have had to traverse that distance.
			Function func = myProg.getFunctionManager().getFunctionContaining(prevGivenAddr);
			if(func == null) {
				//This shouldn't be possible but just to be extra sure we will verify.
				continue;
			}
			Address origMinAddress = func.getBody().getMinAddress();
			String minAddressString = origMinAddress.toString();
			String prevGivenAddrStr = prevGivenAddr.toString();
			int additionalAssemblyDistance = 0;
			int additionalBlockDistance = 0;
			if(!minAddressString.equals(prevGivenAddrStr)) {
				//If the addresses are not equal, we need to find the distance from the given address to the very beginning. Last argument is true to account for that first instruction in the initial block edge case.
				ArrayList<Integer> distances = findAddressDistances(origMinAddress, prevGivenAddr, myProg, true);
				if(distances != null) {
					additionalAssemblyDistance = additionalAssemblyDistance + distances.get(0);
					additionalBlockDistance = additionalBlockDistance + distances.get(1);
				}
			}
			ReferenceIterator allRefs = myProg.getReferenceManager().getReferencesTo(origMinAddress);
			Set<String> visitedFunctions = new HashSet<String>();
			visitedFunctions.add(origMinAddress.toString());
			while(allRefs.hasNext()) {
				Reference ref = allRefs.next();
				//This gets me every location that THIS function is called from. (getFromAddress)
				Address referenceAddr = ref.getFromAddress();
				//We have not seen this function before. Maybe it has the keyAddress we are looking for!?
				Function newFunc = myProg.getFunctionManager().getFunctionContaining(referenceAddr);
				if(newFunc != null) {
					Address minAddress = newFunc.getBody().getMinAddress();
					if(!visitedFunctions.contains(minAddress.toString())) {
						visitedFunctions.add(minAddress.toString());
						Address maxAddress = newFunc.getBody().getMaxAddress();					
						AddressSet funcAddrSet = new AddressSet(minAddress, maxAddress);
						if(funcAddrSet.contains(keyByteAddr)) {
							if(!release) {
								String finalHistory = "Found the function: " + newFunc.getName() + " in XREF we are looking for! ref addr: " + referenceAddr  + " Additional assembly: " + additionalAssemblyDistance + " | Additional blocks: " + additionalBlockDistance + "\n"; 
								for(int i = 0; i < nodeHistory.size(); i++) {
									System.out.print(nodeHistory.get(i));
								}
								System.out.print(finalHistory);								
							}
							ArrayList<Object> output = new ArrayList<Object>();
							output.add(referenceAddr);
							output.add(currAssemblyDistance + additionalAssemblyDistance);
							output.add(currBlockDistance + additionalBlockDistance);
							output.add(currFunctionDistance + 1);
							return output;
						}
						if(currFunctionDistance >= maxFunctionDepth) {
							continue;
						}
						@SuppressWarnings("unchecked")
						ArrayList<String> prevNodeHistory = (ArrayList<String>) nodeHistory.clone();
						String newHistory = "[XREF] Ref addr: " + referenceAddr + " in function: " + newFunc.getName() + " Assembly: " + currAssemblyDistance + " | " +  additionalAssemblyDistance + " || Block: " + currBlockDistance + " | " + additionalBlockDistance + " || new func distance: " + (currFunctionDistance+1) + "\n";
						prevNodeHistory.add(newHistory);
						//Create new entry in the queue for the unvisited function.
						ArrayList<Object> funcEntry = new ArrayList<Object>();
						funcEntry.add(referenceAddr);
						funcEntry.add(currAssemblyDistance + additionalAssemblyDistance);
						funcEntry.add(currBlockDistance + additionalBlockDistance);
						funcEntry.add(currFunctionDistance + 1);
						funcEntry.add(prevNodeHistory);
						functionQueue.add(funcEntry);				
					}
				}
			}
			Address minFuncAddress = func.getBody().getMinAddress();
			Address maxFuncAddress = func.getBody().getMaxAddress();
			AddressSet funcAddrSet = new AddressSet(minFuncAddress, maxFuncAddress);	
			//now get blocks and find the "startAddr".
			ArrayList<ArrayList<Object>> blockQueue = new ArrayList<ArrayList <Object>>();
			CodeBlock initialBlock;
			try {
				initialBlock = bbm.getFirstCodeBlockContaining(minFuncAddress, monitor);
				//No blocks in the function? Skip!
				if(initialBlock == null) {
					continue;
				}
				ArrayList<Object> blockEntry = new ArrayList<Object>();
				//First block in the function. Distance is distance up to this point, actual address could be anywhere.
				blockEntry.add(initialBlock);
				blockQueue.add(blockEntry);
			} catch (Exception e) {
				System.out.println("provided addr not inside a block.. exception: " + e);
				return null;
			}
			Set<String> visitedBlocks = new HashSet<String>();
			visitedBlocks.add(initialBlock.getName());
			//Loop while there are new blocks that are not yet seen. This is a brute force approach, starting at the start of a function, check ALL function calls from it, from all blocks.
			while(blockQueue.size() > 0) {
				//The vast majority of run time is spent going through blocks, only need to check if too much time has elapsed here.
				if(runTimeElapsed(startTime)) {
					return null;
				}
				ArrayList<Object> blockInfo = blockQueue.get(0);
				//Get the block and the distances traveled so far.
				CodeBlock currentBlock = (CodeBlock) blockInfo.get(0);
				blockQueue.remove(0);		
				try {
					CodeBlockReferenceIterator destBlocks = currentBlock.getDestinations(monitor);
					while(destBlocks.hasNext()) {
						/*
						 * Notes on what we have access to from blockRef:
						 * 		1) .getSourceAddress() -> This is the address of where the block starts, in the callee function.
						 * 		2) .getReferentAddress() -> This is the address that the function is called from.
						 * 		3) .getDestinationAddress() and .getReference() -> They both refer to the first address of the new function being referenced. 
						 * 
						 */
						CodeBlockReference blockRef = destBlocks.next();
						int assemblyOffset = 0;
						int blockOffset = 0;
						//Get the distance from the function calling our target to where we started. If path DNE, just use start of the function (minAddress)
						Address startByteAddr = blockRef.getReferent();
						String startAddr = startByteAddr.toString();
						Address endByteAddr = prevGivenAddr;
						String endAddr = endByteAddr.toString();
						if(startAddr.compareTo(endAddr) > 0) {
							//if this is true then startAddr (where we clicked) is AFTER the key address. Need to swap them.
							String tmp = endAddr;
							endAddr = startAddr;
							startAddr = tmp;
							startByteAddr = addrFact.getAddress(startAddr);
							endByteAddr = addrFact.getAddress(endAddr);
						}						
						ArrayList<Integer> distances = findAddressDistances(startByteAddr, endByteAddr, myProg, false);
						if(distances != null) {
							assemblyOffset = assemblyOffset + distances.get(0);
							blockOffset = blockOffset + distances.get(1);
						}
						else {
							//This is a fall back, pretending the user clicked on the first address. Gets us distance data more reliably.
							distances = findAddressDistances(minFuncAddress, prevGivenAddr, myProg, false);
							if(distances != null) {
								assemblyOffset = assemblyOffset + distances.get(0);
								blockOffset = blockOffset + distances.get(1);
							}
							else {
								//If we can't find a path from clicked to current OR from minAddress to current (second one should be impossible), just pass.
								continue;
							}
						}
						CodeBlock nextBlock = blockRef.getDestinationBlock();
						Address destAddr = blockRef.getDestinationAddress();
						//For adding to the function queue, only look at the function destinations that are outside of our current function.
						if(!funcAddrSet.contains(destAddr)) {
							//If we have not visited this function before, add it to the function queue and note that it has been visited.
							if(!visitedFunctions.contains(destAddr.toString())) {
								//Look to see if this destAddr function contains the keyByteAddr. If it does, we found it! 
								Function destFunc = myProg.getFunctionManager().getFunctionContaining(destAddr);
								if(destFunc != null) {
									//isThunk() is always true on system calls. We don't want to go into sys calls (printf, etc) in the search as they are backdoors to faster, incorrect paths to the vulnerabilities.   
									if(destFunc.isExternal() || destFunc.isThunk()) {
										//If this function is not local, then we don't want to go into it. 
										continue;
									}
									Address minAddress = destFunc.getBody().getMinAddress();
									if(!visitedFunctions.contains(minAddress.toString())) {
										visitedFunctions.add(minAddress.toString());
										Address maxAddress = destFunc.getBody().getMaxAddress();
										AddressSet destFuncAddrSet = new AddressSet(minAddress, maxAddress);
										if(destFuncAddrSet.contains(keyByteAddr)) {
											if(!release) {
												String finalHistory = "Found the function: " + destFunc.getName() + " we are looking for!!!! dest addr: " + destAddr  + " | Additional assembly: " + assemblyOffset + " | Additional blocks: " + blockOffset + "\n"; 
												for(int i = 0; i < nodeHistory.size(); i++) {
													System.out.print(nodeHistory.get(i));
												}
												System.out.print(finalHistory);												
											}	
											ArrayList<Object> output = new ArrayList<Object>();
											output.add(destAddr);
											output.add(currAssemblyDistance + assemblyOffset);
											output.add(currBlockDistance + blockOffset);
											output.add(currFunctionDistance + 1);
											return output;
										}
									}
									if(currFunctionDistance >= maxFunctionDepth) {
										continue;
									}
									@SuppressWarnings("unchecked")
									ArrayList<String> prevNodeHistory = (ArrayList<String>) nodeHistory.clone();
									String newHistory = "[FN_CALL] Call Func Addr: " + blockRef.getReferent() + " Dest addr: " + destAddr + " dest function: " + destFunc.getName() + " Assembly: " + currAssemblyDistance + " | " +  assemblyOffset + " || Block: " + currBlockDistance + " | " + blockOffset + " || new func distance: " + (currFunctionDistance+1) + "\n";
									prevNodeHistory.add(newHistory);
									//If this function is not our target function, add the function to the queue to be examined later.
									ArrayList<Object> newFunctionEntry = new ArrayList<Object>();
									newFunctionEntry.add(destAddr);
									//the assembly distance and block distance are updated during traversal, function distance remains the same.
									newFunctionEntry.add(currAssemblyDistance + assemblyOffset);
									newFunctionEntry.add(currBlockDistance + blockOffset);
									newFunctionEntry.add(currFunctionDistance + 1);
									newFunctionEntry.add(prevNodeHistory);
									functionQueue.add(newFunctionEntry);
									visitedFunctions.add(minAddress.toString());
								}
							}
						}
						else {
							//If we have not visited this block before, add it to our ArrayList and hash map.
							if(!visitedBlocks.contains(nextBlock.getName())) {
								ArrayList<Object> blockEntry = new ArrayList<Object>();
								blockEntry.add(nextBlock);
								blockQueue.add(blockEntry);				
								visitedBlocks.add(nextBlock.getName());
							}
						}
					}
				} catch (Exception e) {
					System.out.print("[ERROR] Error getting dest blocks or something else: " + e + "\n");
					continue;
				}			
			}	
		}
		if(!release) {			
			System.out.print("Failed to find function with key address\n");
		}
		return null;
	}
	
	/**  
	 *  <p>This method controls the logic to how we find the distances between the two addresses. It will immediately pull out the keyAddress
	 *  and the function that the ProgramLocationChangedEvent took place. If it determines that the clicked address is not in the same function 
	 *  as the key address, it will immediately call the function findFunctionDistance(). The distances found in this function will be used as the
	 *  starting point and the clicked address will be updated accordingly.</p><br/>
	 *  
	 *  <p>If the clicked address is in the function with the vulnerable address, the distances are all initialized to zero. The code then calls the
	 *  function "findAddressDistances" which finds the distance between the two variables.</p><br/>
	 *  
	 *  <p>After we either fail to find the distance or we find it, a GhidraEvent will be generated with the information. This  uses the class
	 *  "generateGraphDistanceEvent" and creates the event with the name "GraphDistanceEvent". This is logged with all other logs in CAVA.</p><br/>
	 *  
	 * @param event
	 * @return void
	 *
	 * @author Jeremy Johnson
	 */		
	private void computeGraphDistance(PluginEvent event) {
		long start = System.nanoTime();
		ProgramLocationPluginEvent pluginEvent = (ProgramLocationPluginEvent) event;
		ProgramLocation location=pluginEvent.getLocation();
		Address byteAddress = location.getByteAddress();
		Program myProg = pluginEvent.getProgram();
		AddressFactory addrFact = myProg.getAddressFactory();
		Function func = myProg.getFunctionManager().getFunctionContaining(byteAddress);
		if(func != null) {
			/*
			 * Requirements: Need to figure out the distance from two addresses.
			 * 			- keyAddresses may have multiple, so code it for such a case.
			 * 			- do a BFS, keep a hash map of all nodes visited so we don't go to them again.
			 * 			- Keep a block counter and a assembly distance counter. Multiple paths means multiple lengths to track. 
			 * 				-> Keep a distance associated with each path.. use a queue with new starting address and blocks/assembly instructions seen so far.
			 */
			int assemblyDistance;
			int blockDistance;
			int functionDistance;
			String taskIDStr = String.valueOf(getTaskID());
			String allKeyAddrs[][] = CavaPerformanceMetrics.getKeyAddress();//{"0x40797e"};

			for(String[] keyAddrInfo: allKeyAddrs) {
				if(keyAddrInfo == null) {
					continue;
				}
				String keyAddr = keyAddrInfo[0];
				String taskDescriptor = keyAddrInfo[1];	
				if(keyAddr.contains("0x")) {
					keyAddr = keyAddr.replace("0x", "");
				}
				while(keyAddr.length() < 8) {
					keyAddr = "0" + keyAddr;
				}
				//Converts a string into an Address type.
				Address keyByteAddr = addrFact.getAddress(keyAddr);
				//If the address has a typo and is not in the address space, this will return null and we will stop executing.
				if(keyByteAddr == null) {
					return;
				}
				Address minFunctionAddress = func.getBody().getMinAddress();
				Address maxFunctionAddress = func.getBody().getMaxAddress();
				AddressSet funcAddrSet = new AddressSet(minFunctionAddress, maxFunctionAddress);
				//We initially set these variables, but "startAddr" MUST be less than endAddr. We perform a switch below as needed.
				String startAddr = byteAddress.toString();
				Address startByteAddr = byteAddress;
				Address endByteAddr = keyByteAddr;
				String endAddr = keyAddr;
				//This case is where the key address we have is in the function that has been clicked. 
				if(!funcAddrSet.contains(keyByteAddr)) {
					//Did the person click in a function that calls our desired function? or did they enter a function FROM ours? This function checks both and finds a path to our goal function.
					ArrayList<Object> functionDistances = findFunctionDistance(keyByteAddr, byteAddress, myProg);
					if(functionDistances == null) {
						long finish = System.nanoTime();
						long timeElapsed = finish - start;
						if(!release) {
							System.out.print("[TIME] " + timeElapsed/1000000 + " | Failed to find the goal function");						
						}
						GhidraEvent<?> graphDistanceEvent = GhidraEvent.generateGraphDistanceEvent(byteAddress.toString(), keyAddr, -1, -1, -1, taskIDStr, "NOT FOUND", pluginEvent, taskDescriptor);
						CavaEventPublisher.publishNewEvent(graphDistanceEvent);
						//NOTE: This will cause no additional logs to be made for salient distractors. If the first times out, the rest will also. This will ensure the code keeps up with new addresses.
						return;
					}
					startByteAddr = (Address) functionDistances.get(0);
					startAddr = startByteAddr.toString();
					assemblyDistance = (int) functionDistances.get(1);
					blockDistance = (int) functionDistances.get(2);
					functionDistance = (int) functionDistances.get(3);
				}
				else {
					assemblyDistance = 0;
					blockDistance = 0;
					functionDistance = 0;
				}
				//addr.compareTo(other_addr) --> returns: 1 (addr larger) // 0 (addr ==) // -1 (addr smaller)
				if(startAddr.compareTo(endAddr) == 0) {
					GhidraEvent<?> graphDistanceEvent = GhidraEvent.generateGraphDistanceEvent(byteAddress.toString(), keyAddr, assemblyDistance, blockDistance, functionDistance, taskIDStr, "FOUND", pluginEvent, taskDescriptor);
					CavaEventPublisher.publishNewEvent(graphDistanceEvent);
					continue;
				}
				else if(startAddr.compareTo(endAddr) > 0) {
					//if this is true then startAddr (where we clicked) is AFTER the key address. Need to swap them.
					String tmp = endAddr;
					endAddr = startAddr;
					startAddr = tmp;
					startByteAddr = addrFact.getAddress(startAddr);
					endByteAddr = addrFact.getAddress(endAddr);
				}
				//Both addresses are in the same function, simply find their distances and generate the event.
				ArrayList<Integer> distances = findAddressDistances(startByteAddr, endByteAddr, myProg, false);
				if(distances != null) {
					assemblyDistance = assemblyDistance + distances.get(0);
					blockDistance = blockDistance + distances.get(1);
					GhidraEvent<?> graphDistanceEvent = GhidraEvent.generateGraphDistanceEvent(byteAddress.toString(), keyAddr, assemblyDistance, blockDistance, functionDistance, taskIDStr, "FOUND", pluginEvent, taskDescriptor);
					CavaEventPublisher.publishNewEvent(graphDistanceEvent);
				}
				else {
					GhidraEvent<?> graphDistanceEvent = GhidraEvent.generateGraphDistanceEvent(byteAddress.toString(), keyAddr, -1, -1, -1, taskIDStr, "NOT CONNECTED", pluginEvent, taskDescriptor);
					CavaEventPublisher.publishNewEvent(graphDistanceEvent);
				}
				if(!release) {
					long finish = System.nanoTime();
					long timeElapsed = finish - start;
					System.out.print("[TIME] " + timeElapsed/1000000 + " | Final Distances: assembly distance: " + assemblyDistance + " | block distance: " + blockDistance + " | function distance: " + functionDistance);				
				}
			}
		}
	}
	
	/**
	 * If the queue is instantiated, 
	 * send event to the global event publishing queue.
	 * 
	 * @param CavaTask
	 * 
	 * @author Jeremy Johnson
	 */
	public static void updateTaskData(CavaTask currentTask) {
		if(currentTask != null) {
			CavaPerformanceMetrics.setKeyAddresses(currentTask.getKeyAddresses());
			CavaPerformanceMetrics.setTaskID(currentTask.getTaskID());			
		}
		else {
			CavaPerformanceMetrics.setKeyAddresses(new String[2][]);
			CavaPerformanceMetrics.setTaskID(0);
		}
	}
	
}

/*
 * --- Boiler plate java/ghidra code that may be useful later ---
 * 
 * Code that loops through all function names. Note: "isThunk()" returns True if it is a system call!
System.out.print("All function names:\n " );
for (Function func1: myProg.getFunctionManager().getFunctionsNoStubs(true)) {
	System.out.print(func1.getName() + " | external: " + func1.isExternal() + " | global: " + func1.isGlobal() + " | Thunk: " + func1.isThunk() + "\n");
}*/



