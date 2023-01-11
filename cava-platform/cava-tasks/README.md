# CAVA Experimental Tasks

CAVA's Ghidra tasks and task sequence are now stored in a directory of flat files consisting of

1. TaskName.json -- metadata concerning the task such as the binary used, taskID, and trialID
2. TaskName-instructions.txt -- the Unix plain text (\n linebreaks!) containing the instructions which are read by a subject when using Ghidra
3. cava-task-sequence.txt -- a file mapping each TaskName to a sequence number so that task ordering is fully specified but easily changed


## Updating a Task

*Task Instructions*: To update task instructions, use a text editor to open and modify one of the "-instructions" files, edit as needed, and save, ensuring that line endings are Unix-style (lf).   

*Task Metadata*: To update task metadata, use a text editor (or JSON editor) to open and modify the metadata, ensuring to adhere to JSON format for the file. The field names are mapped directly to a CavaTask Java object and as such the field names should match the provided format (fields are case sensitive).

*Task Sequence*: To update the task sequence, use a text editor to open and modify the cava-task-sequence.txt file and change actual order of the tasks as they appear in the file.  The only column in this file should be the TaskName which should use underscores and not spaces. 

*Validation*: To validate that your changes are correct, we have provided a helper script which will perform a validation of each of the files to ensure things like line endings and JSON are adhered to. 


### Requirements for Editing
**Line Endings**: Be aware that some editors will attempt to change line endings which may break loading the task info into our Ghidra plugin.  Files should use Unix '\n' (lf)  line endings which is different than native MacOS '\r' (cr) or Windows '\r\n' (crlf).

**Task Name**: Task names must be unique and must use underscores instead of spaces in all places.  Task names are used to take the sequence file and locate the metadata and instructions files.  Task names will have underscores replaced with spaces in the Ghidra plugin where they are used. 

**TaskID**: The task ID must be unique to each task and is a numeric identifier used in instrumentation to identify the current task in instrumentation event messages.  The task ID is not used for ordering the tasks.

[comment]: <> (The following structure follows an old task instruction format. This needs to be updated.)

An example JSON structure and fields are provided below. Note: Currently "salientDistractors", "problemSize", and "problemComplexity" are not implemented. You are able to include multiple inner lists with addresses in the "keyAddresses" field.

```
{
  "end": "",
  "name": "Point_of_Interest_Triage_1",
  "start": "4078f9",
  "autoSeek": "true",
  "surveytasks": "",
  "survey": "false",
  "taskID": 240,
  "trialID": "1",
  "instructions": "Point_of_Interest_Triage_1-instructions.txt",
  "program": "bryant.bin",
  "answerKey": "This is a buffer overflow and segmentation fault.",
  "keyAddresses": [["0x40797e", "Buffer Overflow Vulnerability"]],
  "salientDistractors": [],
  "problemSize": 120,
  "problemComplexity": 1000,
  "expectedResponse" : "high"
}
```

The fields currently used in our experimental configuration consist of the following: 

 - name: A unique name of the task that is used both in teh Ghidra interface and used to associate the CavaTaskSequence.txt and the -instruction.txt and -metadata.txt for each task. 
 - start: The starting address of the task.  Ghidra will seek to this address when the task starts. 
 - autoSeek: Whether or not Ghidra should set the location to the address 'start' (or beginning of the program if start is not specified).
 - end: The expected ending address for the task.  This address may in some cases be used as a criteria for success. 
 - surveytasks: A list of the taskIDs for each task that the survey covers (e.g. 20,21)
 - survey: A boolean flag on whether to present the intra-task survey after this task is complete.
 - taskID: A unique numeric identifier for this task.
 - trialID: A numeric sequence identifier if this task is repeated multiple times.  This is used to identify tasks which are repeated and the number of repetitions which have been performed. 
 - instructions: A reference to the task's instructions file.  File name should be the same as the task name but with -instructions.txt at the end.
 - program: The name of the program binary for this task (e.g. bryant.bin).  Ghidra will switch to this program at the start of the task. 
 - answerKey: A statement of the solution for a POI or POV task which clearly states why the program is defective.  This information might optionally be provided to a subject after completing a POI or POV task. 
 - keyAddresses: A 2-d list of addresses that are implicated in the vulnerability. The first entry is the address and the second is a short description which is included in log messages when the "cavaPerformanceMetrics.java" program is run. This array is empty if the task is a false positive.


## Running the Task Sequence in Ghidra

To use the task sequence the CAVA Listener plugin reads in the cava-tasks/cava-task-sequence.txt and then loads the tasks and instructions as specified in this folder.  Tasks not listed in the cava-task-sequence.txt file are ignored.  The tasks are presented in the order given in the file.  If it is desired to randomized the sequence for each subject this file must be randomized.  

> Note: Ghidra must be restarted after modification of the the task instructions, metadata, or sequence in order to load the new sequence data into the application. 


## Proposed future updates: 

 - We are considering addding additional metadata to be used for assessing real-tie performance.  For example, a set of addresses and associated reward values could be stored which woudl enable a distance metric (either in straight-line assembly or via Function Graph traversal) to be used as a measure of how 'close' a subject is to a solution or discovery of a vulnerability. 

The following fields are planned, but not yet implemented
  - salientDistractors: A set of addresses of other instructions that are relevant to various types and classes of vulnerability, but are not vulnerable.  This is expected to be useful in identifying performance when a subject is performing analysis of a false-positive POI or is performing analysis of regions of a  program of a true positive POI that are not salient to the vulnerabilty but are salient to program defects or vulnerabilities in general. 
 - problemSize: An estimate of the problem size as measured by the total lines of assembly at a depth of 1 function call from the POI.
 - problemComplexity: An estimate of the problem complexity as measured by the product of the number of parameters, function calls, and values within a depth of 1 function call from the POI. 


