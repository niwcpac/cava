# CAVA Analysis Scripts

This directory holds scripts and tools that are meant to help with analysis of data collected during the cava experiment.

## `GetTypedStrings.py`

This tool takes a km_data.json file and then outputs typed strings the script was able to detect from the file.

### Prerequisites

If on the `cava-analysis` box, then do the following:

1. Open a terminal.
2. Change current directory to CavaAnalysisTools: `cd /home/vagrant/Desktop/CavaAnalysisTools`
3. Use tools, run `python3 GetTypedStrings.py -h` to get more help.

If you want to run the script locally (on your machine!), there's an included conda environment file. 
To get the environment loaded, you first need to run the following command:

`conda env create -f \path\to\environment.yaml`

After doing that you need to run `conda activate cava-analysis` to run the python virtual environment.

If you have a python3 version that is greater than 3.7.3 installed locally, then that should also work for this script.

### How to Use

Here's an example of using the program on a km_data.json file:

`python3 ./GetTypedStrings.py -i km_data.json -o output_file.json`

And here is what the file `output_file.json` might look like:

```
{"TypingEvent": {"String": "i understandfollow instructions", "InitialTimestamp": 1648488797.8431785, "EndingTimestamp": 1648488630.8994203}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488656.6359913, "EndingTimestamp": 1648488656.7558894}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488658.783738, "EndingTimestamp": 1648488658.9309127}}
{"TypingEvent": {"String": "address", "InitialTimestamp": 1648488733.1090412, "EndingTimestamp": 1648488734.1424477}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488741.586327, "EndingTimestamp": 1648488742.530803}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488744.786275, "EndingTimestamp": 1648488744.9142642}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488755.1544695, "EndingTimestamp": 1648488755.2498724}}
{"TypingEvent": {"String": "address", "InitialTimestamp": 1648488773.8740735, "EndingTimestamp": 1648488774.5632117}}
{"TypingEvent": {"String": "g", "InitialTimestamp": 1648488993.5356717, "EndingTimestamp": 1648488993.8245442}}
{"TypingEvent": {"String": "0x10cd", "InitialTimestamp": 1648489004.291306, "EndingTimestamp": 1648489006.120608}}
{"TypingEvent": {"String": "90f", "InitialTimestamp": 1648489007.8568728, "EndingTimestamp": 1648488829.3116348}}
{"TypingEvent": {"String": "inished", "InitialTimestamp": 1648488830.4617932, "EndingTimestamp": 1648488831.2466774}}
{"TypingEvent": {"String": "0x", "InitialTimestamp": 1648488855.9551659, "EndingTimestamp": 1648488856.1786005}}
{"TypingEvent": {"String": "0x", "InitialTimestamp": 1648488857.2287982, "EndingTimestamp": 1648488857.7311218}}
{"TypingEvent": {"String": "finished", "InitialTimestamp": 1648488867.4589658, "EndingTimestamp": 1648488868.3382926}}
{"TypingEvent": {"String": "finished", "InitialTimestamp": 1648488913.0293858, "EndingTimestamp": 1648488914.1179144}}
...
```

### Output file structure

The resulting output file from the script has the following structure:

`{"TypingEvent:"{"String": "KEY_H KEY_I KEY_SPACE KEY_W KEY_O KEY_R KEY_L KEY_D", "InitialTimestamp":0000000001.00000, "EndingTimestamp":000000002.00000}}`

**TypingEvent** : Name of the JSON Object 

**String** : String representation of the keystrokes that were used 

**InitialTimestamp** : The timestamp of the first keystroke 

**EndingTimestamp** : The timestamp of the last keystroke

## `PrepFileForPerformanceMetrics.py`

The purpose of this script is to turn lsl_data.json files into an intermediate form of distance metrics in order for GetPerformanceMetrics.java to work as intended. 

### Prerequisites

If on the `cava-analysis` box then do the following:

1. Open a terminal.
2. Change current directory to CavaAnalysisTools: `cd /home/vagrant/Desktop/CavaAnalysisTools`
3. Use tools, run `python3 PrepFileForPerformanceMetrics.py -h` to get more help.

If you want to run the script locally (on your machine!), there's an included conda environment file. 
To get the environment loaded you first need to run the following command:

`conda env create -f \path\to\environment.yaml`

After doing that you need to run `conda activate cava-analysis` to run the python virtual environment.

If you have a python3 version that is greater than 3.7.3 installed locally, then that should also work for this script.

> **Note**: These are the same instructions as the above script!

### How to Use

Here's an example of using the program on a lsl_data.json file:

`python3 ./PrepFileForPerformanceMetrics.py -i lsl_data.json -o distances.json`

And here is what the file `distances.json` might look like:

```
{"start": "004078e8", "program": "bryant.bin", "end": [["0x40797e", "Buffer Overflow Vulnerability"]], "timestamp": 1648492288.218689, "task": 250}
{"start": "004078e8", "program": "bryant.bin", "end": [["0x40797e", "Buffer Overflow Vulnerability"]], "timestamp": 1648492542.13323, "task": 250}
{"start": "004078e8", "program": "bryant.bin", "end": [["0x40797e", "Buffer Overflow Vulnerability"]], "timestamp": 1648492432.188552, "task": 250}
{"start": "004078e8", "program": "bryant.bin", "end": [["0x40797e", "Buffer Overflow Vulnerability"]], "timestamp": 1648492438.622614, "task": 250}
{"start": "00402444", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648492562.629564, "task": 260}
{"start": "00402484", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648492573.91524, "task": 260}
{"start": "00402477", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648493144.946569, "task": 270}
{"start": "00402477", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648493155.123294, "task": 270}
{"start": "00402477", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648493283.037241, "task": 270}
{"start": "00402477", "program": "bryant.bin", "end": [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]], "timestamp": 1648493313.536636, "task": 270}
{"start": "0040778b", "program": "bryant.bin", "end": [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]], "timestamp": 1648493419.126591, "task": 300}
{"start": "0040778b", "program": "bryant.bin", "end": [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]], "timestamp": 1648493421.918514, "task": 300}
{"start": "00407878", "program": "bryant.bin", "end": [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]], "timestamp": 1648493452.735366, "task": 300}
{"start": "004077ed", "program": "bryant.bin", "end": [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]], "timestamp": 1648493459.706238, "task": 300}
{"start": "0040778b", "program": "bryant.bin", "end": [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]], "timestamp": 1648493472.120854, "task": 300}
```

**start**: Address that was interacted with by the subject

**end**: List of addresses of interest with each entry being the address and descriptor

**TaskID**: TaskID of the task that was being done

**Timestamp**: Timestamp

Something to note: this script's intention was for our own internal usage, so it provides little utility in any other context. Since the instrumentation already takes care of the problem of running performance metrics during the experiment, this script, along with `ghidra_scripts/CavaAnalysisTools/GetPerformanceMetrics.java`, seems redundant. With slight modifications to both of the prior scripts, one would be able to calculate distances between **any** two addresses using **any** binary. For example, one might be interested in determining how far a subject was from the correct address while they were focused on some other field on-screen. Using the json format above in conjuction with `GetPerformanceMetrics.java`, it can be done.

