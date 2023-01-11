# CAVA Analysis Ghidra Scripts

These ghidra scripts are meant to be used on data that was collected from a CAVA experiment. Two of these scripts use the ghidra project files that are collected, using these project files we are able to extract more information from the data such as conclusive evidence that a subject made a comment or performed a relabel. 

These scripts are crucial since we are unable to extract reliably that information with the current level of instrumentation.

## Prerequisites

In order to use these scripts, one needs to open the `cava-analysis` box. This box can be constructed by running `vagrant up cava-analysis` under the host machine path `path/to/cava-core/cava-platform/`. Wait for the box to provision and the ghidra scripts will put at `/home/vagrant/ghidra-scripts`. Once you verify that the scripts are there, open Ghidra. 

Once in Ghidra, open the script manager plugin and the scripts will be available under `CAVA_ANALYSIS`.

Before we can start running the scripts, we need to load the subject ghidra project that is collected at the end of an experiment. It has the following form, `sub_DAY-MONTH-YEAR-TIME.gpr`. We also need the folder `sub_DAY_MONTH-YEAR-TIME.rep` to be in the same directory. These should be located under `cava-data`.

We **strongly** recommend that one either makes copies of these projects or make them read-only in order to avoid tainting subject data.

## `GetAllComments.java`

### Usage

Open the script manager while in Ghidra, and run the script `GetAllComments.java` under `CAVA_ANALYSIS`.

Once you run the script, it will ask for a unix timestamp. Since Ghidra's analysis of the binary creates comments, we need a way to filter these comments apart from subject comments. One can use the initial timestamp in the `lsl_data.json` to act as this filter. After that, choose a directory to output the comments file.

A comments file will have a similar output to this,

```
{"CavaCommentEvent":{"Comment":"I just made a plate comment!","Timestamp":1666913119,"Address":"00400e40"}}
{"CavaCommentEvent":{"Comment":"Comments are really cool!!","Timestamp":1666913151,"Address":"004010a0"}}
{"CavaCommentEvent":{"Comment":"Okay... thats enough comments.","Timestamp":1666913171,"Address":"004083b1"}}
```

## `GetAllLabels.java`

Open the script manager while in Ghidra, and run the script `GetAllLabels.java` under `CAVA_ANALYSIS`.

Once you run the script, it will ask for a unix timestamp. Since Ghidra's analysis of the binary creates labels, we need a way to filter these labels apart from subject labels. One can use the initial timestamp in the `lsl_data.json` to act as this filter. After that, choose a directory to output the labels file.

A label file will have the following form,

```
{"LabelEvent":{"OriginalLabel":"local_EAX","NewLabel":"Renamed_iVar1","Address":"00000090","Timestamp":1666913274}}
{"LabelEvent":{"OriginalLabel":"Renamed_iVar1","NewLabel":"renamed_iVar1","Address":"00000090","Timestamp":1666913286}}
{"LabelEvent":{"OriginalLabel":"renamed_iVar1","NewLabel":"iVar1_cool","Address":"00000090","Timestamp":1666913305}}
{"LabelEvent":{"OriginalLabel":"iVar1_cool","NewLabel":"iVar1Renamed","Address":"00000090","Timestamp":1666913318}}
{"LabelEvent":{"OriginalLabel":"entry","NewLabel":"entry_but_better","Address":"00000016","Timestamp":1666913405}}
{"LabelEvent":{"OriginalLabel":"local_RAX_574","NewLabel":"pdVar7_but_better","Address":"00000091","Timestamp":1666913427}}
{"LabelEvent":{"OriginalLabel":"local_RAX_338","NewLabel":"ptVar2_renamed?","Address":"00000091","Timestamp":1666913438}}
```

### Original labels are not 100% correct 

Theres is a glaring problem with the output above, an acute observer will have noticed that the first label has no "initial label". In Ghidra, the field was originally labeled "iVar1", then we renamed it to "Renamed_iVar1", but the labels script outputs that the original label was "local_EAX". But in other instances, this doesn't happen. Refer to the label "entry" above to make sure. This is a problem. 

This is most likely due to how Ghidra decompiles binaries and how it chooses to label things initially. We currently do not have fix for this. 

Theres many ways around this issue. Here are a few,
1. Relabel variables in your binary to something else initally, then have the subject modify that Ghidra project.
2. Cross reference the lsl_data.json file to figure out what field was interacted with.
3. Check screen-recording of the subject.

## `GetPerformanceMetrics.java`

> **Note**: For this script to work, one doesn't have to use the subjects project data. One can use the experiment binary.

This script was mostly developed for internal usage since it's format depends on the experiment task. But, with slight modifications to this script, one should be able to calculate distance metrics between any two addresses on any binary. 

Before you run the script, one first needs to run `PrepFileForPerformanceMetrics.py` under `/home/vagrant/Desktop/CavaAnalysisTools/`. The output of that script should then be used on this script.

Running this script is no different from the others. First, open the script manager and run `GetPerformanceMetrics.java`, then choose the output file from the python script mentioned above.

The results should look like the following,

```
{"CavaPerformanceMetric":{"ClickedAddress":"004078f9","KeyAddress":"0040797e","AssemblyDistance":18,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648491591.407045","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":240}}
{"CavaPerformanceMetric":{"ClickedAddress":"00407988","KeyAddress":"0040797e","AssemblyDistance":2,"BlockDistance":0,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648491609.966339","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":240}}
{"CavaPerformanceMetric":{"ClickedAddress":"004079b4","KeyAddress":"0040797e","AssemblyDistance":9,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648491804.324985","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":240}}
{"CavaPerformanceMetric":{"ClickedAddress":"004079a1","KeyAddress":"0040797e","AssemblyDistance":6,"BlockDistance":0,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648491807.056435","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":240}}
{"CavaPerformanceMetric":{"ClickedAddress":"00407911","KeyAddress":"0040797e","AssemblyDistance":-1,"BlockDistance":-1,"FunctionDistance":-1,"Info":"NOT CONNECTED","Timestamp":"1648491929.212004","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078f9","KeyAddress":"0040797e","AssemblyDistance":18,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648491936.921586","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004076ad","KeyAddress":"0040797e","AssemblyDistance":114,"BlockDistance":11,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492064.562583","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004076ad","KeyAddress":"0040797e","AssemblyDistance":114,"BlockDistance":11,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492066.629224","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004076e8","KeyAddress":"0040797e","AssemblyDistance":107,"BlockDistance":10,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492073.237808","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"00407737","KeyAddress":"0040797e","AssemblyDistance":109,"BlockDistance":10,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492092.633451","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004077eb","KeyAddress":"0040797e","AssemblyDistance":73,"BlockDistance":2,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492044.950713","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004077eb","KeyAddress":"0040797e","AssemblyDistance":73,"BlockDistance":2,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492068.389848","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004077eb","KeyAddress":"0040797e","AssemblyDistance":73,"BlockDistance":2,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492130.436965","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"0040792c","KeyAddress":"0040797e","AssemblyDistance":15,"BlockDistance":0,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492382.912745","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492257.793011","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"0060c0a0","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":2,"Info":"FOUND","Timestamp":"1648492263.551769","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492270.231124","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492288.218689","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492542.13323","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492432.188552","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"004078e8","KeyAddress":"0040797e","AssemblyDistance":23,"BlockDistance":1,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492438.622614","keyAddressInfo":"Buffer Overflow Vulnerability","TaskID":250}}
{"CavaPerformanceMetric":{"ClickedAddress":"00402444","KeyAddress":"00402477","AssemblyDistance":14,"BlockDistance":0,"FunctionDistance":0,"Info":"FOUND","Timestamp":"1648492562.629564","keyAddressInfo":"Null Pointer Dereference","TaskID":260}}
```

**ClickedAddress**: Address that was interacted with by the subject

**KeyAddress**: Address of Interest, could be a vulnerability or a salient distractor

**AssemblyDistance**: Number of assembly instructions away from the key address

**BlockDistance**: Number of code blocks (blocks in the function graph) away from the key address

**FunctionDistance**: Number of function calls away from key address.

**Info**: Internal Cava performance metadata,
	NOT_FOUND = wasn’t able to find the key address starting from clicked address. Usually means that the subject is really far away
	NOT_CONNECTED = means that the clicked address is not in the same control flow as the keyAddress. Subject is probably looking at the wrong area.
	FOUND = :)

**keyAddressInfo**: Additional information about the keyaddress. It's either a vul. or a salient distractor.

**TaskID**: TaskID of the task that was being done.

**Timestamp**: timestamp
