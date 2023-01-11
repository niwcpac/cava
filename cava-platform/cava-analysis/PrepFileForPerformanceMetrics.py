"""
@author Froylan Maldonado

The purpose of this script is to take a lsl_data.json file, and convert certain internal instrumentation events
to a format that CavaPerformanceMetrics ghidra script can use.
"""

import json
import argparse

"""
Since we currently don't have ways to convert a json event to an address, we have to use the GhidraLocationEvent to 
calculate performance metrics. The other events don't have a way for us to extract a byte Address without constructing
additional Ghidra Scripts. 
"""
def main():
    parser = argparse.ArgumentParser(description="Generate input file for GetPerformanceMetrics Ghidra Script.")
    parser.add_argument("-i", "--inputfile", type=str, default='lsl_data.json',
                        help="path to lsl data (Default: lsl_data.json)")
    parser.add_argument("-o", "--outputfile", type=str, default='starting_points.txt',
                        help="Output file name for starting points to be calculated (Default: starting_points.txt)")
    args = parser.parse_args()

    # Setting variables
    inputfile = args.inputfile
    outputfile = args.outputfile

    # Datafile is a list of json objects loaded from inputfile
    json_distances = []
    lsl_file = open(inputfile, 'r')

    while True:

        line = lsl_file.readline()

        if line is None or line is "":
            break

        event = json.loads(line)

        ghidra_location_event_data = event.get("GhidraLocationChangedEvent")

        if ghidra_location_event_data is None:
            continue

        # This gets the endAddresses we need to calculate a performanceMetric for.
        end_addresses = taskID_to_end_addresses.get(ghidra_location_event_data.get("TaskID"))

        # If the taskID doesn't have an endAddress list associated with it, then that means it occurred outside the
        # POV/POI task.
        if end_addresses is None:
            continue

        distance = {
            "start": ghidra_location_event_data.get("ByteAddress"),
            "end": taskID_to_end_addresses.get(ghidra_location_event_data.get("TaskID")),
            "program": ghidra_location_event_data.get("ProgramName"),
            "task": ghidra_location_event_data.get("TaskID"),
            "timestamp": ghidra_location_event_data.get("Timestamp")
        }

        json_distances.append(distance)

    lsl_file.close()
    metrics_to_get = open(outputfile, 'w')

    for distance in json_distances:
        metrics_to_get.writelines(json.dumps(distance) + "\n")

    metrics_to_get.close()

# This was constructed based off the cava-tasks json files.
taskID_to_end_addresses = {
    250: [["0x40797e", "Buffer Overflow Vulnerability"]],
    270: [["0x402477", "Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]],
    290: None,
    310: [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]],
    330: [["0x401480", "Distractor: potential memory corruption, generally interesting."]],
    350: [["0x4045ea", "Distractor: yyrealloc, possible memory mistakes."]],
    240: [["0x40797e", "Buffer Overflow Vulnerability"]],
    260: [["0x402477","Null Pointer Dereference"], ["0x402408", "Distractor: The 'secret' string and surrounding callocs."]],
    280: None,
    300: [["0x4077eb", "SQL Injection"], ["0x403450", "Distractor: The 'execute_plan' function is related to SQL injection"], ["0x402170", "Distractor: The 'parse_query' function is related to SQL injection"]],
    320: [["0x401480", "Distractor: potential memory corruption, generally interesting."]],
    340: [["0x4045ea", "Distractor: yyrealloc, possible memory mistakes."]]
}

if __name__ == "__main__":
    main()
