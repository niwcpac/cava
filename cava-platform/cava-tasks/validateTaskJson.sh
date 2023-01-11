#!/bin/bash

GREEN=$'\e[0;32m'
RED=$'\e[0;31m'
NC=$'\e[0m'



usage(){
	echo "Usage: validateTaskJson.sh [-c] [-h] "
	echo -e "\t-c to check proper Task.json format"
}



checkFileFormat(){

    errorFiles=()
    validFiles=0
    uniqueName=()

    echo "Checking proper format for files in $PWD"

    # Change to be the task directory. This assumes if you are working in the parent directory that contins the task json files
    array=(`find . -maxdepth 1 -name '*.json' | sort`)

    echo "Found ${#array[@]} metadata.json files"

    for i in "${!array[@]}"; #looping using indices aka 0,1,2,3 etc...
    do
        errorCheck=0
        lineNumber=1
        output=()
        if [ -f ${array[$i]} ] # check if its a file
        then

            while IFS= read -r line;
            do
                if [[ $line == { ]] || [[ $line == } ]]
                then
                    output+=("line($lineNumber) ${GREEN}$line${NC}")
                elif [[ $line =~ \"(.*)\":[[:space:]](\[(.*)\]|(\"(.*)\")|[[:digit:]]+),*$ ]] 
                then
                    if [[ $line =~ "\"name\":" ]]
                    then
                        old_name=$(perl -ne 'if (/"name": "(.*)"/) { print $1 . "\n" }' <<< $line)
                        if [[ "${uniqueName[*]}" =~ "${old_name}" ]]; 
                        then 
                            line=${RED}$line${NC}
                            new_name="Duplicared Name: -> $old_name"
                            ((errorCheck++))

                        else
                            line=${GREEN}$line${NC}
                            uniqueName+=($old_name)
                            new_name=$old_name
                        fi
                        line=$(sed "s/$old_name/$new_name/" <<< $line)
                        output+=("line($lineNumber) $line")
                    else
                        output+=("line($lineNumber) ${GREEN}$line${NC}")
                    fi
                # "program": "douglas.bin"
                else
                    if [[ $line =~ ^[[:space:]]? ]]
                    then
                        output+=("line($lineNumber) ${RED}$line <-- Line contains an empty space${NC}")
                    else
                        output+=("line($lineNumber) ${RED}$line <-- has an error: -> $line${NC}")
                    fi
                    ((errorCheck++))
                fi
                ((lineNumber++))

            done < ${array[$i]}

            if [ $errorCheck -ne 0 ];
            then
                echo -e "\n[$((i+1))] ${array[$i]} ${RED}FAILED${NC}"
                errorFiles+=(${array[$i]})
                echo "${RED}Found $errorCheck lines${NC} that contains error. Please reference the errors below."
                printf '%s\n' "${output[@]}"
                echo
            else
                echo -e "\n[$((i+1))] ${array[$i]} ${GREEN}PASSED${NC}"
                ((validFiles++))
            fi


        else
            echo -e "\t[$((i+1))] lol this is not a json file: ${array[$i]} "
        fi
    done

    echo '-------------------------------------------------------------------'
    echo -e "\t\t\tVALIDATION RESULT"
    echo "PASSED: ${GREEN}$validFiles/${#array[@]}${NC}"
    echo "FAILED: ${RED}${#errorFiles[@]}${NC}"
    
    if [ ${#errorFiles[@]} -ne 0 ];
    then
        echo 
        echo "Found ${#errorFiles[@]} files that contain errors:"

        # difference between $@ and $*:
        # Unquoted, the results are unspecified. In Bash, both expand to separate args and then wordsplit and globbed.
        # Quoted, "$@" expands each element as a separate argument, while "$*" expands to the args merged into one argument: "$1c$2c..." (where c is the first char of IFS).
        # You almost always want "$@". Same goes for "${arr[@]}".
        # Always quote them!
        printf '\t%s\n' "${RED}${errorFiles[@]}${NC}"
    else
        echo "All passsed json format"
    fi
    echo '-------------------------------------------------------------------'
}   


# prepend ; to do silent mode
while getopts ":c" opt; do
	case ${opt} in
		c)	checkFileFormat ;;
		\?)	usage
			exit;;
		*) usage ;;
	esac
done

# check arguments/print usage
if [ $# -eq 0 ]
then
	checkFileFormat
fi

