
IFS="
"

if [ "$1" = "-f" ];
then
    rm -Rf cava-data/cava-run*
    echo "All data under cava-data has been deleted"
else
    echo "This script will delete all cava-run data under cava-data"
    echo "This includes all of the following data"
    echo "---------------------------------------------------------"
    for dir in `ls -1 cava-data | egrep "cava-run"`
    do
        echo $dir
        ls -al cava-data/$dir
    done
    echo "---------------------------------------------------------"
    echo " To confirm, and force deltion, use: ./delete-all-cava-data.sh -f"
fi

