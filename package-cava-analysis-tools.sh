#!/bin/bash

GHIDRA_SCRIPTS_DIR="/vagrant/eclipse-workspace/GhidraScripts"
BOOTSTRAP="/vagrant/cava-platform/bootstrap"
ARCHIVE_DATE="$(date +"%Y.%m.%d")"

usage() {
    echo "Usage: ./package-cava-analysis-tools.sh"
}

if [ ! -f "/etc/debian_version" -o ! -d "/vagrant/cava-platform" ]; then
    echo "!!! Script is intended for use within the cava-core Vagrant environment"
    echo "    For example: vagrant up; vagrant ssh; cd /vagrant/; ./package-cava-analysis-tools.sh"
    exit
fi

cd $GHIDRA_SCRIPTS_DIR

echo "Packing new cava analysis tools"
cp -r ./CavaAnalysisTools /tmp/ghidra_scripts
tar -czvf ./ghidra_scripts.tgz /tmp/ghidra_scripts

echo "Archiving old ghidra_scripts.tgz file to ghidra_scripts-$ARCHIVE_DATE"
mv $BOOTSTRAP/ghidra/ghidra_scripts.tgz $BOOTSTRAP/ghidra/archive/ghidra_scripts/"ghidra_scripts-$ARCHIVE_DATE"

echo "Moving new ghidra_scripts folder to $BOOTSTRAP/ghidra/"
mv ./ghidra_scripts.tgz $BOOTSTRAP/ghidra/

echo "Done"