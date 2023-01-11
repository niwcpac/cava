#!/bin/bash
source /tmp/provision-check.sh 

if [ -z "$GHIDRA_HOME" ]; then GHIDRA_HOME="/opt/ghidra"; fi

# ---------------------------------------------------------------------------------------
# Install CAVA Extensions (see: https://ghidra-sre.org/InstallationGuide.html#Extensions)
echo "-----------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo ">>>>> Installing CAVA Ghidra Extensions to $GHIDRA_HOME/Ghidra/Extensions" | tee -a $PROVISION_LOG
echo ">>>>> To update installed extensions, edit ghidra_extension_release.txt" | tee -a $PROVISION_LOG


cd $GHIDRA_HOME/Ghidra/Extensions
pwd | tee -a $PROVISION_LOG
for file in `cat $BOOTSTRAP/ghidra/extensions/ghidra_extension_release.txt`; do
    echo "Installing: $file" | tee -a $PROVISION_LOG
    unzip -o $BOOTSTRAP/ghidra/extensions/$file >> $PROVISION_LOG
done

