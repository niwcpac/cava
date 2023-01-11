#!/bin/bash

source /tmp/provision-check.sh 

echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
echo "Creating Desktop build file" | tee -a $PROVISION_LOG

DESKTOP="/home/vagrant/Desktop"
RELEASE_METADATA_FILE="/vagrant/release-metadata"

if [ ! -f "$RELEASE_METADATA_FILE" ]; then
    echo "release-metadata not found, skipping creation of desktop build-info file"
    exit
fi

RELEASE_DATE=$(cat $RELEASE_METADATA_FILE | grep "RELEASE DATE:" | sed -r 's/^.*([0-9]{4}.[0-9]{2}.[0-9]{2}).*$/\1/')

if [ -z "$RELEASE_DATE" ]; then RELEASE_DATE="unknown"; fi

echo "Release Date: $RELEASE_DATE"
echo "Release Metadata:"
cat $RELEASE_METADATA_FILE | tee -a $PROVISION_LOG

BUILD_INFO_FILE="$DESKTOP/build_info_$RELEASE_DATE"

cat $RELEASE_METADATA_FILE > $BUILD_INFO_FILE

cp $BUILD_INFO_FILE /opt/cava-log/

echo "Done" | tee -a $PROVISION_LOG
echo "-------------------------------------------------------------------------------" | tee -a $PROVISION_LOG
