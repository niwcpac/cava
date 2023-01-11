#!/bin/bash

# This script creates a tarball release of the Cava platform, checking 
# that build and install info is known and bails out if either are missing.
#
# This script may also be run to generate the release-metadata file 
# as may be needed for testing the platform without creating the release tarball.
# 
# Usage: ./package-cava-platform.sh <test(optional)>"
#

TEST="$1"

if [ "$TEST" == "test" ]; then 
    echo "Testing... will create release metadata.  Release tarball will not be created" 
fi


# The .vagrant cache folder is excluded from the release. 
VAGRANT_DIR="cava-platform/.vagrant"

BUILD_COMMIT=$(cat metadata-build-commit)
INSTALL_COMMIT=$(cat metadata-install-commit)

#Check that we have build commit info
if [ ! -f metadata-build-commit ]; then
    echo "!!! Build commit info not found in metadata-build-comit"
    echo "    Plugins for the Cava Platform must be built first (e.g. ./build)"
    echo "    Exiting"
    exit
fi

#Check that we have build install commit info
if [ ! -f metadata-install-commit ]; then
    echo "!!! Install commit info not found in metadata-install-commit"
    echo "    Plugins for the Cava Platform must be installed before packaging for release (e.g. ./build install)"
    echo "    Exiting"
    exit
fi


#Generate Release Metadata
./build release

if [ "$TEST" == "test" ]; then 
   echo "Skipping release tarfile creation... "
   echo "If desired, please run ./package-cava-platform.sh directly to package for release" 
   exit 
fi


RELEASE_DATE="$(date +"%Y.%m.%d")"

RELEASE="cava-platform-$RELEASE_DATE.tgz"
echo "Creating release tarball: $RELEASE"
tar --exclude="$VAGRANT_DIR" -czvf $RELEASE cava-platform

echo "--------------------------------------"
echo "Release tarball created: ./$RELEASE"
