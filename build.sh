#!/bin/bash

PLUGINLIST="CavaListener CavaDecompile CavaCodeBrowser CavaFunctionGraph"
RELEASE_LIST="cava-platform/bootstrap/ghidra/extensions/ghidra_extension_release.txt"
RELEASE_METADATA="cava-platform/release-metadata"
INSTALL_DIR="cava-platform/bootstrap/ghidra/extensions/"
BOOTSTRAP="cava-platform/bootstrap"
BUILD_COMMIT_FILE="metadata-build-commit"
INSTALL_COMMIT_FILE="metadata-install-commit"

ACTION="$1"

usage () {
    echo "Usage: ./build.sh <clean|build(default)|test|install|release>"
}

if [ ! -f "/etc/debian_version" -o ! -d "/vagrant/cava-platform" ]; then
    echo "!!! Script is intended for use within the cava-core Vagrant environment"
    echo "    For example: vagrant up; vagrant ssh; cd /vagrant/; ./build.sh"
    usage
    exit
fi


if [ "$ACTION" == "clean" ]; then
    echo "Removing built CAVA plugins"

    for plugin in $PLUGINLIST; do

        echo "  Cleaning $plugin build directory"
        REMOVING=$(ls -1 eclipse-workspace/$plugin/dist/*.zip 2>/dev/null)
        if [ -n "$REMOVING" ]; then
            echo "    Removing: $REMOVING"
        fi
        rm eclipse-workspace/$plugin/dist/*.zip &>/dev/null

    done
    
    echo "---------------------------------------------------"
    echo "  Cleaning all installed plugins from cava-platform"
    REMOVING=$(ls -1 $INSTALL_DIR/*.zip 2>/dev/null)
    if [ -n "$REMOVING" ]; then
        echo "    Removing: $REMOVING"
        rm $INSTALL_DIR/*.zip &>/dev/null
    fi
    if [ -f "$RELEASE_LIST" ]; then
        echo "    Removing $RELEASE_LIST"
        rm $RELEASE_LIST &>/dev/null
    fi

    echo "---------------------------------------------------"
    echo "  Removing release metadata file, if present"
    if [ -f "$RELEASE_METADATA" ]; then
        echo "    Removing $RELEASE_METADATA"
        rm $RELEASE_METADATA
    fi

    echo "---------------------------------------------------"
    echo "  Removing install commit metadata file, if present"
    if [ -f "$INSTALL_COMMIT_FILE" ]; then
        echo "    Removing $INSTALL_COMMIT_FILE"
        rm $INSTALL_COMMIT_FILE
    fi

    echo "---------------------------------------------------"
    echo "  Removing build commit metadata file, if present"
    if [ -f "$BUILD_COMMIT_FILE" ]; then
        echo "    Removing $BUILD_COMMIT_FILE"
        rm $BUILD_COMMIT_FILE
    fi

    exit
fi


if [ "$ACTION" == "test" ]; then
    echo "Testing built plugin components"
    echo "No tests implemented yet. Listing most recent build artifacts for verification"

    for plugin in $PLUGINLIST; do
        echo "----------------------------------------------"
        echo "$plugin:"
        ls -1 eclipse-workspace/$plugin/dist/ | tail -n 1
    done
    
    echo "----------------------------------------------"
    echo "----------------------------------------------"
    echo "Checking whether plugins are installed in cava-platform"
    ls -1 $INSTALL_DIR

    exit
fi



if [ "$ACTION" == "install" ]; then
    if [ -f $RELEASE_LIST ]; then rm $RELEASE_LIST; fi

    if [ ! -f $BUILD_COMMIT_FILE ]; then
        echo "!!! Build commit metadata file not found.  Please run ./build first... exiting"
        exit
    fi

    #Remove old install commit info
    if [ -f $INSTALL_COMMIT_FILE ]; then
        rm $INSTALL_COMMIT_FILE;
    fi

    INSTALL_COMMIT=$(git log -1 --format="%H%x09%ad")

    echo "Deleting older plugins in $INSTALL_DIR"
    rm $INSTALL_DIR/*.zip 2>/dev/null

    echo "Installing the most recently built plugins into the cava-platform Vagrant environment"
    for plugin in $PLUGINLIST; do
        zipfile=`ls -1 eclipse-workspace/$plugin/dist/*.zip 2>/dev/null | tail -n 1`
        if [ -z "$zipfile" ]; then 
            echo "!!! Plugin [$plugin] does not appear to be built yet." 
            echo "    Please run './build.sh' to build Cava plugins."
            exit
        fi
        echo $zipfile | awk -F\/ '{print $NF}' >> $RELEASE_LIST
        cp $zipfile $INSTALL_DIR
    done 
    echo "Release contains the following plugins:"
    cat $RELEASE_LIST
    
    echo "$INSTALL_COMMIT" > $INSTALL_COMMIT_FILE
    echo "-------------------------------------------"
    echo "       Finished Plugin Installation        "
    echo "INSTALL COMMIT:"
    cat $INSTALL_COMMIT_FILE
    exit
fi

if [ "$ACTION" == "release" ]; then
    if [ ! -f "$BUILD_COMMIT_FILE" ]; then
        echo "!!! Build commit info not found."
        echo "    Plesea run './build.sh build' to build the Cava plugins"
        exit
    fi
    if [ ! -f "$INSTALL_COMMIT_FILE" ]; then
        echo "!!! Install commit info not found."
        echo "    Please run './build.sh install' to install Cava plugins to the platform"
        exit
    fi

    #Remove old release info
    if [ -f $RELEASE_METADATA ]; then
        rm $RELEASE_METADATA
    fi

    RELEASE_COMMIT=$(git log -1 --format="%H%x09%ad")
    RELEASE_DATE="$(date +"%Y.%m.%d")"

    PLUGIN_INFO=$(cat $RELEASE_LIST)
    INSTALL_INFO=$(cat $INSTALL_COMMIT_FILE)
    BUILD_INFO=$(cat $BUILD_COMMIT_FILE)

cat << EOF > $RELEASE_METADATA
-------- CAVA Platform Release Information --------
RELEASE DATE:   $RELEASE_DATE

RELEASE COMMIT: $RELEASE_COMMIT

INSTALL COMMIT: $INSTALL_INFO

BUILD COMMIT:   $BUILD_INFO

GHIDRA PLUGINS INCLUDED:

$PLUGIN_INFO
EOF

    echo "-------------------------------------------------"
    echo "$RELEASE_METADATA:"
    cat $RELEASE_METADATA
    echo "-------------------------------------------------"
    exit
fi


#Allow no options to trigger default build action
if [ "$ACTION" == "build" -o -z "$ACTION" ]; then
    #Remove old build-commit metadata
    if [ -f "$BUILD_COMMIT_FILE" ]; then
        rm $BUILD_COMMIT_FILE
    fi

    echo "Plugin List: $PLUGINLIST"
    DIR=`pwd`

    echo "----------------------------------------------"
    echo "----------------------------------------------"

    for plugin in $PLUGINLIST; do
       echo "Building $plugin" 
       echo "----------------------------------------------"
       cd $DIR/eclipse-workspace/$plugin
       gradle 
       if [ $? -eq 0 ]; then
           SUCCESS="$SUCCESS $plugin"
       else
           FAILURE="$FAILURE $plugin"
       fi
       
       echo "-------------- Finished $plugin --------------"
       echo "----------------------------------------------"
    done

    cd $DIR
    echo "----------- Build Summary ---------------"
    echo "Successful builds: [$SUCCESS]"
    echo "Failed builds: [$FAILURE]"
    if [ -n "$FAILURE" ]; then
        echo "!!! One or more plugins failed to build."  
        echo "    Build commit info is not being created"
        echo "    ./build install will refused to run if attempted"
    else
        BUILD_COMMIT=$(git log -1 --format="%H%x09%ad")
        echo "$BUILD_COMMIT" > $BUILD_COMMIT_FILE

        echo "-------------------------------------------"
        echo "         Finished Plugin Builds            "
        echo "BUILD COMMIT: "
        cat $BUILD_COMMIT_FILE
    fi

    exit
fi


#Fail out if a different option than the above is provided
if [ -n "$1"  ]; then
    echo "Usage: ./build.sh <clean|build|install|test>" 
    exit
fi


echo "Invalid build action: $ACTION"
usage


