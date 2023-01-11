#!/bin/bash
source /tmp/provision-check.sh

      
BASHRC="/home/vagrant/.bashrc"
CAVA_LIB="/vagrant/eclipse-workspace/CavaListener/lib/"

echo "-----------------------------------------------------------------------------------------------------"
echo ">>>> Updated debian package list"
# Update package list
apt-get -qq update

# Install python pre-requisites for scurve/binvis
#echo ">>>> Installing python pre-requisites"
#apt-get install -qq -y python python-pip python-cairo | tee -a $PROVISION_LOG > /dev/null
#pip install -q pillow | tee -a $PROVISION_LOG > /dev/null

echo ">>>> Installing dependencies for LSL (Lab Streaming Layer)"
# Install dependencies for LSL (Lab Streaming Layer)
# Build instructions: https://labstreaminglayer.readthedocs.io/dev/build.html
apt-get install -qq -y build-essential cmake qt5-default | tee -a $PROVISION_LOG > /dev/null

# Install AFL fuzzer -- unused
#apt-get install -qq -y afl > /dev/null

# Configure environment variables for Ghidra and JAVA
echo "-----------------------------------------------------------------------------------------------------"
echo ">>>> Checking that GHIDRA_INSTALL_DIR and JAVA_HOME environment variables are set in /home/vagrant/.bashrc"
if ! grep -q "GHIDRA_INSTALL_DIR" $BASHRC; then
    echo 'export GHIDRA_INSTALL_DIR="/home/vagrant/ghidra"' >> $BASHRC
fi
echo ">>>> GHIDRA_INSTALL_DIR is set to $GHIDRA_INSTALL_DIR"

if ! grep -q "JAVA_HOME" $BASHRC; then
    echo 'export JAVA_HOME="/opt/jdk"' >> $BASHRC
fi
echo ">>>> JAVA_HOME is set to $JAVA_HOME"


# Fetch required Java libraries for CAVA Ghidra Plugins
echo "-----------------------------------------------------------------------------------------------------"
echo ">>>> Fetching CAVA Plugin Java Libraries for Development" | tee -a $PROVISION_LOG
if [ ! -d $CAVA_LIB ]; then
    mkdir $CAVA_LIB
fi

cd /tmp/
if [ ! -f jgoodies-forms-1_8_0.zip ]; then
    wget -nv http://www.jgoodies.com/download/libraries/forms/jgoodies-forms-1_8_0.zip >> $PROVISION_LOG
fi
rm -Rf jgoodies-forms-1.8.0
unzip -o jgoodies-forms-1_8_0.zip > /dev/null
cp /tmp/jgoodies-forms-1.8.0/jgoodies-forms-*.jar $CAVA_LIB

cd /tmp/
if [ ! -f jgoodies-common-1_8_1.zip ]; then
    wget -nv http://www.jgoodies.com/download/libraries/common/jgoodies-common-1_8_1.zip >> $PROVISION_LOG
fi
rm -Rf jgoodies-common-1.8.1
unzip -o jgoodies-common-1_8_1.zip > /dev/null
cp /tmp/jgoodies-common-1.8.1/jgoodies-common-*.jar $CAVA_LIB

JACKSON_CORE_URI="https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.11.2"
JACKSON_CORE_LIBS="jackson-core-2.11.2.jar
jackson-core-2.11.2-sources.jar
jackson-core-2.11.2-javadoc.jar"

cd $CAVA_LIB
for LIBRARY in $JACKSON_CORE_LIBS; do
    if [ ! -f $LIBRARY ]; then
        wget -nv $JACKSON_CORE_URI/$LIBRARY >> $PROVISION_LOG
    fi
done

JACKSON_DATABIND_URI="https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.11.2"
JACKSON_DATABIND_LIBS="jackson-databind-2.11.2.jar
jackson-databind-2.11.2-sources.jar
jackson-databind-2.11.2-javadoc.jar"

for LIBRARY in $JACKSON_DATABIND_LIBS; do
    if [ ! -f $LIBRARY ]; then
        wget -nv $JACKSON_DATABIND_URI/$LIBRARY >> $PROVISION_LOG
    fi
done

JACKSON_ANNOTATIONS_URI="https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.11.2"
JACKSON_ANNOTATIONS_LIBS="jackson-annotations-2.11.2.jar
jackson-annotations-2.11.2-sources.jar
jackson-annotations-2.11.2-javadoc.jar"

for LIBRARY in $JACKSON_ANNOTATIONS_LIBS; do
    if [ ! -f $LIBRARY ]; then
        wget -nv $JACKSON_ANNOTATIONS_URI/$LIBRARY >> $PROVISION_LOG
    fi
done

# Install Gradle
echo "-----------------------------------------------------------------------------------------------------"
echo ">>>> Installing Gradle and setting GRADLE_HOME environment variable"
GRADLE_VERSION="gradle-7.4.2"
cd /tmp/
if [ ! -f $GRADLE_VERSION-bin.zip ]; then
    wget -nv https://services.gradle.org/distributions/$GRADLE_VERSION-bin.zip >> $PROVISION_LOG
fi
cd /opt/
unzip -o /tmp/$GRADLE_VERSION-bin.zip > $PROVISION_LOG
ln -s /opt/$GRADLE_VERSION /opt/gradle

if  ! grep -q "GRADLE_HOME" $BASHRC;
then
    echo 'export GRADLE_HOME="/opt/gradle-7.4.2"' >> $BASHRC
fi
echo ">>>> GRADLE_HOME is set to $GRADLE_HOME"


echo "-----------------------------------------------------------------------------------------------------"
echo ">>>> Updating /etc/environment with new PATH variable"
echo 'export PATH=${GRADLE_HOME}/bin:${PATH}' >> $BASHRC

echo ">>>> Finished updates to development libraries and /etc/environment"
echo "-----------------------------------------------------------------------------------------------------"
