# CAVA

The purpose of this project is to make it easier to study the human expertise and process involved in software reverse engineering.  This repository consists of all of RE framework and development environment aspects of the DARPA CAVA project (**C**ognitive **A**ids for **V**ulnerability **A**nalysis).  This effort seeks to develop and experimentally verify various cognitive aids for vulnerability analysis tasks.

The project consists of two principle components: 

 1. cava-core: A development environment for building plugins for Ghidra and for performing data analysis of data collected during human subjects research testing (such as opening a saved Ghidra environment). 
 2. cava-platform: An experimental platform which runs Ghidra with a set of instrumented plugins and collects associated human-interaction data such as keyboard and mouse use as well as interactxions with various elements of the Ghidra user interface.


## Quickstart

To run the experimental platform the plugins need to be built.  This requires building the plugins on a system with Java, Eclipse, Ghidra, and the GhidraDev plugin installed and working.  We provide a pre-built virtual machine to streamline plugin development.

### Startup

 1. Provision and start the development virtual machine: `vagrant up`

### Compiling Plugins:

 1. Build a set of instrumented plugins: `vagrant ssh; cd /vagrant/; ./build.sh;`
 2. Install the plugins into the cava-platform: `vagrant ssh; cd /vagrant/; ./build.sh install;`
 3. Generate build release info: `vagrant ssh; cd /vagrant/; ./build.sh release;`

### Plugin Development:

 1. Start Ghidra on the virtual machine desktop for the first time to create Ghidra home directory files and accept the product license.
 2. Start Eclipse and allow GhidraDev to use network communications.
 3. Update Eclipse and plugins using `Help->Check for Updates`.
 4. Open projects from file system from `/vagrant/eclipse-workspace`
 5. Select each project and link each to Ghidra using the GhidraDev menu -- Ghidra is installed at `/home/vagrant/ghidra` -- Python/Jython is not required.
 6. Clear out old Eclipse warnings and errors (select and delete them in the 'Problems' panel).
 7. Test plugin building using `Project->Build All`.
 8. Create new plugins in Eclipse using `GhidraDev->New` menu.
 9. Perform plugin development and testing as desired.

### Platform Configuration:

 1. Run the platform: `cd cava-platform; vagrant up`
 2. Run and configure Ghidra with projects and settings as needed.
 3. Save Ghidra project and settings with a helper script: `cd cava-platform; vagrant ssh; ./collect-current-ghidra-config.sh;`
 4. Modify the desktop environment as needed. 
 5. Save any desktop settings with a helper script: `cd cava-platform; vagrant ssh; ./collect-xfce-settings.sh` 

### Platform Testing:

 1. Destroy and re-provision the platform to test/validate settings: `cd cava-platform; vagrant destroy cava-experiment; vagrant up`
 2. Test as if you were a human subject using the environment.
 3. Re-configure and extend the environment as needed.

### Platform Packaging:

 1. Package the platform for deployment: `vagrant ssh; cd /vagrant/; ./package-cava-platform.sh;`
 2. Validate that the package contains all necessary components by copying to a local directory and testing deployment. 

### Platform Deployment:

 1. Copy the packaged tar file of the cava-platform to the system that will be used for experimentation.
 2. Untar the packaged platform: `tar -xzvf cava-platform.tgz`
 3. Run the platform: `cd cava-platform; vagrant up`

### Test Subject Data Collection:

 1. Shut down the virtual machine: `vagrant halt`
 2. Check that new data is present in `cava-data`: `cd cava-platform/cava-data; ls -al`
 3. If desired, validate this data is complete before destroying the virtual machine.
 4. Destroy the virtual machine (this will not affect contents cava-data directory): `cd cava-platform; vagrant destroy cava-experiment`


## Running the CAVA Platform
Cava is run using Vagrant from within the cava-platform folder.  We recommend starting from a freshly provisioned VM to ensure all changes to the platform are capture during provisioning. 

`cd cava-platform;`
`vagrant destroy;`
`vagrant up;`

Cava is intended to run in a single monitor at a fixed resolution.  We have experimented with various screen resolutions.  We recommend using a letterboxed and centered screen geometry of 1080 x 2560.  If the monitor which you are testing at is at a lower resolution, then Ghidra's plugins will have to be updated to fit the screen. 


# CAVA Development
## Development Environment

Before building, first check that your Vagrant box is up to date: `vagrant box update`.  If it is out of date, you will need to destroy your current build environment and rebuild the environment.  This should only occur on updates of our base box (once or twice per year).  Note that everthing in the virtual machine environment outside of the shared folder at /vagrant should be treated as disposable.  Anything that you would like to be maintained must not live solely inside the virtual machine.  To rebuild your development environment


### Git

Our project uses both Git and Git LFS (Large File Storage).  Both of these tools must be installed on your development computer prior to attempting to check out source code repositories or building the system.  Git LFS is used for binary samples, zip files, and other files which do not normally belong in a Git repository.  

> **Note:** Shutdown your virtual machine before switching branches. Switching git branches with a running machine **will cause networking issues**. If you get errors 
such as "An error was encountered while generating the current list of available VMware adapters in use on this system" -- switch back to the original branch and shut the machine down using *vagrant halt* before continuing.


### Vagrant Basics
`vagrant destroy;`

Destroys the current virtual machine configuration. 

`vagrant box update;`

Updates the Vagrant box to the most recent version.  Boxes are publicly hosted on Hashicorp Cloud. 

`vagrant up;`

Creates a new box by downloading the base box (if needed) and running our provisioning scripts to pull in our codebase and any additional pre-requisites. 

### Eclipse 
Once the Vagrant cava-core virtual machine is running, you will need to set your Eclipse workspace, run Ghidra the first time, and update any out of data Eclipse plugins. 

1. Run Ghidra and it will automatically generate its settings folder at ~/.ghidra
2. Run Eclipse and set your workspace to /vagrant/eclipse-workspace
3. Update any Eclipse Plugins that are out of date.  In particular, the GhidraDev plugin should prompt to be updated.  
4. Restart Eclipse -- ignore the superlong openjdk hotspot Eclipse launcher message that shows up after updating the Ghidra plugin and just start it again (not sure what this is/means).
5. Eclipse should be running and plugins should build properly without errors. 


## Building and Installation

`./build.sh build`

This builds the CAVA plugins using Gradle.  Build artifacts (plugin zip files) are located under the dist folder for each plugin (e.g. eclipse-workspace/CavaListener/dist). 


`./build.sh clean`

Cleans the plugin build artifacts by deleting all of the built and zipped plugins under each plugin dist folders. 

`./build.sh install`

Installs built plugins to the cava-platform folder at `cava-platform/bootstrap/ghidra/extensions`.  This script also overwrites the `ghidra\_extension\_release.txt` file with the most recently modified versions of the plugins found. Once installed, the next run of the cava-platform provisioning (either a fresh start or running the `provision-ghidra-extensions.sh` script will install the plugins into the cava-platform ghidra  under `/opt/ghidra/Ghidra/extensions`


# Creating a new Cava Platform Release

1. Checkout the desired branch/commit for the release.
2. Build using `./build.sh build`
3. Install the newly built plugins: `./build.sh install`
4. Run the updated release: `cd cava-platform; vagrant destroy; vagrant up;`
5. Check that the windowing environment and the Ghidra tool for the release is configured as desired and that all modules load and run as expected.
6. Ghidra Tool Updates: If needed, update the Ghidra tool layout or configuration, then within the running virtual machine, manually save the CAVA-cantordust.tool and CAVA-default.tool to /vagrant/cava-platform/bootstrap/ghidra/ with updated tool configurations, overwriting the previous tool configurations. 
7. Ghidra Software Settings: If needed, update Ghidra's project or software settings, then within the running virtual machine, run `collectCurrentGhidraConfig.sh` (located under /vagrant/bootstrap/ghidra/) to copy Ghidra's current settings.
8. XFCE Desktop Settings: If needed, update the XFCE desktop environment, then within the running virtual machine, run `./collect-xfce-settings.sh` (located under /vagrant/bootstrap/). This collects the XFCE desktop, menu, and panel configurations as currently shown in the running virtual machine.
9. Package the current cava-platform: From the host (not inside the VM), run `./package-cava-platform.sh` to create a zip file of the current platform folder contents. This script tells tar to exclude the .vagrant subfolder and creates a cava-platform tar.gz post-pended with the current date.
10. Copy the tgz to a new folder, extract it, and start/test the packaged release using `vagrant up`

# Monitor Log Messages During an Experiment

1. Execute the following commands in a terminal to see live updates of the log messages being generated:
2. `vagrant ssh`
3. `cd /vagrant/`
4. `./tallyStreamingEvents.sh`


# Updating Vagrant Base Box Images
Our baseline virtual machine images contain only publicly available tools and information and are hosted on the Hashicorp Vagrant Cloud service as publicly accessible virtual machine images.  To update a base box, you will need to start from the most recent baseline image, update this image, repackage it, then re-upload to the Vagrant Cloud environment for re-use.  Note that no proprietary information should be included in the baseline virtual machine.  Any project or program specific data must be dealt with during vagrant provisioning. 

Other than the path to the baseline image, the process for updating the CAVA development and CAVA platform environments is the same.  Note that the Cava Platform is not intended for development and develpment tools should, in general, not be installed to the platform virtual machine.  The rationale is to keep the base image as small as possible.  

1. Create a new directory for updating the baseline image.
2. Run `vagrant init` to create a Vagrantfile (e.g. `vagrant init solarium/ghidra-10-devtools` or `vagrant init solarium/ghidra-10-debian-buster-xfce`
3. Run `vagrant up` to pull down and start the baseline virtual machine. 
4. Enter the VM and edit/update as needed. 
    - Update apt package lists: ```apt-get update```
    - Upgrade available packages: ```apt-get upgrade```
    - Upgrade Ghidra and/or Eclipse where appropriate.
5. Re-package the box. 
6. Test the newly packaged box locally. 
7. Upload to the Vagrant cloud, replacing the current version of the box. 


Updating Ghidra (cava-core and cava-platform)
1. Download the the most recent Ghidra release (https://github.com/NationalSecurityAgency/ghidra/releases).
2. Unzip the new release to replace the old Ghidra release:
    - cava-core: /home/vagrant/ghidra 
    - cava-platform: /opt/ghidra 

Debugger in Ghidra
  - The debugger in Ghidra requires additional packages to get working. 
    - For GDB-based remote debugging over SSH: install gdb and gdbserver.
    - For LLVM-based Debugging using Java locally: 
        1. Install Ninja: apt-get install ninja
        2. Manually build and generate the JNI using instructions at https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Debug/Debugger-swig-lldb/InstructionsForBuildingLLDBInterface.txt

Updating Eclipse (cava-core only)
1. Download the most recent Eclipse release (https://www.eclipse.org/downloads/packages/)
2. Unzip the new release to replace the old Eclipse release: 
    - cava-core: `/opt/eclipse`
    - cava-platform: Eclipse should not be installed in the platform virtual machine.

Box Testing
- Ghidra Testing:
    - Verify that Ghidra runs as expected.
    - After testing, remove `~/.ghidra` before re-packaging the Vagrant box. 

- Eclipse Testing:
    - Verify that Eclipse runs as expected.
    - Ensure any included Eclipse plugins are up to date. 
    - Verify that GhidraDev plugin is installed and up to date.
    - Remove `~/.eclipse` user settings before re-packaging the Vagrant box. 

# Tips and Tricks

## Enabling new plugins
When building and installing new ghidra plugins, you will need to enable them in the experiment platform. Here are the steps to follow,

    1. Open `Ghidra` and start one of the tools.
    2. Left-click `File->Configure`.
    3. Left-click the blue `Configure` text on your plugins category.
    4. Left-click on the checkbox to enable

After following these steps, your plugin should be available under `Window` header.

## Collecting more data

If your experiment has other data to collect and it is saved locally on the virtual machine, it is advised to modify the shell script under `cava-platform/bootstrap/saveCavaData.sh`. This script is ran automatically whenever the experiment platform is halted or destroyed.
