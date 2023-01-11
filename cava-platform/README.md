# CAVA Experiment Platform

This vagrant configuration creates a virtual machine and installs the prerequisites for the Ghidra reverse engineering toolkit and the various plugins and tool configuraions needed to run experiments using the CAVA experimental platform. During installation, this vagrant configuration downloads a pre-configured virtual machine with the current version of Ghidra being used for experimentation. This vagrant box is then extended and modified for use during experimentation. 

### Directory Contents
 - `bootstrap`: This directory contains all software and configuration files used to configure the CAVA Platform.
 - `cava-data`: This directory will be populated with experimental result log files after a run of the experiment.
 - `cava-tasks`: Contains all cava task information.  See cava-tasks/README.md for details on editing tasks or task sequence. 
 - `cava-platform-changelog.md`: Provides a summary of major changes in the platform for each release. 
 - `README.md`: This readme file. 
 - `Vagrantfile`: Provisioning tool used to build a new virtual machine for experimentation. 

### Experimental Tasks
Experimental tasks provide step-by-step instructions to guide a subject through both introductory and advanced tasks in the Ghidra RE environment. The task information under cava-tasks folder is loaded into a task sequencing user interface that presents each task and associated instructions in turn.  

Please see the `cava-tasks/README.md` file for details on updating the task details or sequence. 


### Platform Components
The platform currently includes the following components:

 - **Debian** -- Linux virtual machine stripped of non-required packages.
 - **Ghidra** -- Baseline Ghidra Configuration (v9.2.4 as of 21 January 2022).
 - **CavaListener** -- Plugin which forwards Ghidra PluginEvents for use as experiment markers. Also presents a task instruction and sequencing interface to the user and handles simple inter-task survey questions. 
 - **CavaCodeBrowser** -- Plugin which instruments the Ghidra Listing view (CodeBrowser).
 - **CavaDecompile** -- Plugin which instruments the Ghidra Decompile view.
 - **CavaFunctionGraph** -- Plugin which instruments the Ghidra Function Graph plugin.
 - **Cantordust** -- Plugin which presents a space-filling curve visualization with visual marker of program location.
 - **CAVA-default.tool** -- Ghidra Tool which configures the layout of Ghidra and installed plugins.
 - **CAVA-cantordust.tool** -- Ghidra Tool which includes the Cantordust space-filling visualization.


### Hardware Expectations
The CAVA platform requires sufficiently powerful hardware to run a multi-core virtual machine and to allow ample resources for both internal and external instrumentation as well as sufficient computing in the host operating system to perform eye tracking, screen capture, or other ancillary tasks such as presenting web-based psychological surveys. 
 - Display Geometry: The CAVA Platform can run on nearly any display environment, but the current experiment expects a monitor of at least a native resolution of 2560x1080.  If running on a larger monitor, the CAVA display should be limited to the center portion of the screen at this resolution to ensure that each subject sees the same screen size.  
    - The virtual display size and geometry can be adjusted within VMware using the menu: View > Resize Virtual Machine 
    - If a different default display resolution is needed, this can be modified in bootstrap/provision-display-resolution.sh
 - Display Size: If the native resolution of the monitor is larger than the display resolution, we do not recommend stretching the display to fit.
 - Letterboxing: Letterboxing the CAVA virtual machine presents the CAVA interface in the center of the display area. 
    - This option can be enabled by using VMware's menus: View > Resize Virtual Machine > Desired Resolution, then: View > Full Screen
 - CPU Performance: The CAVA platform is currently cpu-bound and as such a sufficiently fast and modern CPU should be used to run. 
 - GPU Settings: The GPU may be used for screen recording and drivers and screen recording software should be configured to maximize the resolution of captured images to enable later use of OCR and ML-based screen capture analysis.
    - CPU-driven video compression should not be used as this may both increase CPU contention with the virtual machine (potentially introducing user interface delays) and may introduce visual artifacts that may impact later machine vision-based postprocessing of screen recording data.
    - When possible, screen recording should be performed at full resolution of the display.  
    - If needed, it may be useful to consider letterboxing of the recorded region of the screen as it can be used to eliminate the additional costs of capturing the black border around the edges.


### Host Computer Pre-requisites
1. Linux/Unix preferably, but Windows will work fine as long as Vagrant and a suitable VM provider is installed.
2. If doing development or working with our code repository, you will need a recent version of Git and Git LFS.
    - Git LFS is required to pull binary samples and plugins and is a separate install from Git.
    - If only working with a release, Git tools are not required or used. 
3. VMware
    - VMware Workstation or VMware Fusion >= 12.2.1
        - VMware Fusion for MacOS: <https://www.vmware.com/products/fusion.html>
        - VMware Workstation for Windows and Linux: <https://www.vmware.com/products/workstation-pro.html>
4. Vagrant >= 2.3.2 -- <https://www.vagrantup.com/downloads.html>
    - Required Vagrant Plugins: 
        - vagrant-vmware-desktop >= 3.0.1
        - vagrant-reload >= 0.0.1
        - Vagrant plugins can be installed on the command line:
            - `vagrant plugin install vagrant-vmware-desktop`
            - `vagrant plugin install vagrant-reload`
5. Vagrant VMware Utility <https://www.vagrantup.com/docs/providers/vmware/vagrant-vmware-utility> 
6. Access to the internet for package updates and pre-requisites:
    - Vagrant Cloud - <https://app.vagrantup.com>
    - Debian Linux - <https://www.debian.org>
    - AdoptOpenJDK - <https://adoptopenjdk.net>
    - Ghidra - <https://ghidra-sre.org>


### Running the Platform
1. `> vagrant up --provider=vmware_desktop`
2. Wait until host comes up with no login (it will reboot).
3. The icons in the top-right start instrumentation and LSL forwarding.
3. Hover over the bottom-right corner of the screen to open the hidden dock.
    - Click Cava Verify and then Cava Startup to verify that Keyboard/Mouse instrumentation is working properly.
    - Close/Dismiss the Cava Verify (the daemons will continue running in the background).
6. Startup Ghidra and load a program by dragging it onto one of the two provided tools. 
    - The green dragon is the Cava-default tool.
    - The red dragon is the Cava-cantordust tool. 
7. The default project has a 'hello\_world' program which has already been analyzed. 

### Changing an Experiment's Ghidra Projects
An experiment can be run without pre-loading binary images into Ghidra, but doing so and saving the project with a pre-analyzed binary can save time as these steps are generally not interesting experimentally.  To modify the project that Ghidra starts with: 
1. Start Ghidra in the cava-platform as usual. 
2. Modify the project or create a new project as desired. 
3. Delete any project data or loaded program that is not desired.
4. Close Ghidra, saving the modified project. (Tip: Closing the Ghidra application from the CodeBrowser window rather than Ghidra's project window will enable the program to start directly into the CodeBrowser, skipping the step of starting the CodeBrowser by selecting a Ghidra Tool. This can simplify Ghidra startup for experimentation when only a single project is needed.)
5. If multiple projects are desired, create a new project for each, editing settings and Ghidra tool configurations as needed. 
6. Open a terminal on your host and connect to the virtual machine: `cd cava-platform; vagrant ssh; cd /vagrant/bootstrap/ghidra/`
7. Run the script: `./collectCurrentGhidraConfig.sh` -- This script collects the current ghidra project directory and settings from the virtual machine and archives the current settings.  
8. Re-run the cava-experiment using: `vagrant destroy cava-experiment; vagrant up cava-experiment`

### Halting/Destroying the Platform
1. `vagrant destroy cava-experiment` or `vagrant halt cava-experiment`
2. Wait for the data collection scripts to run.

Since the new update includes a multi-machine vagrant configuration, you will now need to specify which machine to destroy/halt. Not specifying the machine will cause the vagrant command abort.

### Getting Started
Vagrant should take care of downloading the base box from VagrantCloud, updating the Debian operating system packages, and updating Guest Additions if required. After running `vagrant up` and the virtual machine is finished building, you should be presented with a running virtual machine. The default vagrant username and password is "vagrant:vagrant". In some cases, if your host's virtual machine software is newer than the box, the guest additions in the box may be stale and you may have to restart the VM to get the guest additions to be properly upgraded.  

To manually update/force guest addition updates:
    - VirtualBox: `vagrant halt; vagrant up; vagrant vbguest`
    - Parallels: `vagrant halt; vagrant up; vagrant vagrant`


### Using the Pre-built Vagrant box with Ghidra 10
1. Create a directory on your host computer for your vagrant instance: `mkdir ghidra-vagrant`
2. You can use the Vagrant Cloud hosted copy or a local copy of the vagrant box.  
    - If using a local copy of the vagrant box: 
    - `vagrant add solarium/Ghidra-10-Debian-Buster-xfce Ghidra-10-Debian-Buster-xfce.box`
3. Run vagrant init: 
    - `vagrant init solarium/Ghidra-10-Debian-Buster-xfce`
4. Run vagrant up: 
    - `vagrant up`
5. Desktop environment should show up. If not, switch to VirtualBox and click "Show".
6. Ghidra desktop icon should show up on the desktop.
7. Ghidra can also be run from the command line: 
    - `cd /opt/ghidra; ghidra-run.sh`



### Alternative Install: To create a new box with Ghidra using a script:
- Create your own vagrant box or import a suitable box with a desktop environment.
- The Vagrant base box used in our build is: solarium/debian-buster-xfce
    - `mkdir my-ghidra-vm`
    - `vagrant init solarium/debian-buster-xfce`
    - `vagrant up`
    - `./InstallGhidra.sh`
- If you would rather install manually instead of using the script, visit the Ghidra website for instructions.
    - <https://ghidra-sre.org>


### Re-Package Your Updated Box
- Install Ghidra in your own Linux environment either manually or by using one of the methods stated above.
- Clean and minimize the size of the virtual machine disk:
    - `vagrant up; vagrant ssh; sudo /vagrant/bootstrap/clean.sh;`
- Package the updated box:
    - `vagrant package --vagrantfile BoxVagrantfile`
    - The 'BoxVagrantFile` provides the default settings (such as to show the GUI) which can be overridden or modified as needed.
