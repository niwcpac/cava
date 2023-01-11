# -*- mode: ruby -*-
# vi: set ft=ruby :

# We use vagrant-reload to restart the virtual machine after initial provisioning
unless Vagrant.has_plugin?("vagrant-reload")
    puts '!! Missing plugin: vagrant-reload plugin is not installed.'
    puts 'Please run: vagrant plugin install vagrant-reload'
    exit
end

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
    config.vm.box = "solarium/ghidra-10-devtools"

    config.vm.define :"cava-development"

        # Change this to check for base-box version updates
    config.vm.box_check_update = true

        # VMWare Options
    config.vm.provider "vmware_desktop" do |vmware, override|
            vmware.memory = 8192
            vmware.cpus = 4
            vmware.gui = true

            #Settings to fix potential VMX PCI slot number issue in future VMWare Releases
            #See: https://www.vagrantup.com/docs/vmware/boxes.html#vmx-allowlisting
            vmware.vmx["ethernet0.pcislotnumber"] = "33"
    end

        # Parallels Options
    config.vm.provider "parallels" do |prl, override|
        prl.memory = 8192
        prl.cpus = 4
        prl.customize ["set", :id, "--startup-view", "window"]

        # Fix for parallels issues with inode in Parallels
        #puts "Configuring inode shared folder fix for Parallels provider"
        override.vm.synced_folder ".", "/vagrant", mount_options: ["share", "noatime", "host_inodes"]
    end

        # Virtualbox Options - GUI performs very poorly in virtualbox
    config.vm.provider "virtualbox" do |vb, override|
            # Change this to allow vagrant to manage VirtualBox guest additions
            override.vbguest.auto_update = false

            # Display the VirtualBox GUI when booting the machine
            vb.gui = true

            # Customize the amount of memory on the VM:
            vb.memory = 8192
            vb.cpus = 4
            vb.customize ["modifyvm", :id, "--vram", "128"]

            # Below may help in performance for some systems
            vb.customize ["modifyvm", :id, "--largepages", "on"]
            vb.customize ["modifyvm", :id, "--vtxvpid", "on"]
            # See: https://www.virtualbox.org/manual/ch10.html#hwvirt

    end


    # The following scripts are used to provision the cava-platform environment
    # For development we probably only need the instrumentation-daemons and if desired, the Ghidra settings 
    #
    # Bootstrap directory for these scripts must be the cava-platform/bootstrap directory
    env_vars = {  
               "LOG" => "/opt/cava-log", 
               "PROVISION_LOG" => "/opt/cava-log/bootstrap.log", 
               "BIN" => "/opt/cava", 
               "BOOTSTRAP" => "/vagrant/cava-platform/bootstrap",
               "DEBIAN_FRONTEND" => "noninteractive",
               "GHIDRA_HOME" => "/home/vagrant/ghidra/",
               "GRADLE_HOME" => "/opt/gradle-7.4.2",
               }

               # Notes: DEBIAN_FRONTEND fixes spurious errors from dpkg-preconfigure
               #
               
    #Always copy over our helper script for environment variable setup
    config.vm.provision "file", source: "cava-platform/bootstrap/provision-check.sh", destination: "/tmp/provision-check.sh", run: 'always'

    # For development, provision tools and libraries required for plugin development
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-development-environment.sh", env: env_vars, preserve_order: true

    #config.vm.provision "shell", path: "cava-platform/bootstrap/provision-start.sh", env: env_vars, preserve_order: true
    #config.vm.provision "shell", path: "cava-platform/bootstrap/provision-package-install.sh", env: env_vars, preserve_order: true

    # Install instrumentation daemons
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-instrumentation-daemons.sh", env: env_vars, preserve_order: true
    
    # Helper script for Ghidra installs used when testing new versions:  
    #config.vm.provision "shell", path: "cava-platform/bootstrap/provision-install-ghidra.sh", env: env_vars, preserve_order: true
    
    # Simplifies desktop environment for experimental use:
    #config.vm.provision "shell", path: "cava-platform/bootstrap/provision-setup-desktop.sh", env: env_vars, preserve_order: true
    
    # Installation of pre-build Ghidra extensions will conflict with use of GhidraDev to start and debug plugins
    # config.vm.provision "shell", path: "cava-platform/bootstrap/provision-ghidra-extensions.sh", env: env_vars, preserve_order: true
    
    # Install the Ghidra settings requires the extensions for the tools to be loaded
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-ghidra-settings.sh", env: env_vars, preserve_order: true

    # Install cava-analysis tools to development desktop
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-install-cava-analysis-tools.sh", env: env_vars
    
    # Always run the display resolution update to set the default VM to the desired screen resolution
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-display-resolution.sh", run: 'always'

    # Creates a file on the Desktop with build metadata
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-plugin-build-check.sh", env: env_vars, preserve_order: true

    # Output friendly comments to let the user know we are finished
    config.vm.provision "shell", path: "cava-platform/bootstrap/provision-finish.sh", env: env_vars, preserve_order: true

    # Reload the virtual machine after provisioning 
    # TODO: This needs updated to change to be only performed when required. Most provision actions do not require a reboot. 
    config.vm.provision :reload
end
