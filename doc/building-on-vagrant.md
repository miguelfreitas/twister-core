# Vagrant + Debian building instructions

This will run a virtual machine with all tools required to build and run twister
using Vagrant. 
This will probably work wherever vagrant can be installed.

## Dependencies
* http://www.vagrantup.com/
* https://www.virtualbox.org/


## Install
1. git clone https://github.com/miguelfreitas/twister-core.git
1. cd twister-core
1. vagrant up



## Tweeking
If you have lots of ram in your machine, feel free to use it
edit the twister-core/Vagrantfile and change the line
```
v.customize ["modifyvm", :id, "--memory", 1024]
```
and write 2048, 4096 or whatever you feel resonable
before running vagrant up.

This will make compile time and life in general much
better in the virtual machine.