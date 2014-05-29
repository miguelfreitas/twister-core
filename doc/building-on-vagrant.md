# Vagrant + Ubuntu building instructions

This will run a virtual machine with all tools required to build and run twister
using Vagrant.
This will probably work wherever vagrant can be installed so Windows, Mac, Linux
at least

## Dependencies
* http://www.vagrantup.com/
* https://www.virtualbox.org/


## Install
1. git clone https://github.com/miguelfreitas/twister-core.git
2. cd twister-core/contrib/buildenv
3. vagrant up



## Tweeking
If you have lots of ram and CPU in your machine, feel free to use it.
Before running vagrant up please set
VAGRANT_RAM and/or VAGRANT_CPU environment variables to whatever is fitting.
Default is 1 CPU and 1024 MB RAM.

Example with 2 CPU and 4096 MB RAM.
```bash
export VAGRANT_CPU=2
export VAGRANT_RAM=4096
```
