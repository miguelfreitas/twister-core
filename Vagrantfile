# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box     = 'debian7'
  config.vm.box_url = 'http://puppet-vagrant-boxes.puppetlabs.com/debian-70rc1-x64-vbox4210.box'

  config.vm.provider "virtualbox" do |v|
    v.customize ["modifyvm", :id, "--memory", 1024]
  end

  #config.vm.synced_folder '.', '/srv/Mailpile'
  

  config.vm.network :public_network
  config.vm.network :forwarded_port, guest: 28332, host: 28332, guest_ip: '127.0.0.1'
  
  config.vm.provision :shell, :path => 'scripts/vagrant_bootstrap.sh'
end
