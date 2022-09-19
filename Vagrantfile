Vagrant.configure("2") do |config|
  config.vm.base_mac = nil
  config.ssh.username = "labs"
  config.ssh.private_key_path = "labs_private"
  config.ssh.forward_agent = true

#  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
    vb.cpus = 1
#    vb.linked_clone = true
  end

  N = 3
  (1..N).each do |machine_id|
    config.vm.define "nginx-#{machine_id}" do |n|
      #n.vm.hostname = "nginx-#{machine_id}"
      #n.vm.network "private_network", ip: "192.168.0.#{75+machine_id}"
      n.vm.network "public_network", bridge: 'Realtek Gaming GbE Family Controller', ip: "192.168.0.#{75+machine_id}"
      n.vm.network "forwarded_port", guest: 80, host: "#{9080+machine_id}"
      n.vm.network "forwarded_port", guest: 443, host: "#{9442+machine_id}"
      n.vm.box = "ubuntu-box"
      end
    end
end