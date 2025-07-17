#!/usr/bin/env ruby
# frozen_string_literal: true

# Example usage of beaker-kubevirt
# This demonstrates how to configure and use the KubeVirt hypervisor

require 'beaker/kubevirt'

# Example Beaker host configuration
hosts_config = {
  'HOSTS' => {
    'centos-vm' => {
      'platform' => 'el-8-x86_64',
      'hypervisor' => 'kubevirt',
      'vm_image' => 'quay.io/kubevirt/centos-stream8-container-disk-demo',
      'network_mode' => 'port-forward',
      'ssh_key' => '~/.ssh/id_rsa.pub',
      'cpu' => 2,
      'memory' => '4Gi',
    },
    'ubuntu-vm' => {
      'platform' => 'ubuntu-20.04-x86_64',
      'hypervisor' => 'kubevirt',
      'vm_image' => 'pvc:ubuntu-20-04-disk',
      'network_mode' => 'nodeport',
      'ssh_key' => '~/.ssh/id_rsa.pub',
      'cpu' => 1,
      'memory' => '2Gi',
    },
  },
  'CONFIG' => {
    # Global KubeVirt configuration
    'kubeconfig' => '~/.kube/config',
    'namespace' => 'beaker-tests',  # required global setting
    'ssh' => {
      'auth_methods' => ['publickey'],
    },
  },
}

puts 'Example KubeVirt Beaker configuration:'
puts hosts_config.to_yaml

# Example of programmatic usage
if $PROGRAM_NAME == __FILE__
  # This would typically be called by Beaker
  options = {
    logger: Logger.new($stdout),
    kubeconfig: ENV['KUBECONFIG'] || File.expand_path('~/.kube/config'),
    namespace: 'beaker-tests',
    vm_image: 'quay.io/kubevirt/fedora-cloud-container-disk-demo',
    network_mode: 'port-forward',
    ssh_key: File.expand_path('~/.ssh/id_rsa.pub'),
  }

  hosts = [
    {
      'name' => 'test-vm',
      'platform' => 'el-8-x86_64',
    },
  ]

  begin
    hypervisor = Beaker::KubeVirt.new(hosts, options)
    puts 'Successfully created KubeVirt hypervisor instance'
    puts "Test group identifier: #{hypervisor.instance_variable_get(:@test_group_identifier)}"
  rescue StandardError => e
    puts "Error creating hypervisor: #{e.message}"
  end
end
