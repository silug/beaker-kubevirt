# frozen_string_literal: true

require 'securerandom'
require 'yaml'
require 'base64'
require 'socket'
require 'tempfile'

begin
  require 'beaker'
rescue LoadError
  # If beaker is not available, define a minimal Hypervisor base class
  module Beaker
    class Hypervisor
      def initialize(hosts, options)
        @hosts = hosts
        @options = options
      end
    end
  end
end

module Beaker
  # Beaker support for KubeVirt virtualization platform
  class KubeVirt < Beaker::Hypervisor
    SLEEPWAIT = 5
    SSH_TIMEOUT = 300

    ##
    # Create a new instance of the KubeVirt hypervisor object
    #
    # @param [Array<Host>] kubevirt_hosts The Array of KubeVirt hosts to provision
    # @param [Hash{Symbol=>String}] options The options hash containing configuration values
    #
    # @option options [String] :kubeconfig Path to kubeconfig file
    # @option options [String] :kubecontext Kubernetes context to use (optional)
    # @option options [String] :namespace Kubernetes namespace for VMs
    # @option options [String] :vm_image Base VM image (PVC, container image, etc.)
    # @option options [String] :network_mode Network mode (port-forward, nodeport, multus)
    # @option options [String] :ssh_key SSH public key to inject
    # @option options [String] :cpu CPU resources for VM
    # @option options [String] :memory Memory resources for VM
    # @option options [Integer] :timeout Timeout for operations
    def initialize(kubevirt_hosts, options)
      require 'beaker/hypervisor/kubevirt_helper'

      super
      @options = options
      @logger = options[:logger]
      @hosts = kubevirt_hosts
      @kubevirt_helper = KubeVirtHelper.new(options)
      @test_group_identifier = "beaker-#{SecureRandom.hex(4)}"
    end

    ##
    # Create and configure virtual machines in KubeVirt
    def provision
      @logger.info("Starting KubeVirt provisioning with identifier: #{@test_group_identifier}")

      @hosts.each do |host|
        create_vm(host)
      end

      @hosts.each do |host|
        wait_for_vm_ready(host)
        setup_ssh_access(host)
      end
    end

    ##
    # Shutdown and destroy virtual machines in KubeVirt
    def cleanup
      @logger.info('Cleaning up KubeVirt resources')

      @hosts.each do |host|
        next unless host['vm_name']

        @kubevirt_helper.delete_vm(host['vm_name'])
        host_name = host.respond_to?(:name) ? host.name : host['name']
        @logger.debug("Deleted KubeVirt VM #{host['vm_name']} for #{host_name}")
      end
    end

    private

    ##
    # Create a single VM for the given host
    # @param [Host] host The host to create a VM for
    def create_vm(host)
      vm_name = generate_vm_name(host)
      host['vm_name'] = vm_name

      cloud_init_data = generate_cloud_init(host)
      vm_spec = generate_vm_spec(host, vm_name, cloud_init_data)

      @logger.debug("Creating KubeVirt VM #{vm_name} for #{host.name}")
      @kubevirt_helper.create_vm(vm_spec)
      @logger.info("Created KubeVirt VM #{vm_name}")
    end

    ##
    # Generate a unique VM name
    # @param [Host] host The host
    # @return [String] The generated VM name
    def generate_vm_name(host)
      host_name = host.respond_to?(:name) ? host.name : host['name']
      base_name = host_name.gsub(/[^a-z0-9-]/, '-').downcase
      "#{@test_group_identifier}-#{base_name}"
    end

    ##
    # Generate cloud-init configuration for the VM
    # @param [Host] host The host configuration
    # @return [String] Base64 encoded cloud-init user data
    def generate_cloud_init(host)
      username = host['user'] || 'beaker'
      ssh_key = find_ssh_public_key

      host_name = host.respond_to?(:name) ? host.name : host['name']

      cloud_init = {
        'users' => [
          {
            'name' => username,
            'sudo' => 'ALL=(ALL) NOPASSWD:ALL',
            'ssh_authorized_keys' => [ssh_key],
            'shell' => '/bin/bash',
          },
        ],
        'hostname' => host_name,
        'ssh_pwauth' => false,
        'disable_root' => false,
        'chpasswd' => {
          'expire' => false,
        },
      }

      # Add custom cloud-init if provided
      if @options[:cloud_init]
        custom_init = YAML.safe_load(@options[:cloud_init])
        cloud_init = cloud_init.merge(custom_init)
      end

      Base64.strict_encode64("#cloud-config\n#{cloud_init.to_yaml}")
    end

    ##
    # Find SSH public key
    # @return [String] SSH public key content
    def find_ssh_public_key
      if @options[:ssh_key]
        if File.exist?(@options[:ssh_key])
          File.read(@options[:ssh_key]).strip
        else
          @options[:ssh_key].strip
        end
      else
        # Try common locations
        default_key_paths = [
          File.join(Dir.home, '.ssh', 'id_rsa.pub'),
          File.join(Dir.home, '.ssh', 'id_ed25519.pub'),
          File.join(Dir.home, '.ssh', 'id_ecdsa.pub'),
        ]

        key_path = default_key_paths.find { |path| File.exist?(path) }
        raise 'No SSH public key found. Specify with :ssh_key option.' unless key_path

        File.read(key_path).strip
      end
    end

    ##
    # Generate VM specification for KubeVirt
    # @param [Host] host The host configuration
    # @param [String] vm_name The VM name
    # @param [String] cloud_init_data Base64 encoded cloud-init data
    # @return [Hash] VM specification
    def generate_vm_spec(host, vm_name, cloud_init_data)
      cpu = host['cpu'] || @options[:cpu] || '1'
      memory = host['memory'] || @options[:memory] || '2Gi'
      vm_image = host['vm_image'] || @options[:vm_image]
      host_name = host.respond_to?(:name) ? host.name : host['name']

      raise 'vm_image must be specified' unless vm_image

      {
        'apiVersion' => 'kubevirt.io/v1',
        'kind' => 'VirtualMachine',
        'metadata' => {
          'name' => vm_name,
          'namespace' => @kubevirt_helper.namespace,
          'labels' => {
            'beaker/test-group' => @test_group_identifier,
            'beaker/host' => host_name,
          },
        },
        'spec' => {
          'running' => true,
          'template' => {
            'metadata' => {
              'labels' => {
                'beaker/test-group' => @test_group_identifier,
                'kubevirt.io/vm' => vm_name,
              },
            },
            'spec' => {
              'domain' => {
                'cpu' => {
                  'cores' => cpu.to_i,
                },
                'memory' => {
                  'guest' => memory,
                },
                'devices' => {
                  'disks' => [
                    {
                      'name' => 'rootdisk',
                      'disk' => {
                        'bus' => 'virtio',
                      },
                    },
                    {
                      'name' => 'cloudinitdisk',
                      'disk' => {
                        'bus' => 'virtio',
                      },
                    },
                  ],
                  'interfaces' => [
                    {
                      'name' => 'default',
                      'bridge' => {},
                    },
                  ],
                },
              },
              'networks' => [
                {
                  'name' => 'default',
                  'pod' => {},
                },
              ],
              'volumes' => [
                generate_root_volume_spec(vm_image),
                {
                  'name' => 'cloudinitdisk',
                  'cloudInitNoCloud' => {
                    'userData' => cloud_init_data,
                  },
                },
              ],
            },
          },
        },
      }
    end

    ##
    # Generate root volume specification based on image type
    # @param [String] vm_image The VM image specification
    # @return [Hash] Volume specification
    def generate_root_volume_spec(vm_image)
      if vm_image.include?('/')
        # Container image
        {
          'name' => 'rootdisk',
          'containerDisk' => {
            'image' => vm_image,
          },
        }
      elsif vm_image.start_with?('pvc:')
        # PVC reference
        pvc_name = vm_image.sub(/^pvc:/, '')
        {
          'name' => 'rootdisk',
          'persistentVolumeClaim' => {
            'claimName' => pvc_name,
          },
        }
      else
        # Assume it's a PVC name
        {
          'name' => 'rootdisk',
          'persistentVolumeClaim' => {
            'claimName' => vm_image,
          },
        }
      end
    end

    ##
    # Wait for VM to be ready and running
    # @param [Host] host The host to wait for
    def wait_for_vm_ready(host)
      vm_name = host['vm_name']
      @logger.info("Waiting for VM #{vm_name} to be ready...")

      timeout = @options[:timeout] || 300
      start_time = Time.now

      loop do
        vmi = @kubevirt_helper.get_vmi(vm_name)

        if vmi && vmi.dig('status', 'phase') == 'Running'
          @logger.debug("VM #{vm_name} is running")
          break
        end

        raise "Timeout waiting for VM #{vm_name} to be ready" if Time.now - start_time > timeout

        sleep SLEEPWAIT
      end

      # Get VM IP address
      setup_networking(host)
    end

    ##
    # Setup networking for the VM
    # @param [Host] host The host to setup networking for
    def setup_networking(host)
      network_mode = @options[:network_mode] || 'port-forward'

      case network_mode
      when 'port-forward'
        setup_port_forward(host)
      when 'nodeport'
        setup_nodeport(host)
      when 'multus'
        setup_multus_networking(host)
      else
        raise "Unsupported network mode: #{network_mode}"
      end
    end

    ##
    # Setup port-forward networking
    # @param [Host] host The host
    def setup_port_forward(host)
      vm_name = host['vm_name']
      local_port = find_free_port

      @logger.debug("Setting up port-forward for VM #{vm_name} on port #{local_port}")

      port_forward_cmd = @kubevirt_helper.setup_port_forward(vm_name, 22, local_port)
      host['ip'] = '127.0.0.1'
      host['port'] = local_port
      host['ssh'] ||= {}
      host['ssh']['port'] = local_port
      host['port_forward_process'] = port_forward_cmd
    end

    ##
    # Setup NodePort networking
    # @param [Host] host The host
    def setup_nodeport(host)
      vm_name = host['vm_name']
      service_name = "#{vm_name}-ssh"

      @logger.debug("Creating NodePort service for VM #{vm_name}")
      service = @kubevirt_helper.create_nodeport_service(vm_name, service_name)

      node_port = service.dig('spec', 'ports', 0, 'nodePort')
      node_ip = @kubevirt_helper.get_node_ip

      host['ip'] = node_ip
      host['port'] = node_port
      host['ssh'] ||= {}
      host['ssh']['port'] = node_port
      host['service_name'] = service_name
    end

    ##
    # Setup Multus networking (external bridge)
    # @param [Host] host The host
    def setup_multus_networking(host)
      vm_name = host['vm_name']
      @logger.debug("Getting external IP for VM #{vm_name} via Multus")

      # For Multus, we need to wait for the VM to get an external IP
      external_ip = wait_for_external_ip(vm_name)

      host['ip'] = external_ip
      host['port'] = 22
      host['ssh'] ||= {}
      host['ssh']['port'] = 22
    end

    ##
    # Wait for VM to get external IP via Multus
    # @param [String] vm_name The VM name
    # @return [String] External IP address
    def wait_for_external_ip(vm_name)
      timeout = @options[:timeout] || 300
      start_time = Time.now

      loop do
        vmi = @kubevirt_helper.get_vmi(vm_name)
        interfaces = vmi.dig('status', 'interfaces')

        if interfaces
          external_interface = interfaces.find { |iface| iface['name'] != 'default' }
          return external_interface['ipAddress'] if external_interface && external_interface['ipAddress']
        end

        raise "Timeout waiting for external IP for VM #{vm_name}" if Time.now - start_time > timeout

        sleep SLEEPWAIT
      end
    end

    ##
    # Find a free local port for port forwarding
    # @return [Integer] Free port number
    def find_free_port
      server = TCPServer.new(0)
      port = server.addr[1]
      server.close
      port
    end

    ##
    # Setup SSH access for the host
    # @param [Host] host The host to setup SSH for
    def setup_ssh_access(host)
      host_name = host.respond_to?(:name) ? host.name : host['name']
      @logger.info("Setting up SSH access for #{host_name} at #{host['ip']}:#{host['port']}")

      # Wait for SSH to be available
      wait_for_ssh(host)

      # Setup SSH keys if needed
      return unless @options[:ssh_private_key]
      return unless host.respond_to?(:options)

      host.options ||= {}
      host.options['ssh'] ||= {}
      host.options['ssh']['keys'] = [@options[:ssh_private_key]]
    end

    ##
    # Wait for SSH to become available
    # @param [Host] host The host to check SSH for
    def wait_for_ssh(host)
      @logger.debug("Waiting for SSH to be available on #{host['ip']}:#{host['port']}")

      timeout = SSH_TIMEOUT
      start_time = Time.now

      loop do
        begin
          sock = TCPSocket.new(host['ip'], host['port'])
          sock.close
          @logger.debug("SSH is available on #{host['ip']}:#{host['port']}")
          break
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ETIMEDOUT
          # SSH not ready yet
        end

        raise "Timeout waiting for SSH on #{host['ip']}:#{host['port']}" if Time.now - start_time > timeout

        sleep 2
      end
    end
  end
end
