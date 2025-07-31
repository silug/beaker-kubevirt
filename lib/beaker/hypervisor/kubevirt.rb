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
    # Beaker support for the KubeVirt virtualization platform.
    #
    # This class implements a Beaker hypervisor driver for managing virtual machines
    # on a KubeVirt-enabled Kubernetes cluster. It provides methods for provisioning,
    # configuring, and cleaning up VMs, as well as handling networking and SSH access.
    #
    # The class expects to be initialized with a list of host definitions and an options hash.
    # It supports multiple network modes (port-forward, nodeport, multus) and integrates
    # with KubeVirt's APIs for VM lifecycle management.
    #
    # @see https://kubevirt.io/ KubeVirt Documentation
    # @see https://github.com/voxpupuli/beaker Beaker Documentation
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
  class Kubevirt < Beaker::Hypervisor
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
    # @option options [String] :namespace Kubernetes namespace for VMs (required)
    # @option options [String] :vm_image Base VM image (PVC, container image, etc.)
    # @option options [String] :network_mode Network mode (port-forward, nodeport, multus)
    # @option options [String] :ssh_key SSH public key to inject
    # @option options [String] :cpu CPU resources for VM
    # @option options [String] :memory Memory resources for VM
    # @option options [Integer] :timeout Timeout for operations
    # @option options [Boolean] :disable_virtio Disable virtio devices (for compatibility with Windows)
    def initialize(kubevirt_hosts, options)
      require 'beaker/hypervisor/kubevirt_helper'

      super
      @options = options
      @namespace = @options[:namespace]
      raise 'Namespace must be specified in options' unless @namespace

      @logger = options[:logger]
      @hosts = kubevirt_hosts
      # Ensure the helper gets the validated namespace
      @kubevirt_helper = KubevirtHelper.new(@options)
      @test_group_identifier = "beaker-#{SecureRandom.hex(4)}"
    end

    ##
    # Create and configure virtual machines in KubeVirt
    def provision
      # rubocop:disable Style/CombinableLoops
      @logger.info("Starting KubeVirt provisioning with identifier: #{@test_group_identifier}")

      @hosts.each do |host|
        create_vm(host)
      end

      @hosts.each do |host|
        wait_for_vm_ready(host)
        setup_networking(host)
      rescue StandardError, Interrupt => e
        @logger.error("Error provisioning host #{host.name}: #{e.message}")
        @logger.error("Cleaning up host #{host.name} due to provisioning failure")
        cleanup
        raise e
      end
      # rubocop:enable Style/CombinableLoops
    end

    ##
    # Shutdown and destroy virtual machines in KubeVirt
    def cleanup(timeout: 10, delay: 1)
      @logger.info('Cleaning up KubeVirt resources')

      @hosts.each do |host|
        next unless host['port_forwarder']

        host_name = host.respond_to?(:name) ? host.name : host['name']
        @logger.debug("Stopping port-forwarder for host: #{host_name}")
        host['port_forwarder'].stop if host['port_forwarder'].respond_to?(:stop)
        Timeout.timeout(timeout) do
          loop do
            break if host['port_forwarder'].state == :stopped

            @logger.debug("Waiting for port-forwarder to stop for host: #{host_name}")
            sleep delay
          end
        rescue Timeout::Error
          @logger.warn("Port-forwarder for host #{host_name} did not stop in time: ")
          raise
        rescue StandardError => e
          @logger.error("Error stopping port-forwarder for host #{host_name}: #{e}")
        end
      end

      @logger.info("Cleaning up resources in namespace: #{@namespace}")
      # Cleanup VMs associated with the test group
      @kubevirt_helper.cleanup_vms(@test_group_identifier)
      # Cleanup secrets associated with the test group
      @kubevirt_helper.cleanup_secrets(@test_group_identifier)
      # Cleanup services associated with the test group
      @kubevirt_helper.cleanup_services(@test_group_identifier)
    end

    private

    ##
    # Create a single VM for the given host
    # @param [Host] host The host to create a VM for
    def create_vm(host)
      vm_name = generate_vm_name(host)
      host['vm_name'] = vm_name

      # Generate DataVolume name if applicable and store it for consistency
      vm_image = host['vm_image'] || @options[:vm_image]
      if vm_image&.start_with?('http://', 'https://')
        base_name = vm_image.split('/').last
        # Create a unique datavolume name by including the VM name in it
        host['dv_name'] = sanitize_k8s_name("#{vm_name}-#{base_name}-dv")
      end

      cloud_init_data = generate_cloud_init(host)
      cloud_init_secret_name = create_cloud_init_secret(host, cloud_init_data)

      vm_spec = generate_vm_spec(host, vm_name, cloud_init_secret_name)

      @logger.debug("Creating KubeVirt VM #{vm_name} for #{host.name}")
      @kubevirt_helper.create_vm(vm_spec)
      @logger.info("Created KubeVirt VM #{vm_name}")
    end

    ##
    # Create a secret holding the cloud-init data
    # @param [Host] host The host configuration
    # @param [String] cloud_init_data Base64 encoded cloud-init data
    # @return [String] The name of the created secret
    def create_cloud_init_secret(host, cloud_init_data)
      raise 'Cloud-init data must be provided' unless cloud_init_data

      secret_name = "#{host['vm_name']}-cloud-init"
      @logger.debug("Creating cloud-init secret #{secret_name} in namespace #{@namespace}")

      secret_spec = {
        'apiVersion' => 'v1',
        'kind' => 'Secret',
        'metadata' => {
          'name' => secret_name,
          'namespace' => @namespace,
          'labels' => get_labels(host),
        },
        'type' => 'Opaque',
        'data' => {
          'userdata' => Base64.strict_encode64(cloud_init_data),
        },
      }

      @kubevirt_helper.create_secret(secret_spec)
      @logger.info("Created cloud-init secret #{secret_name} in namespace #{@namespace}")
      secret_name
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
      # It looks like the ssh-key is being wrapped to a new line by default, so we need to ensure it is properly formatted
      cloud_init_yaml = Psych.dump(cloud_init, line_width: -1)
      cloud_init_yaml.gsub!(/^---\n/, '') # Remove YAML document header
      "#cloud-config\n#{cloud_init_yaml}"
      # Base64.strict_encode64("#cloud-config\n#{cloud_init_yaml}").strip
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

    def get_labels(host)
      {
        'beaker/test-group' => @test_group_identifier,
        'beaker/host' => host.respond_to?(:name) ? host.name : host['name'],
      }
    end

    def disk_bus(host)
      # Determine the disk bus type based on host configuration
      if host['disable_virtio']
        'sata'
      else
        'virtio'
      end
    end

    def eth_model(host)
      # Determine the network model based on host configuration
      if host['disable_virtio']
        'e1000'
      else
        'virtio'
      end
    end

    ##
    # Generate the hardware devices specification for the VM
    # @param [Host] host The host configuration
    # @return [Hash] Hardware devices specification
    def generate_hardware_spec(host)
      {
        'disks' => [
          {
            'name' => 'rootdisk',
            'disk' => {
              'bus' => disk_bus(host),
            },
          },
          {
            'name' => 'configdisk',
            'disk' => {
              'bus' => disk_bus(host),
            },
          },
        ],
        'interfaces' => [
          {
            'name' => 'default',
            'bridge' => {},
            'model' => eth_model(host),
          },
        ],
      }
    end

    ##
    # Generate VM specification for KubeVirt
    # @param [Host] host The host configuration
    # @param [String] vm_name The VM name
    # @param [String] cloud_init_secret Base64 encoded cloud-init data
    # @return [Hash] VM specification
    def generate_vm_spec(host, vm_name, cloud_init_secret)
      cpu = host['cpu'] || @options[:cpu] || '1'
      memory = host['memory'] || @options[:memory] || '2Gi'
      # If the memory is a plain number, assume MiB
      memory = "#{memory}Mi" if /^\d+$/.match?(memory)
      vm_image = host['vm_image'] || @options[:vm_image]
      # TODO: Check this logic, it might be incorrect
      host_name = host.respond_to?(:name) ? host.name : host['name']

      raise 'vm_image must be specified' unless vm_image

      {
        'apiVersion' => 'kubevirt.io/v1',
        'kind' => 'VirtualMachine',
        'metadata' => {
          'name' => vm_name,
          'namespace' => @namespace,
          'labels' => get_labels(host),
        },
        'spec' => {
          'running' => true,
          'dataVolumeTemplates' => generate_root_volume_dvtemplate(vm_image, host),
          'template' => {
            'metadata' => {
              'labels' => get_labels(host).merge({
                                                   'kubevirt.io/vm' => vm_name,
                                                 }),
            },
            'spec' => {
              'domain' => {
                'cpu' => {
                  'cores' => cpu.to_i,
                  'sockets' => 1,
                  'threads' => 1,
                },
                'memory' => {
                  'guest' => memory.to_s,
                },
                'resources' => {
                  'limits' => {
                    'cpu' => cpu.to_s,
                    'memory' => memory.to_s,
                  },
                  'requests' => {
                    'cpu' => '125m',
                    'memory' => '1Gi',
                  },
                },
                'devices' => generate_hardware_spec(host),
                'features' => {
                  'acpi' => {},
                  # Enable SMM (System Management Mode) for secure boot
                  'smm' => {
                    'enabled' => true,
                  },
                },
                # Set to UEFI boot
                'firmware' => {
                  'bootloader' => {
                    'efi' => {},
                  },
                },
                'input' => {
                  'bus' => 'usb',
                  'type' => 'tablet',
                  'name' => 'tablet',
                },
              },
              'hostname' => host_name,
              'networks' => generate_networks_spec(host),
              'volumes' => [
                generate_root_volume_spec(vm_image, host),
                {
                  'name' => 'configdisk',
                  'cloudInitNoCloud' => {
                    'networkDataSecretRef' => {
                      'name' => cloud_init_secret,
                    },
                    'secretRef' => {
                      'name' => cloud_init_secret,
                    },
                  },
                },
              ],
            },
          },
        },
      }
    end

    ##
    # Generate networks specification for the VM
    # @param [Host] host The host configuration
    # @return [Array] Networks specification
    def generate_networks_spec(host)
      if host['network_mode'] == 'multus'
        # Multus network configuration
        multus_networks = host['networks'] || []
        multus_networks.map do |net|
          {
            'name' => net['name'],
            'multus' => {
              'networkName' => net['multus_network_name'],
            },
          }
        end
      else
        # Default network configuration
        [{
          'name' => 'default',
          'pod' => {},
        }]
      end
    end

    ##
    # Generate a DataVolume Template for the root disk
    # @param [String] vm_image The VM image specification
    # @param [Host] host The host configuration
    # @return [Array] DataVolumeTemplate specifications
    def generate_root_volume_dvtemplate(vm_image, host)
      return nil unless vm_image.start_with?('http://', 'https://')

      # Use the dv_name from the current host, not the last one in the array
      dv_name = host['dv_name']

      [
        {
          'metadata' => {
            'name' => dv_name,
            'labels' => get_labels(host),
          },
          'spec' => {
            'storage' => {
              'accessModes' => ['ReadWriteOnce'], # NOTE: This keeps the VM from being live migrated
              'resources' => {
                'requests' => {
                  'storage' => host['disk_size'].to_s || '10Gi', # Default size, can be overridden
                },
              },
            },
            'source' => {
              'http' => {
                'url' => vm_image,
              },
            },
          },
        },
      ]
    end

    ##
    # Generate root volume specification based on image type
    # @param [String] vm_image The VM image specification
    # @param [Host] host The host configuration
    # @return [Hash] Volume specification
    def generate_root_volume_spec(vm_image, host)
      if vm_image.start_with?('http://', 'https://')
        # DataVolume URL
        # Use the dv_name from the current host, not the last one in the array
        dv_name = host['dv_name']

        {
          'name' => 'rootdisk',
          'dataVolume' => {
            'name' => dv_name,
          },
        }
      elsif vm_image.start_with?('docker://', 'oci://')
        # Container image
        # KubeVirt supports container images as root disks
        # but we need to ensure the image is available in the cluster
        {
          'name' => 'rootdisk',
          'containerDisk' => {
            'image' => vm_image.sub(%r{^(docker|oci)://}, ''), # Remove protocol prefix
          },
        }
      else
        # Assume it's a PVC namez
        vm_image = vm_image.sub(%r{^pvc://}, '') if vm_image.start_with?('pvc://')
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
      begin
        Timeout.timeout(timeout) do
          # Wait for the VM to be created and running
          loop do
            vmi = @kubevirt_helper.get_vmi(vm_name)
            if vmi && vmi.dig('status', 'phase') == 'Running'
              @logger.debug("VM #{vm_name} is running")
              break
            end
            sleep SLEEPWAIT
          end
        end
      rescue Timeout::Error
        @logger.error("Timeout waiting for VM #{vm_name} to be ready")
        raise
      end
    end

    ##
    # Setup networking for the VM
    # @param [Host] host The host to setup networking for
    def setup_networking(host)
      network_mode = host['network_mode'] || 'port-forward'

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
      require 'beaker/hypervisor/port_forward'
      vm_name = host['vm_name']

      local_port = find_free_port

      host['ip'] = '127.0.0.1' # Port forwarding will use localhost
      host['port'] = local_port # Default SSH port
      host['ssh'] ||= {}
      host['ssh']['port'] = local_port

      @logger.debug("Setting up port-forward for VM #{vm_name} on port #{local_port}")

      # TODO: This is a placeholder for the actual port on the VM
      host['port_forwarder'] = @kubevirt_helper.setup_port_forward(vm_name, 22, local_port)

      @logger.info("Port forward setup for VM #{vm_name} on localhost:#{local_port}")
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
      node_ip = @kubevirt_helper.node_ip

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

        # return iface['ipAddress'] if iface['ipAddress'] && iface['ipAddress'].empty? == false
        external_interface = interfaces.find { |iface| iface['name'] != 'default' }
        return external_interface['ipAddress'] if external_interface && external_interface['ipAddress']

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

    ##
    # Sanitize a string to make it RFC 1035 DNS label compliant
    # - Lowercase
    # - Only alphanumeric characters and hyphens
    # - Start with a letter
    # - End with an alphanumeric character
    # - Maximum length of 63 characters
    # @param [String] name The string to sanitize
    # @return [String] RFC 1035 compliant string
    def sanitize_k8s_name(name)
      # Remove invalid characters, replace with hyphens
      sanitized = name.downcase.gsub(/[^a-z0-9-]/, '-')

      # Ensure it starts with a letter
      sanitized = "x#{sanitized}" unless /[a-z]/.match?(sanitized[0])

      # Ensure it doesn't end with a hyphen
      sanitized = "#{sanitized}0" if sanitized[-1] == '-'

      # Ensure it's not too long (max 63 chars for DNS label)
      sanitized = sanitized[0..62] if sanitized.length > 63

      sanitized
    end
  end
end
