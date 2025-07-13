# frozen_string_literal: true

require 'kubeclient'
require 'yaml'
require 'tempfile'

module Beaker
  # Helper class for KubeVirt operations
  class KubeVirtHelper
    attr_reader :namespace, :options

    def initialize(options)
      @options = options
      @kubeconfig_path = options[:kubeconfig] || ENV['KUBECONFIG'] || File.join(Dir.home, '.kube', 'config')
      @kubecontext = options[:kubecontext] || ENV.fetch('KUBECONTEXT', nil)
      @logger = options[:logger]

      setup_kubernetes_client
      setup_kubevirt_client
    end

    ##
    # Create a virtual machine
    # @param [Hash] vm_spec The VM specification
    def create_vm(vm_spec)
      # Convert all keys to symbols recursively
      vm_spec_sym = symbolize_keys(vm_spec)
      @kubevirt_client.create_virtual_machine(vm_spec_sym)
    end

    ##
    # Get a virtual machine
    # @param [String] vm_name The VM name
    # @return [Hash] VM object
    def get_vm(vm_name, namespace)
      @kubevirt_client.get_virtual_machine(vm_name, namespace)
    rescue Kubeclient::ResourceNotFoundError
      nil
    end

    ##
    # Get a virtual machine instance
    # @param [String] vmi_name The VMI name
    # @return [Hash] VMI object
    def get_vmi(vmi_name, namespace)
      @kubevirt_client.get_virtual_machine_instance(vmi_name, namespace)
    rescue Kubeclient::ResourceNotFoundError
      nil
    end

    ##
    # Delete a virtual machine
    # @param [String] vm_name The VM name
    def delete_vm(vm_name, namespace)
      begin
        @kubevirt_client.delete_virtual_machine(vm_name, namespace)
        @logger.debug("Deleted VM #{vm_name}")
      rescue Kubeclient::ResourceNotFoundError
        @logger.debug("VM #{vm_name} not found during deletion")
      end

      # Also clean up any associated services
      cleanup_services(vm_name)
    end

    ##
    # Setup port forwarding for a VM
    # @param [String] vm_name The VM name
    # @param [Integer] vm_port The VM port to forward
    # @param [Integer] local_port The local port to forward to
    # @return [Process] The port-forward process
    def setup_port_forward(vm_name, vm_port, local_port, namespace)
      vmi_name = vm_name # VMI usually has the same name as VM

      cmd = [
        'kubectl',
        '--kubeconfig', @kubeconfig_path,
        '--namespace', namespace,
        'port-forward',
        "vmi/#{vmi_name}",
        "#{local_port}:#{vm_port}",
      ]

      cmd += ['--context', @kubecontext] if @kubecontext

      @logger.debug("Starting port-forward: #{cmd.join(' ')}")
      Process.spawn(*cmd)
    end

    ##
    # Create a NodePort service for SSH access
    # @param [String] vm_name The VM name
    # @param [String] service_name The service name
    # @return [Hash] Service object
    def create_nodeport_service(vm_name, service_name, namespace)
      service_spec = {
        'apiVersion' => 'v1',
        'kind' => 'Service',
        'metadata' => {
          'name' => service_name,
          'namespace' => namespace,
          'labels' => {
            'beaker/vm' => vm_name,
          },
        },
        'spec' => {
          'type' => 'NodePort',
          'selector' => {
            'kubevirt.io/vm' => vm_name,
          },
          'ports' => [
            {
              'name' => 'ssh',
              'port' => 22,
              'targetPort' => 22,
              'protocol' => 'TCP',
            },
          ],
        },
      }

      service_spec_sym = symbolize_keys(service_spec)
      @k8s_client.create_service(service_spec_sym)
    end

    ##
    # Get a cluster node IP address
    # @return [String] Node IP address
    def get_node_ip
      nodes = @k8s_client.get_nodes
      node = nodes.first

      # Try to get external IP first, fallback to internal IP
      addresses = node.dig('status', 'addresses') || []
      external_ip = addresses.find { |addr| addr['type'] == 'ExternalIP' }
      internal_ip = addresses.find { |addr| addr['type'] == 'InternalIP' }

      if external_ip
        external_ip['address']
      elsif internal_ip
        internal_ip['address']
      else
        raise 'Could not determine node IP address'
      end
    end

    ##
    # Get service by name
    # @param [String] service_name The service name
    # @return [Hash] Service object
    def get_service(service_name)
      @k8s_client.get_service(service_name, @namespace)
    rescue Kubeclient::ResourceNotFoundError
      nil
    end

    private

    ##
    # Setup Kubernetes API client
    def setup_kubernetes_client
      config = Kubeclient::Config.read(@kubeconfig_path)
      context_config = config.context(@kubecontext)
      @k8s_client = Kubeclient::Client.new(
        context_config.api_endpoint,
        'v1',
        ssl_options: context_config.ssl_options,
        auth_options: context_config.auth_options,
      )
    end

    ##
    # Setup KubeVirt API client
    def setup_kubevirt_client
      config = Kubeclient::Config.read(@kubeconfig_path)
      context_config = config.context(@kubecontext)
      @kubevirt_client = Kubeclient::Client.new(
        context_config.api_endpoint + '/apis/kubevirt.io',
        'v1',
        ssl_options: context_config.ssl_options,
        auth_options: context_config.auth_options,
      )
    end

    ##
    # Load kubeconfig file
    # @return [Hash] Parsed kubeconfig
    def load_kubeconfig
      raise "Kubeconfig file not found: #{@kubeconfig_path}" unless File.exist?(@kubeconfig_path)

      YAML.safe_load(File.read(@kubeconfig_path))
    end

    ##
    # Get context configuration from kubeconfig
    # @param [Hash] config The kubeconfig
    # @return [Hash] Context configuration
    def get_context_config(config)
      current_context = @kubecontext || config['current-context']
      raise 'No current context specified' unless current_context

      context = config['contexts'].find { |ctx| ctx['name'] == current_context }
      raise "Context '#{current_context}' not found" unless context

      cluster_name = context.dig('context', 'cluster')
      user_name = context.dig('context', 'user')

      cluster = config['clusters'].find { |c| c['name'] == cluster_name }
      user = config['users'].find { |u| u['name'] == user_name }

      raise "Cluster '#{cluster_name}' not found" unless cluster
      raise "User '#{user_name}' not found" unless user

      {
        'cluster' => cluster['cluster'],
        'user' => user['user'],
        'namespace' => context.dig('context', 'namespace') || @namespace,
      }
    end

    ##
    # Write content to a temporary file
    # @param [String] prefix File prefix
    # @param [String] content File content
    # @return [String] Path to temporary file
    def write_temp_file(prefix, content)
      file = Tempfile.new(prefix)
      file.write(content)
      file.close
      file.path
    end

    ##
    # Clean up services associated with a VM
    # @param [String] vm_name The VM name
    def cleanup_services(vm_name)
      services = @k8s_client.get_services(namespace: @namespace,
                                          label_selector: "beaker/vm=#{vm_name}")
      services.each do |service|
        @k8s_client.delete_service(service.metadata.name, @namespace)
        @logger.debug("Deleted service #{service.metadata.name}")
      end
    rescue StandardError => e
      @logger.debug("Error cleaning up services for VM #{vm_name}: #{e}")
    end

    ##
    # Recursively convert hash keys to symbols
    def symbolize_keys(obj)
      case obj
      when Hash
        obj.each_with_object({}) do |(k, v), memo|
          memo[k.to_sym] = symbolize_keys(v)
        end
      when Array
        obj.map { |v| symbolize_keys(v) }
      else
        obj
      end
    end
  end
end
