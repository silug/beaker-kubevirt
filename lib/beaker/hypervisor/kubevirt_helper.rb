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
      @namespace = options[:namespace] || 'default'
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
      @kubevirt_client.create_virtual_machine(vm_spec)
    end

    ##
    # Get a virtual machine
    # @param [String] vm_name The VM name
    # @return [Hash] VM object
    def get_vm(vm_name)
      @kubevirt_client.get_virtual_machine(vm_name, @namespace)
    rescue Kubeclient::ResourceNotFoundError
      nil
    end

    ##
    # Get a virtual machine instance
    # @param [String] vmi_name The VMI name
    # @return [Hash] VMI object
    def get_vmi(vmi_name)
      @kubevirt_client.get_virtual_machine_instance(vmi_name, @namespace)
    rescue Kubeclient::ResourceNotFoundError
      nil
    end

    ##
    # Delete a virtual machine
    # @param [String] vm_name The VM name
    def delete_vm(vm_name)
      begin
        @kubevirt_client.delete_virtual_machine(vm_name, @namespace)
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
    def setup_port_forward(vm_name, vm_port, local_port)
      vmi_name = vm_name # VMI usually has the same name as VM

      cmd = [
        'kubectl',
        '--kubeconfig', @kubeconfig_path,
        '--namespace', @namespace,
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
    def create_nodeport_service(vm_name, service_name)
      service_spec = {
        'apiVersion' => 'v1',
        'kind' => 'Service',
        'metadata' => {
          'name' => service_name,
          'namespace' => @namespace,
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

      @k8s_client.create_service(service_spec)
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
      config = load_kubeconfig
      context_config = get_context_config(config)

      api_endpoint = context_config.dig('cluster', 'server')
      api_version = 'v1'

      ssl_options = setup_ssl_options(context_config)
      auth_options = setup_auth_options(context_config)

      @k8s_client = Kubeclient::Client.new(
        api_endpoint,
        api_version,
        ssl_options: ssl_options,
        auth_options: auth_options,
      )
    end

    ##
    # Setup KubeVirt API client
    def setup_kubevirt_client
      config = load_kubeconfig
      context_config = get_context_config(config)

      api_endpoint = context_config.dig('cluster', 'server')
      api_version = 'kubevirt.io/v1'

      ssl_options = setup_ssl_options(context_config)
      auth_options = setup_auth_options(context_config)

      @kubevirt_client = Kubeclient::Client.new(
        api_endpoint,
        api_version,
        ssl_options: ssl_options,
        auth_options: auth_options,
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
    # Setup SSL options for Kubeclient
    # @param [Hash] context_config The context configuration
    # @return [Hash] SSL options
    def setup_ssl_options(context_config)
      ssl_options = {}
      cluster_config = context_config['cluster']

      if cluster_config['certificate-authority-data']
        ca_cert = Base64.decode64(cluster_config['certificate-authority-data'])
        ssl_options[:ca_file] = write_temp_file('ca-cert', ca_cert)
      elsif cluster_config['certificate-authority']
        ssl_options[:ca_file] = cluster_config['certificate-authority']
      end

      ssl_options[:verify_ssl] = false if cluster_config['insecure-skip-tls-verify']

      ssl_options
    end

    ##
    # Setup authentication options for Kubeclient
    # @param [Hash] context_config The context configuration
    # @return [Hash] Auth options
    def setup_auth_options(context_config)
      auth_options = {}
      user_config = context_config['user']

      if user_config['token']
        auth_options[:bearer_token] = user_config['token']
      elsif user_config['tokenFile']
        auth_options[:bearer_token_file] = user_config['tokenFile']
      elsif user_config['client-certificate-data'] && user_config['client-key-data']
        client_cert = Base64.decode64(user_config['client-certificate-data'])
        client_key = Base64.decode64(user_config['client-key-data'])

        auth_options[:client_cert] = write_temp_file('client-cert', client_cert)
        auth_options[:client_key] = write_temp_file('client-key', client_key)
      elsif user_config['client-certificate'] && user_config['client-key']
        auth_options[:client_cert] = user_config['client-certificate']
        auth_options[:client_key] = user_config['client-key']
      end

      auth_options
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
  end
end
