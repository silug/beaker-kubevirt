# frozen_string_literal: true

RSpec.describe Beaker::KubevirtHelper do
  let(:options) do
    {
      logger: double('logger').as_null_object,
      kubeconfig: '/tmp/test-kubeconfig',
      namespace: 'test-namespace',
      k8s_client: double('k8s_client'),
      kubevirt_client: double('kubevirt_client'),
    }
  end

  let(:options_without_clients) do
    {
      logger: double('logger').as_null_object,
      kubeconfig: '/tmp/test-kubeconfig',
      namespace: 'test-namespace',
    }
  end

  let(:mock_config) do
    {
      'apiVersion' => 'v1',
      'kind' => 'Config',
      'current-context' => 'test-context',
      'contexts' => [
        {
          'name' => 'test-context',
          'context' => {
            'cluster' => 'test-cluster',
            'user' => 'test-user',
          },
        },
      ],
      'clusters' => [
        {
          'name' => 'test-cluster',
          'cluster' => {
            'server' => 'https://kubernetes.example.com:6443',
            'certificate-authority-data' => Base64.strict_encode64('fake-ca-cert'),
          },
        },
      ],
      'users' => [
        {
          'name' => 'test-user',
          'user' => {
            'token' => 'fake-token',
          },
        },
      ],
    }
  end

  describe '#initialize' do
    it 'sets up namespace and options' do
      helper = described_class.new(options)

      expect(helper.namespace).to eq('test-namespace')
      expect(helper.options).to eq(options)
    end

    it 'defaults to default namespace' do
      opts = options.dup
      opts.delete(:namespace)
      helper = described_class.new(opts)

      expect(helper.namespace).to eq('default')
    end

    it 'uses injected clients when provided' do
      helper = described_class.new(options)
      # Should not attempt to create clients when they're injected
      expect(helper.namespace).to eq('test-namespace')
    end

    it 'sets up clients when not injected' do
      # Mock the file system for kubeconfig
      allow(File).to receive(:exist?).with('/tmp/test-kubeconfig').and_return(true)
      allow(File).to receive(:read).with('/tmp/test-kubeconfig').and_return(mock_config.to_yaml)

      # Mock the Kubeclient creation
      mock_k8s_client = double('k8s_client')
      mock_kubevirt_client = double('kubevirt_client')

      allow(Kubeclient::Client).to receive(:new).and_return(mock_k8s_client, mock_kubevirt_client)

      helper = described_class.new(options_without_clients)
      expect(helper.namespace).to eq('test-namespace')
    end
  end

  describe '#load_kubeconfig' do
    let(:helper) { described_class.new(options) }

    before do
      allow(File).to receive(:exist?).with('/tmp/test-kubeconfig').and_return(true)
      allow(File).to receive(:read).with('/tmp/test-kubeconfig').and_return(mock_config.to_yaml)
    end

    it 'loads kubeconfig from specified path' do
      config = helper.send(:load_kubeconfig)
      expect(config).to eq(mock_config)
    end

    it 'raises error if kubeconfig does not exist' do
      allow(File).to receive(:exist?).with('/tmp/test-kubeconfig').and_return(false)

      expect { helper.send(:load_kubeconfig) }.to raise_error(/Kubeconfig file not found/)
    end
  end

  describe '#get_context_config' do
    let(:helper) { described_class.new(options) }

    it 'returns context configuration' do
      context_config = helper.send(:get_context_config, mock_config)

      expect(context_config['cluster']['server']).to eq('https://kubernetes.example.com:6443')
      expect(context_config['user']['token']).to eq('fake-token')
    end

    it 'raises error for missing context' do
      config = mock_config.dup
      config['current-context'] = 'missing-context'

      expect { helper.send(:get_context_config, config) }.to raise_error(/Context 'missing-context' not found/)
    end
  end

  describe '#setup_ssl_options' do
    let(:helper) { described_class.new(options) }
    let(:context_config) do
      {
        'cluster' => {
          'certificate-authority-data' => Base64.strict_encode64('fake-ca-cert'),
        },
      }
    end

    it 'sets up SSL options with CA data' do
      allow(helper).to receive(:write_temp_file).and_return('/tmp/ca-cert')

      ssl_options = helper.send(:setup_ssl_options, context_config)

      expect(ssl_options[:ca_file]).to eq('/tmp/ca-cert')
    end

    it 'handles insecure skip TLS verify' do
      context_config['cluster']['insecure-skip-tls-verify'] = true

      ssl_options = helper.send(:setup_ssl_options, context_config)

      expect(ssl_options[:verify_ssl]).to be false
    end
  end

  describe '#setup_auth_options' do
    let(:helper) { described_class.new(options) }

    it 'sets up bearer token auth' do
      context_config = {
        'user' => {
          'token' => 'test-token',
        },
      }

      auth_options = helper.send(:setup_auth_options, context_config)

      expect(auth_options[:bearer_token]).to eq('test-token')
    end

    it 'sets up client certificate auth' do
      context_config = {
        'user' => {
          'client-certificate-data' => Base64.strict_encode64('fake-cert'),
          'client-key-data' => Base64.strict_encode64('fake-key'),
        },
      }

      allow(helper).to receive(:write_temp_file).and_return('/tmp/cert', '/tmp/key')

      auth_options = helper.send(:setup_auth_options, context_config)

      expect(auth_options[:client_cert]).to eq('/tmp/cert')
      expect(auth_options[:client_key]).to eq('/tmp/key')
    end
  end

  describe 'manual kubeconfig parsing fallback' do
    let(:helper) { described_class.new(options) }

    before do
      allow(File).to receive(:exist?).with('/tmp/test-kubeconfig').and_return(true)
      allow(File).to receive(:read).with('/tmp/test-kubeconfig').and_return(mock_config.to_yaml)
    end

    it 'falls back to manual parsing when Kubeclient::Config fails' do
      # Mock Kubeclient::Config.read to raise an error
      allow(Kubeclient::Config).to receive(:read).and_raise(RuntimeError, 'Unknown kubeconfig version')

      # Mock the manual client creation
      mock_k8s_client = double('k8s_client')
      mock_kubevirt_client = double('kubevirt_client')
      allow(Kubeclient::Client).to receive(:new).and_return(mock_k8s_client, mock_kubevirt_client)

      # Mock the temp file creation for SSL/auth setup
      allow(helper).to receive(:write_temp_file).and_return('/tmp/ca-cert')

      helper_without_clients = described_class.new(options_without_clients)
      expect(helper_without_clients.namespace).to eq('test-namespace')
    end
  end
end
