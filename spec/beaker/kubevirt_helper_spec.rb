# frozen_string_literal: true

RSpec.describe Beaker::KubeVirtHelper do
  let(:options) do
    {
      logger: double('logger').as_null_object,
      kubeconfig: '/tmp/test-kubeconfig',
      namespace: 'test-namespace',
    }
  end

  let(:mock_config) do
    {
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

  before do
    allow(File).to receive(:exist?).with('/tmp/test-kubeconfig').and_return(true)
    allow(File).to receive(:read).with('/tmp/test-kubeconfig').and_return(mock_config.to_yaml)
    allow(YAML).to receive(:safe_load).and_return(mock_config)
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
  end

  describe '#load_kubeconfig' do
    let(:helper) { described_class.new(options) }

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
end
