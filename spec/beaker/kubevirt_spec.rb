# frozen_string_literal: true

RSpec.describe Beaker::Kubevirt do
  let(:options) do
    {
      logger: instance_double(Logger).as_null_object,
      kubeconfig: '/tmp/kubeconfig',
      namespace: 'beaker-test',
      vm_image: 'quay.io/kubevirt/fedora-cloud-container-disk-demo',
      ssh_key: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...',
    }
  end

  let(:hosts) do
    [
      {
        'name' => 'test-host',
        'platform' => 'el-8-x86_64',
        'hypervisor' => 'kubevirt',
      },
    ]
  end

  let(:kubevirt_helper) { instance_double(Beaker::KubevirtHelper) }

  before do
    allow(Beaker::KubevirtHelper).to receive(:new).and_return(kubevirt_helper)
    allow(kubevirt_helper).to receive(:namespace).and_return('beaker-test')
  end

  describe '#initialize' do
    let(:hypervisor) { described_class.new(hosts, options) }

    it 'is a Kubevirt hypervisor' do
      expect(hypervisor).to be_instance_of(described_class)
    end

    it 'sets the hosts' do
      expect(hypervisor.instance_variable_get(:@hosts)).to eq(hosts)
    end

    it 'sets the options' do
      expect(hypervisor.instance_variable_get(:@options)).to eq(options)
    end

    it 'sets the namespace' do
      expect(hypervisor.instance_variable_get(:@namespace)).to eq('beaker-test')
    end

    it 'requires namespace to be specified' do
      options_without_namespace = options.dup
      options_without_namespace.delete(:namespace)

      expect do
        described_class.new(hosts, options_without_namespace)
      end.to raise_error('Namespace must be specified in options')
    end

    it 'generates a test group identifier' do
      hypervisor = described_class.new(hosts, options)
      test_group_id = hypervisor.instance_variable_get(:@test_group_identifier)

      expect(test_group_id).to match(/^beaker-[a-f0-9]{8}$/)
    end
  end

  describe '#provision' do
    let(:hypervisor) { described_class.new(hosts, options) }

    before do
      allow(hypervisor).to receive(:create_vm)
      allow(hypervisor).to receive(:wait_for_vm_ready)
    end

    context 'when provisioning' do
      before do
        allow(hypervisor).to receive_messages(create_vm: true, wait_for_vm_ready: true, setup_networking: true, setup_port_forward: true)
        hypervisor.provision
      end

      it 'creates the vm' do
        expect(hypervisor).to have_received(:create_vm).with(hosts[0])
      end

      it 'waits for the vm to be ready' do
        expect(hypervisor).to have_received(:wait_for_vm_ready).with(hosts[0])
      end

      it 'sets up networking' do
        expect(hypervisor).to have_received(:setup_networking).with(hosts[0])
      end
    end
  end

  describe '#cleanup' do
    context 'when cleaning up without port forwards' do
      let(:hypervisor) { described_class.new(hosts, options) }

      before do
        allow(kubevirt_helper).to receive(:cleanup_vms)
        allow(kubevirt_helper).to receive(:cleanup_secrets)
        allow(kubevirt_helper).to receive(:cleanup_services)
        hypervisor.cleanup
      end

      it 'cleans up vms' do
        expect(kubevirt_helper).to have_received(:cleanup_vms).with(anything)
      end

      it 'cleans up secrets' do
        expect(kubevirt_helper).to have_received(:cleanup_secrets).with(anything)
      end

      it 'cleans up services' do
        expect(kubevirt_helper).to have_received(:cleanup_services).with(anything)
      end
    end

    context 'when running a port forwarder' do
      require 'beaker/hypervisor/port_forward'

      let(:hosts_with_port_forward) do
        [
          {
            'name' => 'test-host',
            'platform' => 'el-8-x86_64',
            'hypervisor' => 'kubevirt',
            'port_forwarder' => instance_double(KubeVirtPortForwarder),
          },
        ]
      end
      let(:hypervisor_with_port_forward) { described_class.new(hosts_with_port_forward, options) }

      before do
        forwarder = hosts_with_port_forward[0]['port_forwarder']

        allow(forwarder).to receive(:stop)
        allow(forwarder).to receive(:state).and_return(:running, :running, :stopped)
        allow(kubevirt_helper).to receive(:cleanup_vms)
        allow(kubevirt_helper).to receive(:cleanup_secrets)
        allow(kubevirt_helper).to receive(:cleanup_services)
        hypervisor_with_port_forward.cleanup(delay: 0.25)
      end

      it 'cleans up port forwarders' do
        forwarder = hosts_with_port_forward[0]['port_forwarder']

        expect(forwarder).to have_received(:stop)
      end
    end

    context 'when a stopped port forwarder' do
      require 'beaker/hypervisor/port_forward'

      let(:hosts_with_port_forward) do
        [
          {
            'name' => 'test-host',
            'platform' => 'el-8-x86_64',
            'hypervisor' => 'kubevirt',
            'port_forwarder' => instance_double(KubeVirtPortForwarder),
          },
        ]
      end
      let(:hypervisor_with_port_forward) { described_class.new(hosts_with_port_forward, options) }

      before do
        forwarder = hosts_with_port_forward[0]['port_forwarder']

        allow(forwarder).to receive(:stop)
        allow(forwarder).to receive(:state).and_return(:stopped)
        allow(kubevirt_helper).to receive(:cleanup_vms)
        allow(kubevirt_helper).to receive(:cleanup_secrets)
        allow(kubevirt_helper).to receive(:cleanup_services)
        hypervisor_with_port_forward.cleanup
      end

      it 'cleans up port forwarders' do
        forwarder = hosts_with_port_forward[0]['port_forwarder']

        expect(forwarder).to have_received(:stop)
      end
    end

    context 'when unable to stop a port forwarder in time' do
      require 'beaker/hypervisor/port_forward'

      let(:hosts_with_port_forward) do
        [
          {
            'name' => 'test-host',
            'platform' => 'el-8-x86_64',
            'hypervisor' => 'kubevirt',
            'port_forwarder' => instance_double(KubeVirtPortForwarder),
          },
        ]
      end
      let(:hypervisor_with_port_forward) { described_class.new(hosts_with_port_forward, options) }

      before do
        forwarder = hosts_with_port_forward[0]['port_forwarder']

        allow(forwarder).to receive(:stop)
        allow(forwarder).to receive(:state).and_return(:running)
        allow(kubevirt_helper).to receive(:cleanup_vms)
        allow(kubevirt_helper).to receive(:cleanup_secrets)
        allow(kubevirt_helper).to receive(:cleanup_services)
      end

      it 'raises a timeout error' do
        expect do
          hypervisor_with_port_forward.cleanup(timeout: 0.25, delay: 0.5)
        end.to raise_error(Timeout::Error)
      end
    end
  end

  describe '#generate_vm_spec' do
    let(:vm_spec_args) do
      {
        hypervisor: described_class.new(hosts, options),
        host: hosts[0],
        vm_name: 'test-vm',
        cloud_init_data: 'base64-encoded-cloud-init',
      }
    end
    let(:vm_spec) { vm_spec_args[:hypervisor].send(:generate_vm_spec, vm_spec_args[:host], vm_spec_args[:vm_name], vm_spec_args[:cloud_init_data]) }

    it 'has the correct apiVersion' do
      expect(vm_spec['apiVersion']).to eq('kubevirt.io/v1')
    end

    it 'has the correct kind' do
      expect(vm_spec['kind']).to eq('VirtualMachine')
    end

    it 'has the correct name' do
      expect(vm_spec['metadata']['name']).to eq(vm_spec_args[:vm_name])
    end

    it 'has the correct namespace' do
      expect(vm_spec['metadata']['namespace']).to eq('beaker-test')
    end

    it 'is running' do
      expect(vm_spec['spec']['running']).to be true
    end

    it 'includes cloud-init configuration' do
      volumes = vm_spec.dig('spec', 'template', 'spec', 'volumes')
      cloud_init_volume = volumes.find { |v| v['name'] == 'cidata' }

      expect(cloud_init_volume).not_to be_nil
    end

    it 'references the cloud-init secret' do
      volumes = vm_spec.dig('spec', 'template', 'spec', 'volumes')
      cloud_init_volume = volumes.find { |v| v['name'] == 'cidata' }
      expect(cloud_init_volume.dig('cloudInitNoCloud', 'secretRef', 'name')).to eq(vm_spec_args[:cloud_init_data])
    end
  end

  describe '#generate_cloud_init' do
    let(:hypervisor) { described_class.new(hosts, options) }

    before do
      allow(hypervisor).to receive(:find_ssh_public_key).and_return('ssh-rsa test-key')
    end

    context 'when using Linux hosts' do
      let(:host) { { 'name' => 'test-host', 'user' => 'testuser', platform: 'debian-11-x86_64' } }

      it 'is a cloud-config' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('#cloud-config')
      end

      it 'includes the user' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('testuser')
      end

      it 'includes the ssh key' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('ssh-rsa test-key')
      end

      it 'includes sudo configuration' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('sudo: ALL=(ALL) NOPASSWD:ALL')
      end

      it 'includes bash shell' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('shell: "/bin/bash"')
      end

      it 'includes ssh_pwauth false' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('ssh_pwauth: false')
      end

      it 'includes disable_root false' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('disable_root: false')
      end

      it 'includes chpasswd configuration' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        aggregate_failures do
          expect(cloud_init_data).to include('chpasswd:')
          expect(cloud_init_data).to include('expire: false')
        end
      end
    end

    context 'when using Windows hosts' do
      let(:host) { { 'name' => 'win-host', 'user' => 'winuser', platform: 'windows-2019-x86_64' } }

      it 'is a cloud-config' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('#cloud-config')
      end

      it 'includes the user' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('winuser')
      end

      it 'includes the ssh key' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('ssh-rsa test-key')
      end

      it 'includes primary_group Administrators' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('primary_group: Administrators')
      end

      it 'includes powershell shell' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).to include('shell: powershell.exe')
      end

      it 'does not include sudo configuration' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).not_to include('sudo:')
      end

      it 'does not include ssh_pwauth' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).not_to include('ssh_pwauth:')
      end

      it 'does not include disable_root' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).not_to include('disable_root:')
      end

      it 'does not include chpasswd' do
        cloud_init_data = hypervisor.send(:generate_cloud_init, host)
        expect(cloud_init_data).not_to include('chpasswd:')
      end
    end
  end

  describe '#find_ssh_public_key' do
    let(:hypervisor) { described_class.new(hosts, options) }

    context 'when ssh_key is provided' do
      it 'returns the provided ssh key' do
        expect(hypervisor.send(:find_ssh_public_key)).to eq(options[:ssh_key])
      end

      it 'returns the contents of the file if it exists' do
        allow(File).to receive(:exist?).with(options[:ssh_key]).and_return(true)
        allow(File).to receive(:read).with(options[:ssh_key]).and_return('ssh-rsa test-key')

        expect(hypervisor.send(:find_ssh_public_key)).to eq('ssh-rsa test-key')
      end

      it 'returns the provided content of the key when it does not exist' do
        allow(File).to receive(:exist?).with(options[:ssh_key]).and_return(false)

        expect(hypervisor.send(:find_ssh_public_key)).to eq(options[:ssh_key])
      end
    end

    context 'when the key is not found' do
      let(:options) { super().dup.tap { |opts| opts.delete(:ssh_key) } }

      before do
        allow(File).to receive(:exist?).and_return(false)
      end

      it 'raises an error' do
        expect { hypervisor.send(:find_ssh_public_key) }.to raise_error(RuntimeError, /No matching SSH key pair found/)
      end
    end

    context 'when the id_ecdsa key is found' do
      let(:options) { super().dup.tap { |opts| opts.delete(:ssh_key) } }

      before do
        allow(File).to receive(:exist?).and_return(false)
        ecdsa_private_key_path = File.join(Dir.home, '.ssh', 'id_ecdsa')
        ecdsa_key_path = File.join(Dir.home, '.ssh', 'id_ecdsa.pub')
        allow(File).to receive(:exist?).with(ecdsa_private_key_path).and_return(true)
        allow(File).to receive(:exist?).with(ecdsa_key_path).and_return(true)
        allow(File).to receive(:read).with(ecdsa_key_path).and_return('ssh-ed25519 test-key')
      end

      it 'returns the id_ecdsa key' do
        expect(hypervisor.send(:find_ssh_public_key)).to eq('ssh-ed25519 test-key')
      end
    end
  end

  describe '#find_ssh_key_pair' do
    let(:hypervisor) { described_class.new(hosts, options) }

    context 'when ssh_key is provided as a file path' do
      let(:options) do
        super().merge(ssh_key: '/home/user/.ssh/id_test.pub')
      end

      it 'returns the public key content and matching private key path' do
        allow(File).to receive(:exist?).with('/home/user/.ssh/id_test.pub').and_return(true)
        allow(File).to receive(:exist?).with('/home/user/.ssh/id_test').and_return(true)
        allow(File).to receive(:read).with('/home/user/.ssh/id_test.pub').and_return('ssh-rsa test-key')
        result = hypervisor.send(:find_ssh_key_pair)
        aggregate_failures do
          expect(result[:public_key]).to eq('ssh-rsa test-key')
          expect(result[:private_key_path]).to eq('/home/user/.ssh/id_test')
        end
      end

      it 'raises an error when private key does not exist' do
        allow(File).to receive(:exist?).with('/home/user/.ssh/id_test.pub').and_return(true)
        allow(File).to receive(:read).with('/home/user/.ssh/id_test.pub').and_return('ssh-rsa test-key')
        allow(File).to receive(:exist?).with('/home/user/.ssh/id_test').and_return(false)

        expect { hypervisor.send(:find_ssh_key_pair) }.to raise_error(/Private key not found/)
      end
    end

    context 'when ssh_key is provided as content' do
      let(:options) do
        super().merge(ssh_key: 'ssh-rsa direct-content')
      end

      it 'returns the public key content with nil private key path' do
        allow(File).to receive(:exist?).with('ssh-rsa direct-content').and_return(false)
        result = hypervisor.send(:find_ssh_key_pair)
        aggregate_failures do
          expect(result[:public_key]).to eq('ssh-rsa direct-content')
          expect(result[:private_key_path]).to be_nil
        end
      end
    end

    context 'when searching for default keys' do
      let(:options) { super().dup.tap { |opts| opts.delete(:ssh_key) } }

      it 'finds matching ed25519 key pair' do
        ed25519_path = File.join(Dir.home, '.ssh', 'id_ed25519')
        allow(File).to receive(:exist?).and_return(false)
        allow(File).to receive(:exist?).with(ed25519_path).and_return(true)
        allow(File).to receive(:exist?).with("#{ed25519_path}.pub").and_return(true)
        allow(File).to receive(:read).with("#{ed25519_path}.pub").and_return('ssh-ed25519 test-key')
        result = hypervisor.send(:find_ssh_key_pair)
        aggregate_failures do
          expect(result[:public_key]).to eq('ssh-ed25519 test-key')
          expect(result[:private_key_path]).to eq(ed25519_path)
        end
      end

      it 'finds matching rsa key pair when ed25519 not available' do
        rsa_path = File.join(Dir.home, '.ssh', 'id_rsa')
        allow(File).to receive(:exist?).and_return(false)
        allow(File).to receive(:exist?).with(rsa_path).and_return(true)
        allow(File).to receive(:exist?).with("#{rsa_path}.pub").and_return(true)
        allow(File).to receive(:read).with("#{rsa_path}.pub").and_return('ssh-rsa test-key')
        result = hypervisor.send(:find_ssh_key_pair)
        aggregate_failures do
          expect(result[:public_key]).to eq('ssh-rsa test-key')
          expect(result[:private_key_path]).to eq(rsa_path)
        end
      end

      it 'raises an error when no matching key pairs found' do
        allow(File).to receive(:exist?).and_return(false)

        expect { hypervisor.send(:find_ssh_key_pair) }.to raise_error(/No matching SSH key pair found/)
      end
    end
  end

  describe '#configure_ssh_keys' do
    let(:hypervisor) { described_class.new(hosts, options) }
    let(:host) { hosts[0] }

    before do
      host['ssh'] = {}
    end

    context 'when private key path is available' do
      it 'configures the host ssh keys array' do
        key_pair = { public_key: 'ssh-rsa test-key', private_key_path: '/home/user/.ssh/id_rsa' }
        allow(hypervisor).to receive(:find_ssh_key_pair).and_return(key_pair)

        hypervisor.send(:configure_ssh_keys, host)
        expect(host['ssh']['keys']).to eq(['/home/user/.ssh/id_rsa'])
      end
    end

    context 'when private key path is not available' do
      it 'does not set the keys array' do
        key_pair = { public_key: 'ssh-rsa test-key', private_key_path: nil }
        allow(hypervisor).to receive(:find_ssh_key_pair).and_return(key_pair)

        hypervisor.send(:configure_ssh_keys, host)
        expect(host['ssh']['keys']).to be_nil
      end
    end
  end

  describe '#sanitize_k8s_name' do
    let(:hypervisor) { described_class.new(hosts, options) }

    it 'sanitizes a valid name' do
      expect(hypervisor.send(:sanitize_k8s_name, 'valid-name')).to eq('valid-name')
    end

    it 'sanitizes a name with invalid characters' do
      expect(hypervisor.send(:sanitize_k8s_name, 'invalid@name')).to eq('invalid-name')
    end

    it 'trims the name to 63 characters' do
      long_name = 'a' * 70
      expect(hypervisor.send(:sanitize_k8s_name, long_name).length).to eq(63)
    end

    it 'handles names that end in a hyphen' do
      expect(hypervisor.send(:sanitize_k8s_name, 'bad-sanitized-')).to eq('bad-sanitized-0')
    end

    it 'handles names that do not start with a letter' do
      expect(hypervisor.send(:sanitize_k8s_name, '1invalid-name')).to eq('x1invalid-name')
    end
  end
end
