# frozen_string_literal: true

RSpec.describe Beaker::KubeVirt do
  let(:options) do
    {
      logger: double('logger').as_null_object,
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

  let(:kubevirt_helper) { instance_double('Beaker::KubeVirtHelper') }

  before do
    allow(Beaker::KubeVirtHelper).to receive(:new).and_return(kubevirt_helper)
    allow(kubevirt_helper).to receive(:namespace).and_return('beaker-test')
  end

  describe '#initialize' do
    it 'creates a KubeVirt hypervisor instance' do
      hypervisor = described_class.new(hosts, options)

      expect(hypervisor).to be_instance_of(described_class)
      expect(hypervisor.instance_variable_get(:@hosts)).to eq(hosts)
      expect(hypervisor.instance_variable_get(:@options)).to eq(options)
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
      allow(hypervisor).to receive(:setup_ssh_access)
    end

    it 'provisions all hosts' do
      expect(hypervisor).to receive(:create_vm).with(hosts[0])
      expect(hypervisor).to receive(:wait_for_vm_ready).with(hosts[0])
      expect(hypervisor).to receive(:setup_ssh_access).with(hosts[0])

      hypervisor.provision
    end
  end

  describe '#cleanup' do
    let(:hypervisor) { described_class.new(hosts, options) }

    before do
      hosts[0]['vm_name'] = 'test-vm-name'
    end

    it 'deletes all VMs' do
      expect(kubevirt_helper).to receive(:delete_vm).with('test-vm-name')

      hypervisor.cleanup
    end
  end

  describe '#generate_vm_spec' do
    let(:hypervisor) { described_class.new(hosts, options) }
    let(:host) { hosts[0] }
    let(:vm_name) { 'test-vm' }
    let(:cloud_init_data) { 'base64-encoded-cloud-init' }

    it 'generates a valid VM specification' do
      vm_spec = hypervisor.send(:generate_vm_spec, host, vm_name, cloud_init_data)

      expect(vm_spec['apiVersion']).to eq('kubevirt.io/v1')
      expect(vm_spec['kind']).to eq('VirtualMachine')
      expect(vm_spec['metadata']['name']).to eq(vm_name)
      expect(vm_spec['metadata']['namespace']).to eq('beaker-test')
      expect(vm_spec['spec']['running']).to be true
    end

    it 'includes cloud-init configuration' do
      vm_spec = hypervisor.send(:generate_vm_spec, host, vm_name, cloud_init_data)

      volumes = vm_spec.dig('spec', 'template', 'spec', 'volumes')
      cloud_init_volume = volumes.find { |v| v['name'] == 'cloudinitdisk' }

      expect(cloud_init_volume).not_to be_nil
      expect(cloud_init_volume.dig('cloudInitNoCloud', 'userData')).to eq(cloud_init_data)
    end
  end

  describe '#generate_cloud_init' do
    let(:hypervisor) { described_class.new(hosts, options) }
    let(:host) { { 'name' => 'test-host', 'user' => 'testuser' } }

    it 'generates base64-encoded cloud-init data' do
      allow(hypervisor).to receive(:find_ssh_public_key).and_return('ssh-rsa test-key')

      cloud_init_data = hypervisor.send(:generate_cloud_init, host)
      decoded = Base64.strict_decode64(cloud_init_data)

      expect(decoded).to include('#cloud-config')
      expect(decoded).to include('testuser')
      expect(decoded).to include('ssh-rsa test-key')
    end
  end
end
