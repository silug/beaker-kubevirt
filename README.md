# Beaker::KubeVirt

A Beaker hypervisor provider for [KubeVirt](https://kubevirt.io), enabling automated acceptance testing of Puppet code using virtual machines running inside Kubernetes clusters.

## Features

- Deploy VMs using KubeVirt's `VirtualMachine` objects
- Support for multiple image sources (PVC, ContainerDisk, DataVolume)
- Cloud-init configuration injection for user setup and SSH keys
- Multiple networking modes (port-forward, NodePort, Multus)
- Automatic VM lifecycle management (provision, test, cleanup)
- Integration with existing Beaker workflows

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'beaker-kubevirt'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install beaker-kubevirt
```

## Configuration

### Prerequisites

- A Kubernetes cluster with KubeVirt installed
- Valid kubeconfig file with cluster access
- SSH public key for VM access

### Beaker Host Configuration

Configure your Beaker hosts file to use the KubeVirt hypervisor:

```yaml
HOSTS:
  centos-vm:
    platform: el-8-x86_64
    hypervisor: kubevirt
    vm_image: quay.io/kubevirt/fedora-cloud-container-disk-demo
    network_mode: port-forward
    ssh_key: ~/.ssh/id_rsa.pub
    cpu: 2
    memory: 4Gi

CONFIG:
  # Global KubeVirt configuration
  kubeconfig: ~/.kube/config
  kubecontext: my-context  # optional
  namespace: beaker-tests  # required - namespace for all VMs
  ssh:
    password: beaker
    auth_methods: ['publickey', 'password']
```

### Configuration Options

| Option | Description | Required | Default | Location |
|--------|-------------|----------|---------|----------|
| `kubeconfig` | Path to kubeconfig file | Yes | `$KUBECONFIG` or `~/.kube/config` | CONFIG (global) |
| `kubecontext` | Kubernetes context to use | No | Current context | CONFIG (global) |
| `namespace` | Kubernetes namespace for VMs | **Yes** | `default` | **CONFIG (global)** |
| `vm_image` | VM image specification | Yes | - | HOSTS (per-host) |
| `network_mode` | Networking mode | No | `port-forward` | HOSTS (per-host) |
| `networks` | Custom network configuration | No | Auto-generated | HOSTS (per-host) |
| `ssh_key` | SSH public key path or content | Yes | Auto-detect from `~/.ssh/` | HOSTS (per-host) |
| `cpu` | CPU cores for VM | No | `1` | HOSTS (per-host) |
| `memory` | Memory for VM | No | `2Gi` | HOSTS (per-host) |
| `disk_size` | Size of the root disk | No | `10Gi` | HOSTS (per-host) |
| `cloud_init` | Custom cloud-init YAML | No | Auto-generated | HOSTS (per-host) |

**Important**: The `namespace`, `kubeconfig`, and `kubecontext` options must be specified in the global `CONFIG` section, not per-host. All VMs will be created in the same Kubernetes namespace.

### VM Image Formats

The `vm_image` option supports several formats:

- **Container image**: `quay.io/kubevirt/fedora-cloud-container-disk-demo`
- **PVC reference**: `pvc:my-vm-disk` or just `my-vm-disk`
- **DataVolume**: `http://example.com/my-datavolume.img` or `https://example.com/my-datavolume.img` NOTE: CDI must be installed in the cluster for DataVolume support.

### Network Modes

- **port-forward**: Uses `kubectl port-forward` (default, works everywhere)
- **nodeport**: Creates a NodePort service (requires node access)
- **multus**: Uses Multus bridge networking (requires Multus CNI)

## Usage Example

```yaml
# beaker-hosts.yaml
HOSTS:
  puppet-agent:
    platform: el-8-x86_64
    hypervisor: kubevirt
    vm_image: quay.io/kubevirt/centos-stream8-container-disk-demo
    network_mode: port-forward
    ssh_key: ~/.ssh/id_rsa.pub
    cpu: 2
    memory: 4Gi

CONFIG:
  # Global KubeVirt configuration
  kubeconfig: ~/.kube/config
  namespace: beaker-tests
  ssh:
    auth_methods: ['publickey']
```

```ruby
# spec/acceptance/basic_spec.rb
require 'spec_helper_acceptance'

describe 'basic functionality' do
  context 'on KubeVirt VM' do
    it 'should provision successfully' do
      expect(fact_on(default, 'kernel')).to eq('Linux')
    end

    it 'should have SSH access' do
      result = on(default, 'echo "Hello from KubeVirt VM"')
      expect(result.stdout.strip).to eq('Hello from KubeVirt VM')
    end
  end
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/voxpupuli/beaker-kubevirt.

## License

The gem is available as open source under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html) as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
