# frozen_string_literal: true

require 'beaker-rspec'
require 'beaker/hypervisor/kubevirt'

describe 'my kubevirt vm' do
  it 'can run a command' do
    on default, 'echo hello'
  end
end
