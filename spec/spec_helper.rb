# frozen_string_literal: true

require 'simplecov'

SimpleCov.start

# Suppress Beaker::Kubevirt's at_exit cleanup handler during this gem's own
# test run. In downstream projects (which may also have RSpec loaded) the
# handler should remain active.
ENV['BEAKER_KUBEVIRT_DISABLE_AT_EXIT_CLEANUP'] = '1'

require 'beaker/hypervisor/kubevirt'
require 'beaker/hypervisor/kubevirt_helper'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Mock external dependencies
  config.before do
    # Mock Kubeclient classes
    stub_const('Kubeclient::Client', Class.new)
    stub_const('Kubeclient::ResourceNotFoundError', Class.new(StandardError))

    # Allow Kubeclient::Client to be instantiated
    allow(Kubeclient::Client).to receive(:new).and_return(instance_double(Kubeclient::Client).as_null_object)
  end
end
