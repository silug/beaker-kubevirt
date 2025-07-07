# frozen_string_literal: true

require_relative 'kubevirt/version'

# Require beaker first to get the base Hypervisor class
begin
  require 'beaker'
rescue LoadError
  # Beaker might not be available in all contexts
end

require 'beaker/hypervisor/kubevirt'

module Beaker
  module Kubevirt
    class Error < StandardError; end
  end

  # The KubeVirt class is defined in beaker/hypervisor/kubevirt.rb
  # This file serves as the main entry point for the gem
end
