# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

begin
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new
  task default: %i[spec rubocop]
rescue LoadError
  # RuboCop is optional
  task default: [:spec]
end

desc 'Run acceptance tests (requires KubeVirt cluster)'
task :acceptance do
  puts 'Running acceptance tests...'
  puts 'Note: This requires a KubeVirt-enabled Kubernetes cluster'
  # Add acceptance test commands here
end

desc 'Run examples'
task :examples do
  ruby 'examples/usage.rb'
end
