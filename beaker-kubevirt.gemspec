# frozen_string_literal: true

require_relative 'lib/beaker/kubevirt/version'

Gem::Specification.new do |spec|
  spec.name = 'beaker-kubevirt'
  spec.version = Beaker::Kubevirt::VERSION
  spec.authors = ['Steven Pritchard']
  spec.email = ['steven.pritchard@gmail.com']

  spec.summary = 'KubeVirt hypervisor support for Beaker acceptance testing'
  spec.description = 'Enables Beaker to provision VMs using KubeVirt for automated acceptance testing of Puppet code.'
  spec.homepage = 'https://github.com/voxpupuli/beaker-kubevirt'
  spec.license = 'Apache-2.0'
  spec.required_ruby_version = '>= 2.7.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/voxpupuli/beaker-kubevirt'
  spec.metadata['changelog_uri'] = 'https://github.com/voxpupuli/beaker-kubevirt/blob/main/CHANGELOG.md'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Runtime dependencies
  spec.add_runtime_dependency 'base64', '~> 0.1'
  spec.add_runtime_dependency 'beaker', '>= 4.0'
  spec.add_runtime_dependency 'kubeclient', '~> 4.9'

  # Development dependencies
  spec.add_development_dependency 'pry', '~> 0.10'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'simplecov', '~> 0.22.0'
  spec.add_development_dependency 'voxpupuli-rubocop', '~> 2.8.0'
  spec.add_development_dependency 'yard', '~> 0.9'
end
