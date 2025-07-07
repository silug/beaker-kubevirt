# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of KubeVirt hypervisor provider for Beaker
- Support for VM provisioning using KubeVirt VirtualMachine objects
- Multiple image source support (PVC, ContainerDisk, DataVolume)
- Cloud-init configuration injection for VM setup
- Multiple networking modes:
  - Port-forward (default, works in all environments)
  - NodePort (requires node access)
  - Multus (external bridge networking)
- Automatic VM lifecycle management (provision, test, cleanup)
- SSH key injection and access setup
- Resource configuration (CPU, memory)
- Kubernetes authentication support (token, client certificates)
- Comprehensive test suite and examples

### Security
- SSH public key authentication by default
- Secure handling of Kubernetes credentials

## [0.1.0] - 2025-07-07

### Added
- Initial gem structure and basic implementation
