<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).

## [v2.5.1](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/v2.5.1) - 2025-02-24

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/v2.5.0...v2.5.1)

### Fixed

- PE-40175 [#98](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/98) ([taikaa](https://github.com/taikaa))

## [v2.5.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/v2.5.0) - 2024-03-06

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/v2.4.0...v2.5.0)

### Added

- (PA-5575) Add Amazon to display support in Puppet forge [#76](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/76) ([shubhamshinde360](https://github.com/shubhamshinde360))

## [v2.4.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/v2.4.0) - 2023-02-14

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/v2.3.0...v2.4.0)

### Added

- (MODULES-11371) Updates PDK template [#67](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/67) ([mhashizume](https://github.com/mhashizume))

## [v2.3.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/v2.3.0) - 2021-10-04

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/2.2.0...v2.3.0)

### Added

- (MODULES-11167)(MODULES-11191) Add RockyLinux and AlmaLinux to sshkeys-core metadata [#47](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/47) ([BobosilaVictor](https://github.com/BobosilaVictor))

## [2.2.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/2.2.0) - 2020-10-16

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/2.1.0...2.2.0)

### Added

- (MODULES-10765) Implement public key certificate support [#35](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/35) ([bastelfreak](https://github.com/bastelfreak))

### Fixed

- (MODULES-10827) Exported sshkey already exists error [#38](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/38) ([Dorin-Pleava](https://github.com/Dorin-Pleava))

## [2.1.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/2.1.0) - 2020-06-22

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/2.0.0...2.1.0)

### Added

- (MODULES-10671) New SSH key types for OpenSSH 8.2 [#31](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/31) ([Dorin-Pleava](https://github.com/Dorin-Pleava))

### Fixed

- (PUP-10510) Fix sshkeys not being correctly purged [#32](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/32) ([GabrielNagy](https://github.com/GabrielNagy))

## [2.0.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/2.0.0) - 2020-03-13

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/1.0.3...2.0.0)

### Added

- (MODULES-7613) use name and type as composite namevar [#27](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/27) ([ciprianbadescu](https://github.com/ciprianbadescu))

## [1.0.3](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/1.0.3) - 2019-11-01

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/1.0.2...1.0.3)

### Added

- (MODULES-9578) Create ssh_authorized_key in root path [#20](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/20) ([GabrielNagy](https://github.com/GabrielNagy))

## [1.0.2](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/1.0.2) - 2019-01-11

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/1.0.1...1.0.2)

### Added

- (maint) add LICENSE file [#16](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/16) ([melissa](https://github.com/melissa))
- (L10n) Update Japanese translations [#13](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/13) ([melissa](https://github.com/melissa))

### Fixed

- ssh_authorized_key: Fix invalid 'options' error [#10](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/10) ([natemccurdy](https://github.com/natemccurdy))

## [1.0.1](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/1.0.1) - 2018-08-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/1.0.0...1.0.1)

### Added

- (PUP-9053) Enable localization and bump puppet version to at least 6 [#7](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/7) ([melissa](https://github.com/melissa))
- (maint) Import missed User type integration test from puppet repo [#6](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/6) ([jhelwig](https://github.com/jhelwig))
- (maint) Import the User type unit tests specific to ssh_authorized_keys [#5](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/5) ([jhelwig](https://github.com/jhelwig))
- Install module on all hosts, not just those with default role [#4](https://github.com/puppetlabs/puppetlabs-sshkeys_core/pull/4) ([joshcooper](https://github.com/joshcooper))

## [1.0.0](https://github.com/puppetlabs/puppetlabs-sshkeys_core/tree/1.0.0) - 2018-07-17

[Full Changelog](https://github.com/puppetlabs/puppetlabs-sshkeys_core/compare/d1719de1d77b9c139b1b5f5832330807c0fe11fe...1.0.0)
