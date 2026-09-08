# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/joshtgl/cidrwall/compare/v0.1.2...v0.1.3) - 2026-09-05

### Added

- verify after applying lists, apply sets separately
- add additional logging messages

### Fixed

- move logs to debug
- set count constant
- update default batch sizes

### Other

- *(ci)* push dev version image

## [0.1.2](https://github.com/joshtgl/cidrwall/compare/v0.1.1...v0.1.2) - 2026-08-21

### Added

- stream lists, assume ordered

## [0.1.1](https://github.com/joshtgl/cidrwall/compare/v0.1.0...v0.1.1) - 2026-08-21

### Fixed

- *(deps)* update rust crate toml to v1

### Other

- *(deps)* update rust docker tag to v1.97
- *(ci)* add release workflows
