# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-07

First release.

### Added

- `ndiscover-cli`, a command-line tool that finds NETIO devices with UDP Discover
  - searches every local network at once, also while a VPN routes all traffic through itself
  - `--interface` to search the networks of one interface only
  - `--timeout` for how long to wait for answers
  - `--detailed` and `--json` output
- `ndiscover`, a desktop app
  - scans when it starts, and regularly with **Scan every**
  - lists devices with links to their web interface
  - shows the full firmware version on hover, with a button to copy it
  - logs in to devices with firmware 5.0 or newer over plain or secure WebSocket connections
  - switches outputs with one checkbox per output
  - remembers logins and logs in again automatically
  - checks for firmware updates and installs them
- `scripts/macos-app.sh`, which builds a macOS app bundle
- `ndiscover_lib`, a library to find devices with UDP Discover
- `ndiscover_control` 0.1.0, a library to log in to devices with firmware 5.0 or newer, switch their
  outputs and check for and install firmware updates

[Unreleased]: https://github.com/ekkomaru/ndiscover/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ekkomaru/ndiscover/releases/tag/v0.2.0
