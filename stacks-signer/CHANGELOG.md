# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the versioning scheme outlined in the [README.md](README.md).

## [Unreleased]

## Added

## Changed

## [3.1.0.0.1.0]

### Added

### Changed

- Added tenure extend timestamp to signer block responses
- Added tenure_idle_timeout_secs configuration option for determining when a time-based tenure extend will be accepted

## [3.1.0.0.0.0]

### Added

- **SIP-029 consensus rules, activating in epoch 3.1 at block 875,000** (see [SIP-029](https://github.com/will-corcoran/sips/blob/feat/sip-029-halving-alignment/sips/sip-029/sip-029-halving-alignment.md) for details)

### Changed

## [3.0.0.0.4.0]

### Added

### Changed

- Use the same burn view loader in both block validation and block processing

## [3.0.0.0.3.0]

### Added

### Changed

- Allow a miner to extend their tenure immediately if the winner of the next tenure has committed to the wrong parent tenure (#5361)

## [3.0.0.0.2.0]

### Added
-  Adds `tenure_last_block_proposal_timeout_secs` option to account for delayed global block acceptance. default to 30s

### Changed

## [3.0.0.0.1.0]

### Added

### Changed

- Change block rejection message to generic block response

## [3.0.0.0.0.1]

### Added

### Changed
- Update block proposal timeout default to 10 minutes (#5391)
- Updated documentation link in output (#5363)

## [3.0.0.0.0.0]

### Added

- Improved StackerDB message structures
- Improved mock signing during epoch 2.5
- Include the `stacks-signer` binary version in startup logging and StackerDB messages
- Added a `monitor-signers` CLI command for better visibility into other signers on the network
- Support custom Chain ID in signer configuration
- Refresh the signer's sortition view when it sees a block proposal for a new tenure
- Fixed a race condition where a signer would try to update before StackerDB configuration was set

### Changed

- Migrate to new Stacks Node RPC endpoint `/v3/tenures/fork_info/:start/:stop`
- Improved chainstate storage for handling of forks and other state
- Updated prometheus metric labels to reduce high cardinality

## [2.5.0.0.5.3]

### Added

### Changed

- Update node endpoints to match stacks-core release 2.5.0.0.7
  - `/v2/block_proposal` -> `/v3/block_proposal`
  - `/v2/stacker_set` -> `/v3/stacker_set`

## [2.5.0.0.5.2]

### Added

### Changed

- Reuse BlockResponse slot for MockSignature message type (#5103)

## [2.5.0.0.5.2-rc1]

### Added

- Signer set handoff integration test (#5037)
- Add mock signing (#5020)
- Add versioning info set at build-time (#5016)

### Changed

- Fix out of sync `RPCPeerInfo` with stacks-node (#5033, #5014, #4999)
- Logging Improvements (#5025)
- Timeout empty sortition (#5003)
- Enum for version specific data (#4981)

## [2.5.0.0.5.1]

### Added

- Adds signerdb schema versioning (#4965)
- Added voting cli commands `generate-vote` and `verify-vote` (#4934)
- Add soritiion tracking cache (#4905)
- Push blocks to signer set and adds `/v3/blocks/upload` (#4902)

### Changed

- Fix an issue of poorly timed tenure and bitcoin blocks (#4956)
- Process pending blocks before ending tenure (#4952)
- Update rusqlite/sqlite versions (#4948)
- return last block sortition in `/v3/sortitions` (#4939)