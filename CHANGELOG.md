# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - Unreleased

### Changed

- **Breaking:** split the single `@activeledger/sdk` package into a monorepo of three packages - `@activeledger/sdk-core` (shared, internal), `@activeledger/sdk-node` (Node.js, signing via `node:crypto`), and `@activeledger/sdk-web` (browsers and React Native, signing via `@noble/curves`).
- **Breaking:** RSA support removed - both packages only support secp256k1 identities. `KeyType.RSA` no longer exists; `generateKey()` no longer takes a `KeyType` argument.
- **Breaking:** `Connection`'s optional RSA-based transport-encryption feature removed.
- **Breaking:** `exportKey`/`importKey` (file-based key persistence) moved to `@activeledger/sdk-node`'s `KeyHandler` only - not available on `@activeledger/sdk-web`.
- `@activeledger/sdk-node` no longer depends on `@activeledger/activecrypto` or `node-rsa` - secp256k1 signing is implemented directly on top of `node:crypto`.

## [1.3.6] - 02-02-2023

### Fixed

- Dependency issues (Axios)


## [1.3.5] - 02-02-2023

### Fixed

- Updated definitations to include $responses and $debug

## [1.3.4] - 21-02-2020

### Fixed

- Eventsource reference for node builds

## [1.3.3] - 12-09-2019

### Fixed

- Uses native EventSource is available else uses polyfill

## [1.3.2] - 30-12-2019

### Fixed

- Event emitter being unsubscribed to soon

## [1.3.1] - 12-09-2019

### Changed

- Updated some packages
- Corrected labelled transaction test

### Fixed

- Import reject message if file not found was the same as the export error message when a file cannot be written
- Activedefintions error if not installed, moved to dependencies until solution is found

## [1.3.0] - 09-09-2019

### Added

- Server sent event handling

## [1.2.5] - 22-05-2019

### Added

- This changelog
- Added labelled transaction builder function, with interface
- Browser check before running code reliant on fs

### Changed

- Test updates
- Refactored code

### Removed

## [1.2.1] - 21-11-2018

### Changed

- Fixed issue with Readme
- Updated tests
- Updated to work with Activecrypto changes
- Updated Readme
- Sign Transaction function now accepts a string

## [1.2.0] - 07-11-2018

### Added

- Keys can be imported and exported

### Changed

- Using TypeDoc for documentation
- Test updates

### Fixed

- GitHub IO display

## [1.1.1] - 05-11-2018

### Added

- Encryption test

### Fixed

- Removed erroneous JSON.parse

## [1.1.0] - 31-10-2018

### Changed

- Switched to Axios for http requests to improve browser support

## [1.0.0] - 30-10-2018

### Initial release

- Activeledger Node.js SDK
- Key handling
- Connection handling
- Transaction handling
- Readme
