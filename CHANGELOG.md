# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support elliptic curve keys

### Changed 

- Update jsonwebtoken to 9.0

---

## [0.4.1] - 2023-04-03

### Added

- [[#16](https://github.com/primait/jwks_client/pull/16)] Add instrumentation of fetch_keys function.

### Changed

- MSRV bumped to 1.67

---

## [0.4.0] - 2022-11-11

### Added

- Is now possible to know if the error is caused by expired jwt (useful for refreshing purposes)
- Deps improvements

### Fixed

- README code example updated with the latest changes.
- *BREAKING* [[#11](https://github.com/primait/jwks_client/issues/11)] - avoid require owned string as params in getters 

---

## [0.3.0] - 2022-04-01

### Added

- Added new builder pattern struct `JwksClientBuilder`.
- Added `JwksClient::builder` function to create a new `JwksClientBuilder`.
- Added custom in-memory cache with entries TTL.  

### Removed

- Removed `JwksClient::new` function.

---

## [0.2.0] - 2022-03-14

### Added

- Added `timeout` (default set to 10 seconds) and `connect_timeout` (default set to 20 seconds) functions. These values 
  are used in `reqwest::Client` to avoid never-ending http requests.
- Added new library usage [example](./examples/get_jwks.rs).
- Added library usage documentation.

### Changed

- Changed cache TTL duration set from 1 minute to 1 day.

---

## [0.1.0] - 2021-10-28

### Added

- First release 🎉

[Unreleased]: https://github.com/primait/jwks_client/compare/0.4.1...HEAD
[0.4.1]: https://github.com/primait/jwks_client/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/primait/jwks_client/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/primait/jwks_client/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/primait/jwks_client/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/primait/jwks_client/releases/tag/0.1.0
