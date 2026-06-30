# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/primait/jwks_client/compare/v0.6.1...v0.6.2) - 2026-06-30

### Other

- Update mockall requirement from 0.14 to 0.15 ([#62](https://github.com/primait/jwks_client/pull/62))
- Bump rust from 1.88 to 1.96 ([#59](https://github.com/primait/jwks_client/pull/59))

## [0.6.1](https://github.com/primait/jwks_client/compare/v0.6.0...v0.6.1) - 2026-06-23

### Other

- Fully leverage release-plz to establish automated CI/CD ([#60](https://github.com/primait/jwks_client/pull/60))
- add docker ecosystem to dependabot.yml ([#58](https://github.com/primait/jwks_client/pull/58))
- add release-plz workflow to create PR after merge on master ([#56](https://github.com/primait/jwks_client/pull/56))
- Bump Swatinem/rust-cache from 2.7.8 to 2.9.1 ([#53](https://github.com/primait/jwks_client/pull/53))
- Bump actions/checkout from 3 to 6 ([#54](https://github.com/primait/jwks_client/pull/54))

---

## [0.6.0] - 2026-05-04

### Added

- JWT `nbf` claims are now validated when present

---

## [0.5.3] - 2026-04-07

### Changed

- MSRV bumped to 1.88
- Update jsonwebtoken to 10.x

---

## [0.5.2] - 2025-08-11

### Added

- Support for EdDSA (thanks @jhart0)

---

## [0.5.1] - 2024-04-17

### Changed

- Expose TLS features

---

## [0.5.0] - 2023-12-12

### Changed

- Exposed `JsonWebKeySet` type.
- *BREAKING*: Changed `JwksSource` trait function `fetch_keys` error return type in `JwksClientError`.

---

## [0.4.2] - 2023-10-18

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


[Unreleased]: https://github.com/primait/jwks_client/compare/0.6.0...HEAD
[0.6.0]: https://github.com/primait/jwks_client/compare/0.5.3...0.6.0
[0.5.3]: https://github.com/primait/jwks_client/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/primait/jwks_client/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/primait/jwks_client/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/primait/jwks_client/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/primait/jwks_client/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/primait/jwks_client/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/primait/jwks_client/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/primait/jwks_client/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/primait/jwks_client/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/primait/jwks_client/releases/tag/0.1.0
