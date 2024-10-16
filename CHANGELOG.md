# Changelog

## [0.9.0] - 2024-10-09

### Added

- `validate_aud` field and method to `Verifier` for overriding the validation of the audience claim. This is set to `true` by default.
- `validate_exp` field and method to `Verifier` for overriding the validation of the expiration claim. This is set to `true` by default.
- `validate_nbf` field and method to `Verifier` for overriding the validation of the not before claim. This is set to `false` by default.

## [0.8.0] - 2024-10-03

### Changed

- `client-reqwest` feature is now enabled by default.
- `client-surf` feature is now disabled by default.

- MSRV is now 1.73.0
  
- Updated the minimum versions of the following dependencies:
  - jsonwebtoken [9.3.0]
  - reqwest [0.12.8]
  - reqwest-middleware [0.3.3]
  - http-cache-surf [0.13.0]
  - http-cache-reqwest [0.14.0]

- Removed the following dependencies:
  - jsonwebkey

## [0.7.0] - 2023-07-29

### Added

- `client-surf` feature that enables the `surf` client for remote requests. This is enabled by default.
- `cache-surf` feature that enables cache on disk to store keys when using the `surf` client. This is disabled by default.
- `client-reqwest` feature that enables the `reqwest` client for remote requests. This is disabled by default.
- `cache-reqwest` feature that enables cache on disk to store keys when using the `reqwest` client. This is disabled by default.

### Changed

- MSRV is now 1.65.0
 
- Updated the minimum versions of the following dependencies:
  - async-trait [0.1.72]
  - serde [1.0.178]
  - serde_json [1.0.104]
  - http-cache-surf [0.11.2]

## [0.6.2] - 2023-07-19

### Changed

- Updated the minimum versions of the following dependencies:
  - anyhow [1.0.72]
  - async-trait [0.1.71]
  - serde [1.0.171]
  - serde_json [1.0.103]
  - http-cache-surf [0.11.0]
  - jwt-simple [0.11.6]
  - mockito [1.1.0]

## [0.6.1] - 2023-04-20

### Changed

- `keys_endpoint` field in `Config` struct set to public

## [0.6.0] - 2023-04-19

### Added

- `new_with_config` method that allows for overriding the default configuration
- `Config` struct for options passed to the `new_with_config` method

### Changed

- MSRV is now 1.63.0

- Updated the minimum versions of the following dependencies:
  - anyhow [1.0.70]
  - jsonwebtoken [8.3.0]
  - async-trait [0.1.68]
  - serde [1.0.160]
  - serde_json [1.0.96]
  - http-cache-surf [0.9.0]
  - jwt-simple [0.11.4]
  - mockito [1.0.2]

## [0.5.0] - 2023-02-07

### Changed

- MSRV is now 1.60.0
- Edition is now 2021

- Updated the minimum versions of the following dependencies:
  - anyhow [1.0.69]
  - jsonwebtoken [8.2.0]
  - async-trait [0.1.64]
  - serde [1.0.152]
  - serde_json [1.0.92]
  - http-cache-surf [0.6.0]
  - jwt-simple [0.11.3]
  - mockito [0.31.1]

## [0.4.5] - 2022-11-16

### Changed

- Updated the minimum versions of the following dependencies:
  - async-trait [0.1.58]
  - anyhow [0.1.66]
  - http-cache-surf [0.5.2]
  - jsonwebtoken  [8.1.1]
  - jwt-simple [0.11.2]
  - serde [1.0.147]
  - serde_json [1.0.87]
  - async-std [1.12.0]

## [0.4.4] - 2022-06-17

### Changed

- Updated the minimum versions of the following dependencies:
  - async-trait [0.1.56]
  - http-cache-surf [0.5.0]
  - jsonwebtoken  [8.1.1]
  - serde [1.0.137]
  - serde_json [1.0.81]

## [0.4.3] - 2022-04-30

### Added

- This changelog to keep a record of notable changes to the project.

### Changed

- Updated the minimum versions of the following dependencies:
  - jsonwebtoken [8.1.0]
  - async-std [1.11.0]
  - mockito [0.31.0]
  - async-trait [0.1.53]
  - jwt-simple [0.11.0]
  - http-cache-surf [0.4.6]
  - serde_json [1.0.79]
  - jsonwebkey [0.3.5]
  - anyhow [1.0.57]
