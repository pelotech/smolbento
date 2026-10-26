# Changelog

## [0.1.1](https://github.com/pelotech/smolbento/compare/v0.1.0...v0.1.1) (2026-10-26)


### Bug Fixes

* **cli:** exit quietly when stdout is closed instead of panicking ([#5](https://github.com/pelotech/smolbento/issues/5)) ([f244d8c](https://github.com/pelotech/smolbento/commit/f244d8cc1fb0f750b0d9f46dbca4b18363777716))
* **release:** check the macOS ad-hoc signature without rcodesign verify ([#6](https://github.com/pelotech/smolbento/issues/6)) ([ec86a17](https://github.com/pelotech/smolbento/commit/ec86a1727041eb7ec2dfebfebbb5977124b5ca37))


### Chores

* cancel superseded PR runs, skip Rust jobs on docs-only changes, cache cargo ([#8](https://github.com/pelotech/smolbento/issues/8)) ([ec76791](https://github.com/pelotech/smolbento/commit/ec767915b12ef8d5cebd1f1bd593c70fc08413f5))

## 0.1.0 (2026-10-26)


### Features

* initial smolbento with sbx-compatible core lifecycle ([e38b47b](https://github.com/pelotech/smolbento/commit/e38b47bee83298c636ba1433d2c8bba36b8ae5a0))


### Bug Fixes

* **deps:** update rust crate serde-saphyr to v2 ([#3](https://github.com/pelotech/smolbento/issues/3)) ([9daa723](https://github.com/pelotech/smolbento/commit/9daa723f3acda6cefdfda2a6f34e8f2f18c5def5))


### Chores

* **deps:** update dependency sigstore/cosign to v3 ([#2](https://github.com/pelotech/smolbento/issues/2)) ([8233443](https://github.com/pelotech/smolbento/commit/82334430b00dc9c6c79d22c49db11261acb1ad79))
