# Changelog

## [0.3.0](https://github.com/pelotech/smolbento/compare/v0.2.1...v0.3.0) (2026-10-27)


### Features

* add clone mode (run/create --clone) ([#17](https://github.com/pelotech/smolbento/issues/17)) ([90021dd](https://github.com/pelotech/smolbento/commit/90021dd5f99ef222d16a2b5ce33e8133cffee743))


### Bug Fixes

* stop sandboxes from reaching services on the host's localhost ([#15](https://github.com/pelotech/smolbento/issues/15)) ([a590ca5](https://github.com/pelotech/smolbento/commit/a590ca5dbf7ccbb46a6702c4499c31b572155348))

## [0.2.1](https://github.com/pelotech/smolbento/compare/v0.2.0...v0.2.1) (2026-10-27)


### Bug Fixes

* make --deny-network add per-sandbox deny rules, as in sbx ([#13](https://github.com/pelotech/smolbento/issues/13)) ([66730ce](https://github.com/pelotech/smolbento/commit/66730cebc518635f8f1288f84193857b99a74278))

## [0.2.0](https://github.com/pelotech/smolbento/compare/v0.1.1...v0.2.0) (2026-10-27)


### Features

* add network policy, secrets and ports ([#12](https://github.com/pelotech/smolbento/issues/12)) ([dac3bb0](https://github.com/pelotech/smolbento/commit/dac3bb05297ea7218ef3a3fea25740804e438981))


### Chores

* **deps:** update actions/create-github-app-token action to v3.3.0 ([#11](https://github.com/pelotech/smolbento/issues/11)) ([2eda4df](https://github.com/pelotech/smolbento/commit/2eda4dff7275992645b3d0f58da1b2e3fa40ec4e))
* dispatch homebrew-tap formula bump on release ([#9](https://github.com/pelotech/smolbento/issues/9)) ([0f7fe60](https://github.com/pelotech/smolbento/commit/0f7fe60a1eecdf86763ba57ea56e2ef82c34ea13))

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
