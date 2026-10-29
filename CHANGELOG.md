# Changelog

## [0.12.0](https://github.com/pelotech/smolbento/compare/v0.11.0...v0.12.0) (2026-10-29)


### Features

* **skills:** agent skills store, --skills modes and kit skill capabilities ([#45](https://github.com/pelotech/smolbento/issues/45)) ([89ae87b](https://github.com/pelotech/smolbento/commit/89ae87bd0d5fc44a6c9c2ba901dd4099e6c2ef08))

## [0.11.0](https://github.com/pelotech/smolbento/compare/v0.10.1...v0.11.0) (2026-10-29)


### Features

* keep agent images cached for new sandboxes ([#43](https://github.com/pelotech/smolbento/issues/43)) ([6bfb526](https://github.com/pelotech/smolbento/commit/6bfb52636f17f9de1e976d771fa7a3c303e04372))

## [0.10.1](https://github.com/pelotech/smolbento/compare/v0.10.0...v0.10.1) (2026-10-29)


### Bug Fixes

* open the host browser for agent logins and keep links clickable ([#41](https://github.com/pelotech/smolbento/issues/41)) ([af96f5f](https://github.com/pelotech/smolbento/commit/af96f5f231a6a055bf9975896d22c8317a661237))

## [0.10.0](https://github.com/pelotech/smolbento/compare/v0.9.0...v0.10.0) (2026-10-29)


### Features

* filtered SSH agent forwarding (Phase 5b) ([#39](https://github.com/pelotech/smolbento/issues/39)) ([010eae3](https://github.com/pelotech/smolbento/commit/010eae3afd6a5eadeacd2771a5851f619b67a15b))

## [0.9.0](https://github.com/pelotech/smolbento/compare/v0.8.0...v0.9.0) (2026-10-29)


### Features

* browser and clipboard bridge while attached (Phase 5e) ([#37](https://github.com/pelotech/smolbento/issues/37)) ([6bb8a48](https://github.com/pelotech/smolbento/commit/6bb8a48f3af82e7e931854eb86509b103f4d39ac))

## [0.8.0](https://github.com/pelotech/smolbento/compare/v0.7.0...v0.8.0) (2026-10-28)


### Features

* progress output while creating sandboxes, and sbx aliases ([#34](https://github.com/pelotech/smolbento/issues/34)) ([f2894ce](https://github.com/pelotech/smolbento/commit/f2894ce2309b1af3caf0d10ffd171b1bfdacb093))


### Bug Fixes

* **kits:** copy binary files from a kit's files/ directory ([#35](https://github.com/pelotech/smolbento/issues/35)) ([a570439](https://github.com/pelotech/smolbento/commit/a570439d4dadf18cbe10a071a82bbc416126c7eb))

## [0.7.0](https://github.com/pelotech/smolbento/compare/v0.6.0...v0.7.0) (2026-10-28)


### Features

* kit host mounts, --mount and inspect (Phase 5a) ([#31](https://github.com/pelotech/smolbento/issues/31)) ([be321de](https://github.com/pelotech/smolbento/commit/be321debdd18aa0c64fb75b34868464ba1ae1413))


### Docs

* move trailing comments off install command lines so zsh paste works ([#33](https://github.com/pelotech/smolbento/issues/33)) ([cc15008](https://github.com/pelotech/smolbento/commit/cc15008271c7545b77bccf9a9c79a1f296709780))

## [0.6.0](https://github.com/pelotech/smolbento/compare/v0.5.0...v0.6.0) (2026-10-28)


### Features

* host services via localhost policy rules (Phase 4c) ([#30](https://github.com/pelotech/smolbento/issues/30)) ([0545dc9](https://github.com/pelotech/smolbento/commit/0545dc94b5ef5630f08e800ebcef002f8d57187d))
* registry logins for host pulls and the kit builder ([#28](https://github.com/pelotech/smolbento/issues/28)) ([fc91d95](https://github.com/pelotech/smolbento/commit/fc91d95d87dd9564df11a0493e2e9dbcc96ba0a2))


### Tests

* **e2e:** reach httpbin.org instead of example.com ([#27](https://github.com/pelotech/smolbento/issues/27)) ([d8833b9](https://github.com/pelotech/smolbento/commit/d8833b93dfa4e6e490c136469aa95e0ea5343f83))

## [0.5.0](https://github.com/pelotech/smolbento/compare/v0.4.0...v0.5.0) (2026-10-28)


### Features

* add sbx environment files (Phase 4b) ([#25](https://github.com/pelotech/smolbento/issues/25)) ([17bb335](https://github.com/pelotech/smolbento/commit/17bb335d6f164e8870ad34b9437efa34ecc2704f))
* add sbx kits (Phase 4a) with measured sbx parity ([#23](https://github.com/pelotech/smolbento/issues/23)) ([4f88b60](https://github.com/pelotech/smolbento/commit/4f88b60c483a474a80241992f950e13690fdb1c8))


### Bug Fixes

* **deps:** update rust crate base64 to 0.23.0 ([#24](https://github.com/pelotech/smolbento/issues/24)) ([36b9908](https://github.com/pelotech/smolbento/commit/36b99089f1ca18b831b64a5d72a9a82d3f721937))


### Chores

* **deps:** update dependency sigstore/cosign to v3.1.4 ([#21](https://github.com/pelotech/smolbento/issues/21)) ([9eccbf2](https://github.com/pelotech/smolbento/commit/9eccbf22295480262db0d58460e0c66571faac12))
* **deps:** update swatinem/rust-cache action to v2.9.3 ([#20](https://github.com/pelotech/smolbento/issues/20)) ([2a4ac56](https://github.com/pelotech/smolbento/commit/2a4ac562f1d9aec2c9a7b702a0e3c4bddd99a3c1))
* require smolvm 1.32.4 ([#26](https://github.com/pelotech/smolbento/issues/26)) ([e3634b9](https://github.com/pelotech/smolbento/commit/e3634b9ac80fc5605b80d6993d00ff9d12f29fa0))

## [0.4.0](https://github.com/pelotech/smolbento/compare/v0.3.0...v0.4.0) (2026-10-27)


### Features

* add sbt fork for copy-on-write sandbox copies ([#18](https://github.com/pelotech/smolbento/issues/18)) ([b12ef71](https://github.com/pelotech/smolbento/commit/b12ef7135ea89abf32df282b32208b7f04785387))

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
