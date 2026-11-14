# Changelog

## [0.23.0](https://github.com/pelotech/smolbento/compare/v0.22.1...v0.23.0) (2026-11-14)


### Features

* **ssh-agent:** ssh-agent@1 authenticate limits (5g) ([#108](https://github.com/pelotech/smolbento/issues/108)) ([75d5f31](https://github.com/pelotech/smolbento/commit/75d5f315bb47f2a3e7b706323a1e13d1f0dd843d))


### Refactors

* **sandbox:** map the workspace through smolvm instead of remapping uids ([#105](https://github.com/pelotech/smolbento/issues/105)) ([36d20e3](https://github.com/pelotech/smolbento/commit/36d20e3a5e80d3a343eaf692ea06a071d32dbaab))


### Docs

* make the docs concise and direct ([#107](https://github.com/pelotech/smolbento/issues/107)) ([06be613](https://github.com/pelotech/smolbento/commit/06be613c66438f653a7d380a2d0de58ef13dc836))

## [0.22.1](https://github.com/pelotech/smolbento/compare/v0.22.0...v0.22.1) (2026-11-13)


### Refactors

* remaining project review cleanups ([#103](https://github.com/pelotech/smolbento/issues/103)) ([aa24eab](https://github.com/pelotech/smolbento/commit/aa24eabd4890d20c8d88380d73cdd74e7731f080))

## [0.22.0](https://github.com/pelotech/smolbento/compare/v0.21.0...v0.22.0) (2026-11-13)


### Features

* **kits:** kit.requireSignature and kit.trustedSigners ([#101](https://github.com/pelotech/smolbento/issues/101)) ([2fe3d9a](https://github.com/pelotech/smolbento/commit/2fe3d9a694edfc8b6d05dac31a14a9691b0c58f2))

## [0.21.0](https://github.com/pelotech/smolbento/compare/v0.20.1...v0.21.0) (2026-11-13)


### Features

* **kit:** kit pack, push and pull for v2 kits ([#98](https://github.com/pelotech/smolbento/issues/98)) ([91c22b1](https://github.com/pelotech/smolbento/commit/91c22b1e455912501879bfd6632402eb6d1a29e7))
* **kit:** kit sign, kit verify and kit push --sign ([#100](https://github.com/pelotech/smolbento/issues/100)) ([3e6a72c](https://github.com/pelotech/smolbento/commit/3e6a72cf7d2eebd172e78cd445d54b7be760aa4d))

## [0.20.1](https://github.com/pelotech/smolbento/compare/v0.20.0...v0.20.1) (2026-11-13)


### Bug Fixes

* **kits:** read an existing directory as a kit without ./ where only a kit goes ([#96](https://github.com/pelotech/smolbento/issues/96)) ([57b1f34](https://github.com/pelotech/smolbento/commit/57b1f3450f6dac90a8cbcc2660333d41f4bf5928))

## [0.20.0](https://github.com/pelotech/smolbento/compare/v0.19.1...v0.20.0) (2026-11-13)


### Features

* **env:** read-only env files, fuse: false, MCP reachability, kit add format check ([#94](https://github.com/pelotech/smolbento/issues/94)) ([681aa48](https://github.com/pelotech/smolbento/commit/681aa48cab7a66ecbe54520a8ed67bc27a073671))

## [0.19.1](https://github.com/pelotech/smolbento/compare/v0.19.0...v0.19.1) (2026-11-13)


### Bug Fixes

* **kits:** expand a kit variable's reference to itself, as sbx does ([#92](https://github.com/pelotech/smolbento/issues/92)) ([5c7422f](https://github.com/pelotech/smolbento/commit/5c7422f99339527d76412a6920ff379f989edba8))

## [0.19.0](https://github.com/pelotech/smolbento/compare/v0.18.0...v0.19.0) (2026-11-13)


### Features

* retire gemini, read published v2 kits, finish sbxenv.yaml bindings and mcp ([#90](https://github.com/pelotech/smolbento/issues/90)) ([a668e95](https://github.com/pelotech/smolbento/commit/a668e95c9264a2defaf979a40597e65d9994f153))

## [0.18.0](https://github.com/pelotech/smolbento/compare/v0.17.1...v0.18.0) (2026-11-13)


### Features

* **env:** pass arguments after -- to env run, as sbx does ([#88](https://github.com/pelotech/smolbento/issues/88)) ([0210f05](https://github.com/pelotech/smolbento/commit/0210f0502abf71fd0592396aad143ccb41dfcb8c))

## [0.17.1](https://github.com/pelotech/smolbento/compare/v0.17.0...v0.17.1) (2026-11-13)


### Bug Fixes

* **env:** match sbx on ports, file sets and lifecycle output; split e2e over three runners ([#86](https://github.com/pelotech/smolbento/issues/86)) ([dd4eba8](https://github.com/pelotech/smolbento/commit/dd4eba8780338d772f3c78d1948bfd6188694f99))

## [0.17.0](https://github.com/pelotech/smolbento/compare/v0.16.0...v0.17.0) (2026-11-13)


### Features

* **env:** lifecycle, registries, entrypoint and cmd in sbxenv.yaml ([#84](https://github.com/pelotech/smolbento/issues/84)) ([66f6c82](https://github.com/pelotech/smolbento/commit/66f6c82a468fa12d919ebc95ad8d030b17eb7346))

## [0.16.0](https://github.com/pelotech/smolbento/compare/v0.15.3...v0.16.0) (2026-11-12)


### Features

* **env:** add env plan and remember approvals ([#82](https://github.com/pelotech/smolbento/issues/82)) ([f538ea1](https://github.com/pelotech/smolbento/commit/f538ea15c7093a6b740316cc9219d59a9875cb4a))

## [0.15.3](https://github.com/pelotech/smolbento/compare/v0.15.2...v0.15.3) (2026-11-12)


### Bug Fixes

* check MCP selections early, refuse mixed v2/v3 kits, clearer hints ([#81](https://github.com/pelotech/smolbento/issues/81)) ([35f4b00](https://github.com/pelotech/smolbento/commit/35f4b00a7631859c30d2accc6e582a9b4658b551))
* match sbx on failed creates and closed terminals ([#79](https://github.com/pelotech/smolbento/issues/79)) ([f54f1bf](https://github.com/pelotech/smolbento/commit/f54f1bf7d961d856a3232d9f4603c9f318eb1ece))

## [0.15.2](https://github.com/pelotech/smolbento/compare/v0.15.1...v0.15.2) (2026-11-12)


### Bug Fixes

* keep error hints, close run's early returns, and give MCP secrets their own label ([#75](https://github.com/pelotech/smolbento/issues/75)) ([2a05e5f](https://github.com/pelotech/smolbento/commit/2a05e5f9d92e1e0b379e564852c6f85bb1bcefc7))
* **kits:** export a v3 kit argument that declares env ([#78](https://github.com/pelotech/smolbento/issues/78)) ([46cde51](https://github.com/pelotech/smolbento/commit/46cde51d4a8f342ffcba155ad4e2b36cabd19aeb))


### Chores

* build the release targets on pull requests; pin the cross-compile image ([#76](https://github.com/pelotech/smolbento/issues/76)) ([76794ac](https://github.com/pelotech/smolbento/commit/76794ac27ace0947580ae078d82fd8cc61858425))

## [0.15.1](https://github.com/pelotech/smolbento/compare/v0.15.0...v0.15.1) (2026-11-12)


### Bug Fixes

* **release:** match cargo-zigbuild rustc version to the Nix dev shell ([#73](https://github.com/pelotech/smolbento/issues/73)) ([2b9ce39](https://github.com/pelotech/smolbento/commit/2b9ce394823eb4e95915642621855d6911ac7203))

## [0.15.0](https://github.com/pelotech/smolbento/compare/v0.14.0...v0.15.0) (2026-11-12)


### Features

* **mcp:** static MCP servers (sbt mcp, --static-mcp) ([#72](https://github.com/pelotech/smolbento/issues/72)) ([9a02769](https://github.com/pelotech/smolbento/commit/9a02769b486ca0621b35924408128d5c248e7916))


### Bug Fixes

* run and create cleanups, input checks, error hints and sbx/bento completions ([#70](https://github.com/pelotech/smolbento/issues/70)) ([fbd2b0a](https://github.com/pelotech/smolbento/commit/fbd2b0ad9eb791fcf356775accfb121b5b77ed79))

## [0.14.0](https://github.com/pelotech/smolbento/compare/v0.13.0...v0.14.0) (2026-11-12)


### Features

* require smolvm 1.34.1 and stream plain exec output ([#67](https://github.com/pelotech/smolbento/issues/67)) ([3493942](https://github.com/pelotech/smolbento/commit/34939428368e6fd0a761b9152fce05869172785d))


### Bug Fixes

* guard approval denies and refuse a non-private bridge socket directory ([#69](https://github.com/pelotech/smolbento/issues/69)) ([bc4bcb4](https://github.com/pelotech/smolbento/commit/bc4bcb4b3fb12e18865883c3dbb72efcf4b321f3))
* **run:** forget the sandbox's policy and secrets on --rm ([#53](https://github.com/pelotech/smolbento/issues/53)) ([05b0e14](https://github.com/pelotech/smolbento/commit/05b0e145d0e895fede3ab90fb290bfe3c5e6e3d7))


### Refactors

* decouple cli from domain modules and remove duplication ([#68](https://github.com/pelotech/smolbento/issues/68)) ([0ae8d45](https://github.com/pelotech/smolbento/commit/0ae8d4530a55cb5cfd04448ba0e39b2082515f97))
* **kits:** split resolve_for and apply into named steps ([#59](https://github.com/pelotech/smolbento/issues/59)) ([1c19de1](https://github.com/pelotech/smolbento/commit/1c19de103ae2ce0a0f31fc7ae22987b8629d82df))
* move Ctx out of cli and split lifecycle.rs ([#58](https://github.com/pelotech/smolbento/issues/58)) ([135fef6](https://github.com/pelotech/smolbento/commit/135fef613f6b7e4595e300d1e639d44d2acbc752))
* small cleanups from the project review ([#57](https://github.com/pelotech/smolbento/issues/57)) ([e8dab3c](https://github.com/pelotech/smolbento/commit/e8dab3c74695532750cc5f7869852f2561709f62))


### Chores

* **deps:** lock file maintenance ([#63](https://github.com/pelotech/smolbento/issues/63)) ([7513714](https://github.com/pelotech/smolbento/commit/7513714183dc36be3a0707645ae58eb56df3e2c3))
* **deps:** update cachix/install-nix-action action to v31.11.3 ([#60](https://github.com/pelotech/smolbento/issues/60)) ([c310c1a](https://github.com/pelotech/smolbento/commit/c310c1a77bb7982932188a7caf69c73d30a6add1))
* **deps:** update dependency smol-machines/smolvm to v1.33.0 ([#61](https://github.com/pelotech/smolbento/issues/61)) ([2c8500f](https://github.com/pelotech/smolbento/commit/2c8500f4409fff23fcc2ec63a5d7d15ee218760b))
* **deps:** update docker/sandbox-templates docker tag ([#62](https://github.com/pelotech/smolbento/issues/62)) ([18e4225](https://github.com/pelotech/smolbento/commit/18e4225b149273e7d3ec2cf001793bd2003d1650))
* **deps:** update pre-commit hook zizmorcore/zizmor-pre-commit to v1.32.0 ([#64](https://github.com/pelotech/smolbento/issues/64)) ([ddee5d1](https://github.com/pelotech/smolbento/commit/ddee5d113c35c281a5f3b656ddb543e76feabed6))
* **deps:** update rust crate toml to v1.2.0 ([#65](https://github.com/pelotech/smolbento/issues/65)) ([8f7a8be](https://github.com/pelotech/smolbento/commit/8f7a8be6c1a0e05e5f7fb5b78137aa3d6dcb82ee))
* **deps:** update sigstore/cosign-installer action to v4.1.3 ([#66](https://github.com/pelotech/smolbento/issues/66)) ([8f7a2ea](https://github.com/pelotech/smolbento/commit/8f7a2ea3acfdba7167e9dedf9c564c655e59ec99))


### Docs

* **agents:** record the smolvm behaviour smolbento relies on ([#51](https://github.com/pelotech/smolbento/issues/51)) ([20c2350](https://github.com/pelotech/smolbento/commit/20c2350368c79cf1c7a7b92ff2eda1b49524f560))


### Tests

* **e2e:** push the host-mount kit instead of building it ([#54](https://github.com/pelotech/smolbento/issues/54)) ([c4482b3](https://github.com/pelotech/smolbento/commit/c4482b3851bfccd830198459092c469ed14e9f8b))
* read prompt answers through Ctx so prompts can be tested ([#56](https://github.com/pelotech/smolbento/issues/56)) ([23c62ee](https://github.com/pelotech/smolbento/commit/23c62ee14788a94493c3f56a84b855118fc1fe30))
* TestEnv helpers and Kit::new ([#55](https://github.com/pelotech/smolbento/issues/55)) ([2330868](https://github.com/pelotech/smolbento/commit/2330868ed8c6c05ed9f76d3f9a8f752790afd5a6))

## [0.13.0](https://github.com/pelotech/smolbento/compare/v0.12.0...v0.13.0) (2026-10-31)


### Features

* **template:** save, list, remove and load templates, and run from them with -t ([#48](https://github.com/pelotech/smolbento/issues/48)) ([074664b](https://github.com/pelotech/smolbento/commit/074664b249392268892ec1c8d5ce23d35c3d9c99))


### Bug Fixes

* **kits:** drop qualified deny rules on network-policy@2 host-only fallback ([#49](https://github.com/pelotech/smolbento/issues/49)) ([f2e14cd](https://github.com/pelotech/smolbento/commit/f2e14cdf49b83751952a77e816d96600450d9c65))

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
