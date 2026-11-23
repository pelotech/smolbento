# Changelog

## [0.37.0](https://github.com/pelotech/smolbento/compare/v0.36.2...v0.37.0) (2026-11-23)


### Features

* **egress:** hosted credential swap behind network.egress ([#224](https://github.com/pelotech/smolbento/issues/224)) ([26668e7](https://github.com/pelotech/smolbento/commit/26668e706dfbeffc5246608eae2dac520a7099c7))
* **egress:** hosted egress enforces network rules and is the default ([#227](https://github.com/pelotech/smolbento/issues/227)) ([94b5be3](https://github.com/pelotech/smolbento/commit/94b5be32a54050611a847bc07bfd342169b4b147))

## [0.36.2](https://github.com/pelotech/smolbento/compare/v0.36.1...v0.36.2) (2026-11-22)


### Bug Fixes

* **deps:** update url to 2.5.9 for RUSTSEC-2026-0592 ([#222](https://github.com/pelotech/smolbento/issues/222)) ([77e513a](https://github.com/pelotech/smolbento/commit/77e513a797169d5a3168412d91be7f2d7b7a6bf9))

## [0.36.1](https://github.com/pelotech/smolbento/compare/v0.36.0...v0.36.1) (2026-11-22)


### Bug Fixes

* **bridge:** bound the processes login relays keep alive; rm stops them on Linux ([#218](https://github.com/pelotech/smolbento/issues/218)) ([eb8f54d](https://github.com/pelotech/smolbento/commit/eb8f54d460a965489b1e74579083951b7d0f2d88))
* **kits:** refuse lifecycle conflicts, name invalid group members, kit.env reads the container environment ([#221](https://github.com/pelotech/smolbento/issues/221)) ([ccc62f3](https://github.com/pelotech/smolbento/commit/ccc62f366167867645abacc75dbe790224b55b2b))
* **ssh-agent:** an install-only grant's guest socket goes when the install phase ends ([#220](https://github.com/pelotech/smolbento/issues/220)) ([23bbf9f](https://github.com/pelotech/smolbento/commit/23bbf9f6a44070dde28784a3ece5a497617c9adf))

## [0.36.0](https://github.com/pelotech/smolbento/compare/v0.35.0...v0.36.0) (2026-11-22)


### Features

* **kits:** kit mounts ls|rm; conformance claims host-mount@1 and lifecycle@1 ([#216](https://github.com/pelotech/smolbento/issues/216)) ([2f25c36](https://github.com/pelotech/smolbento/commit/2f25c3684ca2d1bc80342f9345ef28f131937b66))


### Bug Fixes

* **kits:** keep every declared capability version; run conformance at SPEC_COMMIT ([#214](https://github.com/pelotech/smolbento/issues/214)) ([21cd2fe](https://github.com/pelotech/smolbento/commit/21cd2fe6ec68f88314cc2a5269cd8e158c50b17a))
* **policy:** policy check reads URLs as sbx does and reports the closed host loopback ([#217](https://github.com/pelotech/smolbento/issues/217)) ([d5513f3](https://github.com/pelotech/smolbento/commit/d5513f370e54f310bb4e3115d15a7beb52cb336e))

## [0.35.0](https://github.com/pelotech/smolbento/compare/v0.34.0...v0.35.0) (2026-11-22)


### Features

* **secrets:** bind and revoke secrets in existing sandboxes live ([#210](https://github.com/pelotech/smolbento/issues/210)) ([10cdec7](https://github.com/pelotech/smolbento/commit/10cdec77c21d0ec7fcd818031fcc8418aa0e052a))


### Bug Fixes

* **env:** drop empty kit entries and refuse blank paths, as sbx does ([#213](https://github.com/pelotech/smolbento/issues/213)) ([d1fdf1f](https://github.com/pelotech/smolbento/commit/d1fdf1f2b6b98636bfe06a9d15dc393b14306246))
* **kits:** refuse malformed volume, host-mount, resources and credential requests ([#204](https://github.com/pelotech/smolbento/issues/204)) ([a1dbb00](https://github.com/pelotech/smolbento/commit/a1dbb00e9d2a9b9a1c2157c4221c8c7bdf12f4b1))
* **kits:** run a v3 startup hook without a user as the session user ([#211](https://github.com/pelotech/smolbento/issues/211)) ([0a6b113](https://github.com/pelotech/smolbento/commit/0a6b11329fbd59c0b7897822441c534d08778c82))
* **kits:** unset hook variables stay unset; agent-context@1 kept and neutralized ([#206](https://github.com/pelotech/smolbento/issues/206)) ([09581f7](https://github.com/pelotech/smolbento/commit/09581f7a5d0b1c95db1444655c81655c1ad1410e))
* **smolvm:** never signal a pid after its process is reaped ([#207](https://github.com/pelotech/smolbento/issues/207)) ([c2a109f](https://github.com/pelotech/smolbento/commit/c2a109fecc530a2f920055df329ba42a522e7123))
* **ssh:** a session that stops reading its input can't stall the connection ([#208](https://github.com/pelotech/smolbento/issues/208)) ([2a130b5](https://github.com/pelotech/smolbento/commit/2a130b592a7dd738c729d3517e20de8abc57ad03))


### Refactors

* one sandbox listing per command, atomic unit files, cached presets ([#212](https://github.com/pelotech/smolbento/issues/212)) ([eed0213](https://github.com/pelotech/smolbento/commit/eed021325af4aac7719f9d22a29b04d81868cb5f))


### Chores

* remove dead code, fix contradictory docs, skip a redundant CI job ([#209](https://github.com/pelotech/smolbento/issues/209)) ([5a05d9a](https://github.com/pelotech/smolbento/commit/5a05d9a4349e454293381d982a98d2573c691c8d))

## [0.34.0](https://github.com/pelotech/smolbento/compare/v0.33.4...v0.34.0) (2026-11-22)


### Features

* **kits:** start Docker for dockerd@1 in the runtime ([#199](https://github.com/pelotech/smolbento/issues/199)) ([9c406b3](https://github.com/pelotech/smolbento/commit/9c406b34c4fa4b658526574995215f5d7ad65058))


### Bug Fixes

* ask for the network policy on stderr like sbx; fork refreshes the parent's units ([#203](https://github.com/pelotech/smolbento/issues/203)) ([a949968](https://github.com/pelotech/smolbento/commit/a9499686bb3fcf5f2628988893cdb0430aa92be5))
* clipboard stall, hyphenated credential modes, two env-file panics ([#201](https://github.com/pelotech/smolbento/issues/201)) ([fcf8174](https://github.com/pelotech/smolbento/commit/fcf81745598942b6a00e70b9a679f129a5fa186e))
* keep secrets and skills on failed writes; kit inspect/validate agree with resolve ([#202](https://github.com/pelotech/smolbento/issues/202)) ([4e6c4b7](https://github.com/pelotech/smolbento/commit/4e6c4b763edef959ec94343a50ae802049d74386))

## [0.33.4](https://github.com/pelotech/smolbento/compare/v0.33.3...v0.33.4) (2026-11-21)


### Bug Fixes

* **kits:** the shipped docker kit only starts dockerd and provides nothing ([#197](https://github.com/pelotech/smolbento/issues/197)) ([8f10175](https://github.com/pelotech/smolbento/commit/8f101757e9e53ce2133e1f950df7cfaa3e69f52c))


### Chores

* **smolvm:** pin 1.36.1 ([#196](https://github.com/pelotech/smolbento/issues/196)) ([61e9e1b](https://github.com/pelotech/smolbento/commit/61e9e1b2ee25f1ca5f296e5db1d2772354b1db78))

## [0.33.3](https://github.com/pelotech/smolbento/compare/v0.33.2...v0.33.3) (2026-11-20)


### Bug Fixes

* harden secrets, ssh-agent, policy, serve and host-service edge cases ([#194](https://github.com/pelotech/smolbento/issues/194)) ([30234aa](https://github.com/pelotech/smolbento/commit/30234aaf1190ccd9b11cf91241bc23c6b0f36cfc))

## [0.33.2](https://github.com/pelotech/smolbento/compare/v0.33.1...v0.33.2) (2026-11-20)


### Chores

* run the release builds on the release PR and build changes; check darwin on every PR ([#189](https://github.com/pelotech/smolbento/issues/189)) ([2f101cc](https://github.com/pelotech/smolbento/commit/2f101ccfc6a6e548bfb602346472785c66f11cc8))


### Tests

* **e2e:** balance CI shards by duration and drop VM checks unit tests prove ([#193](https://github.com/pelotech/smolbento/issues/193)) ([2cb1bb7](https://github.com/pelotech/smolbento/commit/2cb1bb7898dca75421b1d77c29fb758caf0da62f))
* **e2e:** fix stale ignore reasons and comments; fail an unchecked host services test on CI ([#190](https://github.com/pelotech/smolbento/issues/190)) ([a864c2c](https://github.com/pelotech/smolbento/commit/a864c2cb724ff28a152f6b23e599ac25ea5762e6))
* **e2e:** pull images once, build the nix kit once, keep the builder ([#192](https://github.com/pelotech/smolbento/issues/192)) ([680eab2](https://github.com/pelotech/smolbento/commit/680eab2c6fa5728f1316651bda3ce9147935607a))

## [0.33.1](https://github.com/pelotech/smolbento/compare/v0.33.0...v0.33.1) (2026-11-20)


### Bug Fixes

* **smolvm:** download the pinned smolvm before the first smolvm call, whatever the command ([#187](https://github.com/pelotech/smolbento/issues/187)) ([f1bdee0](https://github.com/pelotech/smolbento/commit/f1bdee0c287aabc9cd1c4604f7edefbfc0c61658))

## [0.33.0](https://github.com/pelotech/smolbento/compare/v0.32.1...v0.33.0) (2026-11-20)


### Features

* **cli:** bento cp copies a directory out of a sandbox ([#184](https://github.com/pelotech/smolbento/issues/184)) ([a44ea84](https://github.com/pelotech/smolbento/commit/a44ea842747b884ba7efe84f8edf664dca5313ff))
* **kits:** apply credential@1 inject schemes in v3, and read v2 through v3 ([#185](https://github.com/pelotech/smolbento/issues/185)) ([37a85ec](https://github.com/pelotech/smolbento/commit/37a85ecdae0e577ce9472db9a635ce6041ea6521))
* **secret:** hand running sandboxes a new secret value at once ([#177](https://github.com/pelotech/smolbento/issues/177)) ([0a88c4e](https://github.com/pelotech/smolbento/commit/0a88c4e87069accfe16c68633a2bcf6dd8d1c799))


### Bug Fixes

* launch published v2 workloads, keep others' MCP rules on a failed create, and tidy ([#179](https://github.com/pelotech/smolbento/issues/179)) ([7a3714e](https://github.com/pelotech/smolbento/commit/7a3714e413dfa870935613760a9ef3c696e22332))


### Refactors

* **builder:** copy the kit in and the build out with machine files ([#178](https://github.com/pelotech/smolbento/issues/178)) ([2ad9c9c](https://github.com/pelotech/smolbento/commit/2ad9c9c590b3a1e216d6c18044825109bf6b6c44))
* **kits:** make Kit.v2 the one record of a kit's format ([#182](https://github.com/pelotech/smolbento/issues/182)) ([92d7bae](https://github.com/pelotech/smolbento/commit/92d7bae13cca3401d8f51f776c2a2613efc30190))
* **sandbox:** one definition of the recorded fields; two start layers ([#183](https://github.com/pelotech/smolbento/issues/183)) ([e43003a](https://github.com/pelotech/smolbento/commit/e43003afdd8f7341fb7b3bc2d09fd25c7fd5ef6f))
* share helpers, one policy rule check, simpler kit loading and cli cleanups ([#181](https://github.com/pelotech/smolbento/issues/181)) ([7099bf9](https://github.com/pelotech/smolbento/commit/7099bf948a61938f79638cda82729c772c2b9613))


### Chores

* **smolvm:** pin 1.35.5 ([#175](https://github.com/pelotech/smolbento/issues/175)) ([42090fd](https://github.com/pelotech/smolbento/commit/42090fd034d41beb64fd64eb520975a958788d8f))


### Tests

* share sandbox, policy, secret and capability fixtures ([#180](https://github.com/pelotech/smolbento/issues/180)) ([e506247](https://github.com/pelotech/smolbento/commit/e5062472ef99d5184ec5dc226230b26d628a7b3b))

## [0.32.1](https://github.com/pelotech/smolbento/compare/v0.32.0...v0.32.1) (2026-11-19)


### Bug Fixes

* **builder:** start dockerd before every build instead of trusting the first start ([#174](https://github.com/pelotech/smolbento/issues/174)) ([2e3405a](https://github.com/pelotech/smolbento/commit/2e3405ae86901fd60e373f9601fe942bfad9ef96))


### Tests

* **e2e:** trace creates in CI, and stop a hung test after 5 minutes ([#171](https://github.com/pelotech/smolbento/issues/171)) ([5fa356b](https://github.com/pelotech/smolbento/commit/5fa356bcdc070f3a743a2fdb7306748e97de0007))

## [0.32.0](https://github.com/pelotech/smolbento/compare/v0.31.1...v0.32.0) (2026-11-18)


### Features

* **kits:** expand kit references inside a capability's config before reading it ([#164](https://github.com/pelotech/smolbento/issues/164)) ([cbc3990](https://github.com/pelotech/smolbento/commit/cbc3990818339da989f107f211c9e17d6cf8ec78))
* **kits:** read capability groups and apply each whole or not at all ([#161](https://github.com/pelotech/smolbento/issues/161)) ([d8159ea](https://github.com/pelotech/smolbento/commit/d8159ea64d8d8a1f439bb919171a9e64c099e5dd))


### Refactors

* **kits:** build a v2 kit's hooks and files as v3 configs ([#167](https://github.com/pelotech/smolbento/issues/167)) ([0ee9177](https://github.com/pelotech/smolbento/commit/0ee9177b8c4d20f67f9064113196015b0ea8a7fd))
* **kits:** decide what kit add must recreate by capability type ([#165](https://github.com/pelotech/smolbento/issues/165)) ([cfadf91](https://github.com/pelotech/smolbento/commit/cfadf9164266b6f26b7a96a0735f201428846803))
* **kits:** read every v3 descriptor in its published form ([#166](https://github.com/pelotech/smolbento/issues/166)) ([3fddbe1](https://github.com/pelotech/smolbento/commit/3fddbe11bb400872a4590fd1c0effee741926b40))


### Chores

* **deps:** update cachix/install-nix-action action to v31.11.4 ([#163](https://github.com/pelotech/smolbento/issues/163)) ([0f0b48d](https://github.com/pelotech/smolbento/commit/0f0b48d88c551c174afd33b282a9ebb5fa820517))
* **deps:** update cachix/install-nix-action action to v31.11.5 ([#169](https://github.com/pelotech/smolbento/issues/169)) ([b701152](https://github.com/pelotech/smolbento/commit/b701152d10ed67045583f914e5a7323b2e88131a))


### Tests

* **e2e:** run every local-kit build test in the builder group ([#168](https://github.com/pelotech/smolbento/issues/168)) ([a7b4bc7](https://github.com/pelotech/smolbento/commit/a7b4bc74705be430b45f63d96a8dc221d01d46e8))

## [0.31.1](https://github.com/pelotech/smolbento/compare/v0.31.0...v0.31.1) (2026-11-17)


### Bug Fixes

* **kits:** lay out agent context as the kit spec's suite expects ([#157](https://github.com/pelotech/smolbento/issues/157)) ([ca28d3d](https://github.com/pelotech/smolbento/commit/ca28d3dae7082e0226f13eba50c6b339451839d3))
* **kits:** load kits the spec allows and check [@2](https://github.com/2) entries as it says ([#159](https://github.com/pelotech/smolbento/issues/159)) ([6491558](https://github.com/pelotech/smolbento/commit/6491558f84ccf42a414530ab036829f9e4612eab))


### Chores

* **smolvm:** pin 1.35.3 and drop the empty allow-list workaround ([#160](https://github.com/pelotech/smolbento/issues/160)) ([b0482a0](https://github.com/pelotech/smolbento/commit/b0482a0be157d225a10223120ecce0c8d01fa060))

## [0.31.0](https://github.com/pelotech/smolbento/compare/v0.30.0...v0.31.0) (2026-11-17)


### Features

* **kits:** write agent context to every agent file a kit names ([#153](https://github.com/pelotech/smolbento/issues/153)) ([21fbb04](https://github.com/pelotech/smolbento/commit/21fbb04a398c67800e793b00b85972abcdfae424))


### Bug Fixes

* **kits:** write agent-context@2 text into the agent file ([#152](https://github.com/pelotech/smolbento/issues/152)) ([07d83a9](https://github.com/pelotech/smolbento/commit/07d83a93cd40a6fb073e0ad7f347cd2c20351be2))


### Chores

* **deps:** accept the chrono and humantime unmaintained advisories ([#154](https://github.com/pelotech/smolbento/issues/154)) ([41ec4d0](https://github.com/pelotech/smolbento/commit/41ec4d0cc28b19873b4cb6001b67cca7d8ad6b69))
* **main:** release nix-kit 0.2.1 ([#156](https://github.com/pelotech/smolbento/issues/156)) ([36d515c](https://github.com/pelotech/smolbento/commit/36d515c4af503744164542bf70615e4823f228af))

## [0.30.0](https://github.com/pelotech/smolbento/compare/v0.29.1...v0.30.0) (2026-11-16)


### Features

* **cli:** approval options, HTTP rule removal, UDP checks and other sbx 0.53 flags ([#149](https://github.com/pelotech/smolbento/issues/149)) ([1e59e40](https://github.com/pelotech/smolbento/commit/1e59e40a6f62eea2ecad1e20bb2e6a015afcd0f0))
* **cli:** policy ls in sbx 0.53's layout, with its filters ([#148](https://github.com/pelotech/smolbento/issues/148)) ([071585f](https://github.com/pelotech/smolbento/commit/071585f1d48c687f16a3c10b87f0b7d52d3c6a8b))


### Bug Fixes

* **kits:** read a kit as v3 by its schemaVersion, as sbx does ([#151](https://github.com/pelotech/smolbento/issues/151)) ([61b0d33](https://github.com/pelotech/smolbento/commit/61b0d339719d9fd31b8f77065944e6a6ceb0bee8))


### Chores

* **deps:** update pre-commit hook kjanat/actionlint to v1.17.1 ([#146](https://github.com/pelotech/smolbento/issues/146)) ([13821e4](https://github.com/pelotech/smolbento/commit/13821e45e660cbcaa6805e1e76961a3b8d828de1))

## [0.29.1](https://github.com/pelotech/smolbento/compare/v0.29.0...v0.29.1) (2026-11-16)


### Bug Fixes

* **kits:** kit add refuses a kit that exports an argument as a variable ([#142](https://github.com/pelotech/smolbento/issues/142)) ([fa6f4ed](https://github.com/pelotech/smolbento/commit/fa6f4edca043dc6aa3d0f5d9a7989ed7d27a8e83))


### Refactors

* drop the 0.15 label shim and the non-Unix branches ([#145](https://github.com/pelotech/smolbento/issues/145)) ([a8ef95a](https://github.com/pelotech/smolbento/commit/a8ef95a0a1df0945d7aba8844bafd2c316d1013d))
* move six test modules out and split the args and registry files ([#141](https://github.com/pelotech/smolbento/issues/141)) ([2a8dd66](https://github.com/pelotech/smolbento/commit/2a8dd66ce6908e60b5c034f01d613b576840f2c3))
* share test helpers and remove duplicated code ([#144](https://github.com/pelotech/smolbento/issues/144)) ([bc4d599](https://github.com/pelotech/smolbento/commit/bc4d599a0024dcfb79782aecb20275291b67a23c))


### Chores

* **deps:** lock file maintenance ([#140](https://github.com/pelotech/smolbento/issues/140)) ([d616534](https://github.com/pelotech/smolbento/commit/d616534c9988323435b32f4c7e2895f824fe2688))

## [0.29.0](https://github.com/pelotech/smolbento/compare/v0.28.1...v0.29.0) (2026-11-15)


### Features

* **cli:** more sbx flags and aliases, help text for every argument, simpler output code ([#138](https://github.com/pelotech/smolbento/issues/138)) ([d530f2e](https://github.com/pelotech/smolbento/commit/d530f2edb3f4c2a888e1152fac42b2106740743f))
* **cli:** sbx's error format and --json on more commands; split tests and the usage guide ([#135](https://github.com/pelotech/smolbento/issues/135)) ([694d0f7](https://github.com/pelotech/smolbento/commit/694d0f75d430d8452d777b4af6d17d74b76e21ec))
* **kits:** a built-in git-signing kit ([#139](https://github.com/pelotech/smolbento/issues/139)) ([aedeab0](https://github.com/pelotech/smolbento/commit/aedeab0002282df7c95404293825383a13b7fbd3))


### Chores

* **main:** release nix-kit 0.2.0 ([#136](https://github.com/pelotech/smolbento/issues/136)) ([8fbbb6e](https://github.com/pelotech/smolbento/commit/8fbbb6ed87b74ba7d418e6fc92e0c03965744e04))

## [0.28.1](https://github.com/pelotech/smolbento/compare/v0.28.0...v0.28.1) (2026-11-15)


### Bug Fixes

* **kits:** no key prompt in Claude, one agent guide, quiet kit warnings ([#130](https://github.com/pelotech/smolbento/issues/130)) ([2b6b301](https://github.com/pelotech/smolbento/commit/2b6b301d76bace6015da896a7313fcf3f68c1f44))


### Chores

* **main:** release nix-kit 0.1.0 ([#129](https://github.com/pelotech/smolbento/issues/129)) ([4407340](https://github.com/pelotech/smolbento/commit/44073409d986ba2d5c9f4440239e5c562fabf09e))
* stop installing smolvm on the runners ([#134](https://github.com/pelotech/smolbento/issues/134)) ([505d0d9](https://github.com/pelotech/smolbento/commit/505d0d9dd21a852cea86ea159ad394d1e86d575e))


### Docs

* **readme:** a scripted demo GIF of bento run claude ([#132](https://github.com/pelotech/smolbento/issues/132)) ([3cf865d](https://github.com/pelotech/smolbento/commit/3cf865da5cebe2616210fa6665ee6fc080627042))

## [0.28.0](https://github.com/pelotech/smolbento/compare/v0.27.0...v0.28.0) (2026-11-15)


### Features

* bring a pinned smolvm and name the command bento ([#128](https://github.com/pelotech/smolbento/issues/128)) ([29a92e4](https://github.com/pelotech/smolbento/commit/29a92e42018dde49baa5410f9903f75389988699))
* built-in agents are sbx's published kits ([#126](https://github.com/pelotech/smolbento/issues/126)) ([85bddb6](https://github.com/pelotech/smolbento/commit/85bddb6981f4489d81a42197552095822e9922a8))


### Chores

* **deps:** pin dependencies ([#127](https://github.com/pelotech/smolbento/issues/127)) ([57a6e03](https://github.com/pelotech/smolbento/commit/57a6e03048aa1940052725d3572df00c000a096c))


### Tests

* faster, offline unit tests and no silent e2e passes ([#124](https://github.com/pelotech/smolbento/issues/124)) ([d10aa7b](https://github.com/pelotech/smolbento/commit/d10aa7bda1ef42e5b1e4a72cdc80ea20a87b30c8))

## [0.27.0](https://github.com/pelotech/smolbento/compare/v0.26.1...v0.27.0) (2026-11-15)


### Features

* sbx 0.51–0.53 parity and same-name folder fix ([#123](https://github.com/pelotech/smolbento/issues/123)) ([ed91121](https://github.com/pelotech/smolbento/commit/ed911217e075d28441456b28bf7ade879c84573a))


### Chores

* sign and check the nix kit with the released smolbento ([#121](https://github.com/pelotech/smolbento/issues/121)) ([8c08972](https://github.com/pelotech/smolbento/commit/8c08972da65f0cbd6524c3419edd1318c4b39b5f))

## [0.26.1](https://github.com/pelotech/smolbento/compare/v0.26.0...v0.26.1) (2026-11-14)


### Bug Fixes

* **kits:** keep release-please from rewriting nix.yaml ([#119](https://github.com/pelotech/smolbento/issues/119)) ([d5cc377](https://github.com/pelotech/smolbento/commit/d5cc377a758839709f6842f7a1e55a5ba49aad7b))


### Chores

* **main:** release nix-kit 0.0.1 ([#116](https://github.com/pelotech/smolbento/issues/116)) ([3ff5fcc](https://github.com/pelotech/smolbento/commit/3ff5fcca51c50b122fdc6c5f81193acb9084c736))
* **main:** release nix-kit 0.0.2 ([#120](https://github.com/pelotech/smolbento/issues/120)) ([c58c17d](https://github.com/pelotech/smolbento/commit/c58c17df917595faffc176b676231ea5e0977aea))

## [0.26.0](https://github.com/pelotech/smolbento/compare/v0.25.1...v0.26.0) (2026-11-14)


### Features

* **kits:** add the nix kit (Phase 8) ([#115](https://github.com/pelotech/smolbento/issues/115)) ([c0f3429](https://github.com/pelotech/smolbento/commit/c0f3429ab4f59ec0be212e9c2acdbcf8dbd909cf))

## [0.25.1](https://github.com/pelotech/smolbento/compare/v0.25.0...v0.25.1) (2026-11-14)


### Bug Fixes

* move to smolvm 1.35 and idmap fix ([#113](https://github.com/pelotech/smolbento/issues/113)) ([882e4fa](https://github.com/pelotech/smolbento/commit/882e4fa7bf150d276e230964752110bfada5302b))

## [0.25.0](https://github.com/pelotech/smolbento/compare/v0.24.0...v0.25.0) (2026-11-14)


### Features

* **ssh:** setup ssh and ssh NAME.sbx (5h) ([#111](https://github.com/pelotech/smolbento/issues/111)) ([57c96c1](https://github.com/pelotech/smolbento/commit/57c96c1bb42d17dd951b1c8c516c476f4ce2417e))

## [0.24.0](https://github.com/pelotech/smolbento/compare/v0.23.0...v0.24.0) (2026-11-14)


### Features

* **sandbox:** serve the SSH agent and bridge for the sandbox's life, and run a workload's Entrypoint at boot ([#109](https://github.com/pelotech/smolbento/issues/109)) ([d5e78f6](https://github.com/pelotech/smolbento/commit/d5e78f6d7232fa22f96f913e55b6fa12cb46339d))

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
