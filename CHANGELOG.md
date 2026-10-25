# Changelog

Every notable change to scudo, by release. Generated from the commit history
with [git-cliff](https://git-cliff.org); the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-10-25

### Features

- **profile:** Env and --env copy named variables into the sandbox ([851d3fe](https://github.com/mtorromeo/scudo/commit/851d3fe3cf0e3ac7186dfc283b23ece1bd0fbf09))
- **profile:** Inherit the environment by default, deny_env and allow_env with globs ([8f60e86](https://github.com/mtorromeo/scudo/commit/8f60e86f356a5478ec453c4e8754a185a7d15e68))
- **profile:** Deny_env removes variables from the service manager's environment ([374c955](https://github.com/mtorromeo/scudo/commit/374c955577cd034dc79b31a43ef4738d476cc84e))

## [0.2.0] - 2026-10-19

### Features

- **config:** Regex and command-line match patterns, replace = ["match"] ([916af9f](https://github.com/mtorromeo/scudo/commit/916af9f20bdd111cdbfb75998d1393f50cf63a7f))
- **broker:** A matched profile saying delegable = false stops a delegated run ([1242645](https://github.com/mtorromeo/scudo/commit/1242645e90ee0132251bf4924f5b4ac715d0df90))
- **examples:** Cargo-install matches cargo install and binstall on its own ([7f120b0](https://github.com/mtorromeo/scudo/commit/7f120b084761aba4dfc2806518db734469751bed))
- **examples:** Npm-publish matches npm publish, cargo-install covers install-update ([208a8a9](https://github.com/mtorromeo/scudo/commit/208a8a98d714a6c7005b8e1066386f2329b9c595))
- **examples:** Npm-publish becomes npm-auth, covering npm login too ([d6d07cb](https://github.com/mtorromeo/scudo/commit/d6d07cbc8eb4c648d24a475c88c076abaf623214))
- **cli:** --fs-hide, --fs-read and --fs-write change file access for one run ([26f9be4](https://github.com/mtorromeo/scudo/commit/26f9be46bb83e112947bfbd058c4817c72ec5ae2))

### Bug fixes

- **policy:** Mount scudo-bpfd's socket into the sandbox on its own ([253434d](https://github.com/mtorromeo/scudo/commit/253434deee0ec1cebaadea90d9c57be2ae967ba6))
- **profile:** A variable inside a path component is not made absolute ([904a10a](https://github.com/mtorromeo/scudo/commit/904a10aa15db230a9d2482745a928f6aea03f4b0))
- **filesystem:** Grants inside directories the unit replaces are bind mounts ([dc45e8b](https://github.com/mtorromeo/scudo/commit/dc45e8bec8a3d58f9e71018da5924420b0c8a04f))

### Tests

- **examples:** Follow npm-publish's rename to npm-auth ([de65f47](https://github.com/mtorromeo/scudo/commit/de65f472263c023fc363140504f0549e648a1799))

[0.3.0]: https://github.com/mtorromeo/scudo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mtorromeo/scudo/compare/v0.1.0...v0.2.0

