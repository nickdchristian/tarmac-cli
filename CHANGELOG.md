# Changelog

## [0.1.5](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.4...v0.1.5) (2026-10-20)


### Features

* **access:** add non-root bootstrap role with a least-privilege policy ([#15](https://github.com/nickdchristian/tarmac-cli/issues/15)) ([71f31ad](https://github.com/nickdchristian/tarmac-cli/commit/71f31ad4ec67b0aa1e4fd426a72bb3e8b8662ba9))
* add cloudtrail.retention_days to cap CloudTrail log storage ([#40](https://github.com/nickdchristian/tarmac-cli/issues/40)) ([32084ed](https://github.com/nickdchristian/tarmac-cli/commit/32084ed62a9eedf6259af05428bd3480c68fa901))
* deny member-account closure in the shipped SCPs ([#30](https://github.com/nickdchristian/tarmac-cli/issues/30)) ([24c695f](https://github.com/nickdchristian/tarmac-cli/commit/24c695fe6365597ca2fe326a318196de719ae886))
* **logging:** add run context, redaction, audit events and an optional JSON-lines run log ([#32](https://github.com/nickdchristian/tarmac-cli/issues/32)) ([fad0102](https://github.com/nickdchristian/tarmac-cli/commit/fad0102c5be3bd430355af98e91b5a4762c3a928))
* **logging:** add tarmac logs command ([#37](https://github.com/nickdchristian/tarmac-cli/issues/37)) ([31dc84a](https://github.com/nickdchristian/tarmac-cli/commit/31dc84a8501ad89c00701de0c9f343741f8fb33e))
* **logging:** audit events for baseline and security changes ([#35](https://github.com/nickdchristian/tarmac-cli/issues/35)) ([5d10b78](https://github.com/nickdchristian/tarmac-cli/commit/5d10b78eea1d6d2b287623418ef61f8866197435))
* **logging:** audit events for governance changes ([#34](https://github.com/nickdchristian/tarmac-cli/issues/34)) ([b640861](https://github.com/nickdchristian/tarmac-cli/commit/b64086138d27832833abaeb1c7db4d5fc37ab68f))
* **logging:** audit events for identity and teardown ([#36](https://github.com/nickdchristian/tarmac-cli/issues/36)) ([837da3d](https://github.com/nickdchristian/tarmac-cli/commit/837da3d0b1ee54de3b953afad7c41fbeae02e4d8))
* **logging:** record every AWS call and tie runs to CloudTrail ([#33](https://github.com/nickdchristian/tarmac-cli/issues/33)) ([08da3a0](https://github.com/nickdchristian/tarmac-cli/commit/08da3a056a22fe34d22bb4b7879a8ad30d06096a))


### Bug Fixes

* handle concurrent organization creation and cover organization bootstrap ([#20](https://github.com/nickdchristian/tarmac-cli/issues/20)) ([b14422e](https://github.com/nickdchristian/tarmac-cli/commit/b14422e25820f3f76f5c7a1bb7969d267eff544d))
* harden the account lifecycle from fresh account to teardown and redeploy ([#14](https://github.com/nickdchristian/tarmac-cli/issues/14)) ([cd1ce53](https://github.com/nickdchristian/tarmac-cli/commit/cd1ce53d559016c5a6c8fecefbcd93d207564db2))
* leave a default VPC intact when network interfaces are attached ([#31](https://github.com/nickdchristian/tarmac-cli/issues/31)) ([7621f0d](https://github.com/nickdchristian/tarmac-cli/commit/7621f0db99bbc7fbe7e152d37b3bc4323d19d59a))
* make cloudtrail.enable_kms false skip the log archive KMS key ([#39](https://github.com/nickdchristian/tarmac-cli/issues/39)) ([a7845d8](https://github.com/nickdchristian/tarmac-cli/commit/a7845d8137df8ae178d0509dde23eabe09144029))
* paginate SNS topic and subscription checks in preflight ([#22](https://github.com/nickdchristian/tarmac-cli/issues/22)) ([ad7c553](https://github.com/nickdchristian/tarmac-cli/commit/ad7c553fa3119639d6b63d1b1ae42482549c26f0))
* refresh assumed-role credentials instead of caching static keys ([#21](https://github.com/nickdchristian/tarmac-cli/issues/21)) ([3dad66f](https://github.com/nickdchristian/tarmac-cli/commit/3dad66f00be7551c05a16f77edc4d70233265f57))
* refuse to suspend an account when no Suspended OU exists ([#29](https://github.com/nickdchristian/tarmac-cli/issues/29)) ([d54e81d](https://github.com/nickdchristian/tarmac-cli/commit/d54e81d322c8db4d1e7103b4ad9e0c1c9f3296e3))
* reject SCP targets that are not the root or a declared OU ([#28](https://github.com/nickdchristian/tarmac-cli/issues/28)) ([227124f](https://github.com/nickdchristian/tarmac-cli/commit/227124f3176a38dfca7f97f50fb6b54f5220d676))
* resolve architecture, security, and reliability audit findings ([#13](https://github.com/nickdchristian/tarmac-cli/issues/13)) ([7f18203](https://github.com/nickdchristian/tarmac-cli/commit/7f182033e95cb3444740fe3dcff069465c8543f8))
* resolve SCP policy files relative to the config directory ([#27](https://github.com/nickdchristian/tarmac-cli/issues/27)) ([968ebcb](https://github.com/nickdchristian/tarmac-cli/commit/968ebcb64716d974fc5078313fbe85caedfe204e))
* tolerate unreadable or invalid SCP JSON when comparing policies ([#26](https://github.com/nickdchristian/tarmac-cli/issues/26)) ([98deecc](https://github.com/nickdchristian/tarmac-cli/commit/98deecce876c71d1144d7503524a95a216c315b2))


### Documentation

* add SECURITY.md, CONTRIBUTING.md, and update README dev guide ([#10](https://github.com/nickdchristian/tarmac-cli/issues/10)) ([e04360f](https://github.com/nickdchristian/tarmac-cli/commit/e04360f775231d746935dd6ce31d16c1fa3f0e97))

## [0.1.4](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.3...v0.1.4) (2026-10-06)


### Documentation

* bust camo cache on pypi badges ([1383211](https://github.com/nickdchristian/tarmac-cli/commit/13832118793b3b72f71e11fe59493fcbabd5b42c))
* update python versions badge to dynamic pypi badge ([2bd9018](https://github.com/nickdchristian/tarmac-cli/commit/2bd9018eb38894949252c163f7bb6e357568b973))

## [0.1.3](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.2...v0.1.3) (2026-10-06)


### Bug Fixes

* resolve pypi release pipeline skipping and sync package metadata ([#5](https://github.com/nickdchristian/tarmac-cli/issues/5)) ([fbf5901](https://github.com/nickdchristian/tarmac-cli/commit/fbf590163ee8d13c4c5c5a84cb76a96192aebae6))

## [0.1.2](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.1...v0.1.2) (2026-10-06)


### Features

* initial release of tarmac enterprise landing zone engine ([3fbcd71](https://github.com/nickdchristian/tarmac-cli/commit/3fbcd712c882f9e93e9c2c914ed32c8e7d3082bb))


### Documentation

* streamline and modernize readme for clarity ([#3](https://github.com/nickdchristian/tarmac-cli/issues/3)) ([27d0c94](https://github.com/nickdchristian/tarmac-cli/commit/27d0c94173b594766aae1703f5c07919440f5574))

## [0.1.1](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.0...v0.1.1) (2026-10-06)


### Features

* initial release of tarmac enterprise landing zone engine ([3fbcd71](https://github.com/nickdchristian/tarmac-cli/commit/3fbcd712c882f9e93e9c2c914ed32c8e7d3082bb))


### Documentation

* streamline and modernize readme for clarity ([#3](https://github.com/nickdchristian/tarmac-cli/issues/3)) ([27d0c94](https://github.com/nickdchristian/tarmac-cli/commit/27d0c94173b594766aae1703f5c07919440f5574))
