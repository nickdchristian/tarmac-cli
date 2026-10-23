# Changelog

## [0.4.2](https://github.com/nickdchristian/tarmac-cli/compare/v0.4.1...v0.4.2) (2026-10-23)


### Bug Fixes

* issues found deploying and tearing down against a real AWS organization ([#102](https://github.com/nickdchristian/tarmac-cli/issues/102)) ([60400ea](https://github.com/nickdchristian/tarmac-cli/commit/60400eabecf81d71a9c9dba2e68abe08f4d6d71a))

## [0.4.1](https://github.com/nickdchristian/tarmac-cli/compare/v0.4.0...v0.4.1) (2026-10-22)


### Bug Fixes

* **import:** validate a relative --config-dir where the files were written ([#100](https://github.com/nickdchristian/tarmac-cli/issues/100)) ([fc4b9e4](https://github.com/nickdchristian/tarmac-cli/commit/fc4b9e45474e31a9de1156aa2cb8bb56e6444631))

## [0.4.0](https://github.com/nickdchristian/tarmac-cli/compare/v0.3.1...v0.4.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **import:** `tarmac import --force` is removed; import always overwrites.
* **inventory:** run `tarmac bootstrap` again to grant the deployment permission set access to the bucket, then `tarmac deploy --phase 1` (or a full deploy) before deploying single phases. TARMAC_INVENTORY_FILE is no longer read.

### Features

* **import:** overwrite existing config files, keeping changed ones as .bak ([#98](https://github.com/nickdchristian/tarmac-cli/issues/98)) ([44a6c97](https://github.com/nickdchristian/tarmac-cli/commit/44a6c9787eea4fe9f6e2decba2a84cf6e54258f0))
* **inventory:** store the inventory in a bucket in the management account ([#96](https://github.com/nickdchristian/tarmac-cli/issues/96)) ([31f7ff9](https://github.com/nickdchristian/tarmac-cli/commit/31f7ff984c9507c91bbc6a55a9859a8193113936))

## [0.3.1](https://github.com/nickdchristian/tarmac-cli/compare/v0.3.0...v0.3.1) (2026-10-22)


### Documentation

* rewrite the README to be shorter and easier to follow ([#91](https://github.com/nickdchristian/tarmac-cli/issues/91)) ([a43663a](https://github.com/nickdchristian/tarmac-cli/commit/a43663a186895ae2900464f780ff04f859ec630e))

## [0.3.0](https://github.com/nickdchristian/tarmac-cli/compare/v0.2.0...v0.3.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **bootstrap:** 'tarmac deploy --phase 1' no longer runs as root. Enable IAM Identity Center first (it creates the organization) and run 'tarmac access sso'.

### Features

* **bootstrap:** run tarmac as an IAM Identity Center login created by tarmac bootstrap ([#89](https://github.com/nickdchristian/tarmac-cli/issues/89)) ([14e8110](https://github.com/nickdchristian/tarmac-cli/commit/14e8110c73120fb41319cd821a8a98cb24f1d1e8))

## [0.2.0](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.10...v0.2.0) (2026-10-21)


### ⚠ BREAKING CHANGES

* **cli:** Removed commands and their replacements: `doctor` -> `preflight`; `apply`, `account apply`, `account plan` -> `deploy run --phase 4 [--dry-run]`; `drift` -> `status --detail` (`--strict` unchanged); `access check` -> `info --strict`; `org bootstrap`, `org contacts`, `org root-access`, `org activate-cost-tags`, `org cleanup-vpc` -> `deploy run --phase 1`; `ou sync`, `org scp plan`, `org scp apply` -> `deploy run --phase 2`; `baseline cloudtrail`, `baseline logs` -> `deploy run --phase 3`; `baseline backend`, `baseline audit`, `baseline security`, `baseline harden-*` -> `deploy run --phase 5`; `identity sync` -> `deploy run --phase 6`; `deploy teardown` -> `deploy destroy`; `baseline anomaly-status` -> `account anomaly-status`. `--sse-s3` and `--s3-only` are replaced by `cloudtrail.enable_kms: false` and `terraform_backend.enable_dynamodb: false`.

### Features

* **cli:** simplify the command set and plan dry runs from live AWS state ([#87](https://github.com/nickdchristian/tarmac-cli/issues/87)) ([d750282](https://github.com/nickdchristian/tarmac-cli/commit/d750282c3d403a461cca9d900e0fc2c0f44a4858))

## [0.1.10](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.9...v0.1.10) (2026-10-21)


### Bug Fixes

* **deploy:** restore teardown confirmation prompt and harden CFN templates ([#85](https://github.com/nickdchristian/tarmac-cli/issues/85)) ([6b08c44](https://github.com/nickdchristian/tarmac-cli/commit/6b08c44b38799b28bd7ae7a23a9937914f4bb863))
* **drift:** reconcile account tag hierarchy and drift inspection checks ([#83](https://github.com/nickdchristian/tarmac-cli/issues/83)) ([2ac4513](https://github.com/nickdchristian/tarmac-cli/commit/2ac4513b62c2130dac84d04d833b7e1a1a97bcd9))
* **governance:** resolve CFN import, logical ID collision, and SSO teardown bugs ([#84](https://github.com/nickdchristian/tarmac-cli/issues/84)) ([ab44883](https://github.com/nickdchristian/tarmac-cli/commit/ab448839105878aae136eaeb59c9c66c32f37f64))

## [0.1.9](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.8...v0.1.9) (2026-10-21)


### Features

* **budget:** forecast alert, on by default at 100 percent ([#64](https://github.com/nickdchristian/tarmac-cli/issues/64)) ([55f5b1a](https://github.com/nickdchristian/tarmac-cli/commit/55f5b1a570e508a991ad7188334205b47bfb297b))
* **cloudtrail:** opt-in S3 Object Lock on the log bucket, with a strong recommendation ([#66](https://github.com/nickdchristian/tarmac-cli/issues/66)) ([03ffd90](https://github.com/nickdchristian/tarmac-cli/commit/03ffd90fc5a59560027314b0f65fc62c71071792))
* **config:** optional AWS Config recorders in every account ([#69](https://github.com/nickdchristian/tarmac-cli/issues/69)) ([a299135](https://github.com/nickdchristian/tarmac-cli/commit/a299135038293cc60d472de30ab6fad5d540f456))
* **preflight:** warn when the deployed access role is older than this release ([#70](https://github.com/nickdchristian/tarmac-cli/issues/70)) ([068f51d](https://github.com/nickdchristian/tarmac-cli/commit/068f51db901ab94ba3c77032d1b8bff75a6f4a8a))
* **security:** alert by email when the root user is used in the management account ([#78](https://github.com/nickdchristian/tarmac-cli/issues/78)) ([af54026](https://github.com/nickdchristian/tarmac-cli/commit/af54026a5f911c439af7cb7deb05a7c304f72095))
* **securityhub:** central configuration policy for the organization ([#68](https://github.com/nickdchristian/tarmac-cli/issues/68)) ([d0a039d](https://github.com/nickdchristian/tarmac-cli/commit/d0a039d53a2676b1a5afbbb41fea4439816a7de7))
* **stacks:** protect data and access stacks from accidental deletion ([#77](https://github.com/nickdchristian/tarmac-cli/issues/77)) ([ce6c7db](https://github.com/nickdchristian/tarmac-cli/commit/ce6c7db633dfed5e0df51a9e04ad41e6465f3c92))
* stop before overwriting SCPs or budgets tarmac did not create ([#67](https://github.com/nickdchristian/tarmac-cli/issues/67)) ([6c75968](https://github.com/nickdchristian/tarmac-cli/commit/6c75968ac87fa7d32d5a0fad77e08aa7099c81c1))
* **terraform:** lock state in S3 by default and keep an existing DynamoDB table ([#76](https://github.com/nickdchristian/tarmac-cli/issues/76)) ([5562eb7](https://github.com/nickdchristian/tarmac-cli/commit/5562eb7aea395f07a10173debf14f9e1b6a443db))


### Bug Fixes

* **access:** let the role clean up default VPCs in the management account ([#58](https://github.com/nickdchristian/tarmac-cli/issues/58)) ([1ffab56](https://github.com/nickdchristian/tarmac-cli/commit/1ffab56299298485a0233718802f13f3911c3c6c))
* audit existing Identity Center users and groups, name accounts by ID in close hint ([#59](https://github.com/nickdchristian/tarmac-cli/issues/59)) ([ae97286](https://github.com/nickdchristian/tarmac-cli/commit/ae9728687b751a04e8f0e55e2462304ea8c88d2d))
* **baseline:** record the definition of a budget tarmac replaces ([#61](https://github.com/nickdchristian/tarmac-cli/issues/61)) ([2b5e8c1](https://github.com/nickdchristian/tarmac-cli/commit/2b5e8c1068c29b334e27bacf630d7372d5cb1c5a))
* **ci:** set GH_REPO so release-please can dispatch the publish workflow ([#57](https://github.com/nickdchristian/tarmac-cli/issues/57)) ([5a886cf](https://github.com/nickdchristian/tarmac-cli/commit/5a886cf55c3b058f1b4cafe3a4919e29bb6d13ef))
* **cli:** check AWS credentials up front in deploy, destroy and import ([#62](https://github.com/nickdchristian/tarmac-cli/issues/62)) ([20ed3a6](https://github.com/nickdchristian/tarmac-cli/commit/20ed3a6643310bca14e1ca3bb1e93a61e3fba073))
* **cloudtrail:** default log encryption to SSE-S3 and keep an existing KMS key ([#80](https://github.com/nickdchristian/tarmac-cli/issues/80)) ([8c60aac](https://github.com/nickdchristian/tarmac-cli/commit/8c60aacc59c58744a03243652d9e43f22ce89415))
* **guardduty:** create detectors with every optional feature off ([#75](https://github.com/nickdchristian/tarmac-cli/issues/75)) ([9e6c20d](https://github.com/nickdchristian/tarmac-cli/commit/9e6c20d136c4c1e1afdc9414c1759c55a21d9a06))
* **import:** only assign permission sets on accounts written to accounts.yaml ([#55](https://github.com/nickdchristian/tarmac-cli/issues/55)) ([e9d9d21](https://github.com/nickdchristian/tarmac-cli/commit/e9d9d21bdc9ca17a69457cc9701fd459d1085487))
* **scp:** exempt AssumeRoot sessions with the documented aws:AssumedRoot key ([#71](https://github.com/nickdchristian/tarmac-cli/issues/71)) ([8c8cacd](https://github.com/nickdchristian/tarmac-cli/commit/8c8cacddb9216f393458031d93f003b71942ecc8))
* **security:** register the GuardDuty and Security Hub admin in every Region ([#72](https://github.com/nickdchristian/tarmac-cli/issues/72)) ([b69cee2](https://github.com/nickdchristian/tarmac-cli/commit/b69cee22020cf3780b8f7429cf61ca6b4bd3a5e8))
* stop reporting phase 1 complete when management VPC cleanup fails ([#56](https://github.com/nickdchristian/tarmac-cli/issues/56)) ([5749548](https://github.com/nickdchristian/tarmac-cli/commit/5749548f0a97aa1f3074ad0d42562655d8446e37))


### Documentation

* **access:** stop calling the access policy least privilege and warn that the Identity Center Region is hard to change ([#74](https://github.com/nickdchristian/tarmac-cli/issues/74)) ([3fc8a1c](https://github.com/nickdchristian/tarmac-cli/commit/3fc8a1cd6b26045e29a7f3902bf6f0098577e444))
* example SCP protecting GuardDuty and Security Hub from being turned off ([#79](https://github.com/nickdchristian/tarmac-cli/issues/79)) ([e7ff122](https://github.com/nickdchristian/tarmac-cli/commit/e7ff12259fad69968f09b15624a468c9bd6108c5))
* example SCP restricting regions ([#65](https://github.com/nickdchristian/tarmac-cli/issues/65)) ([2a29461](https://github.com/nickdchristian/tarmac-cli/commit/2a2946190306ca62af2bee19f92869bb4bb52b1d))
* **templates:** correct comments that overstated KMS separation of duties and alert scope ([#73](https://github.com/nickdchristian/tarmac-cli/issues/73)) ([c4d2ff2](https://github.com/nickdchristian/tarmac-cli/commit/c4d2ff270b714a1526eadc6f8951867b422b0a82))

## [0.1.8](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.7...v0.1.8) (2026-10-20)


### Bug Fixes

* **ci:** tolerate release runs that open no pull request ([#53](https://github.com/nickdchristian/tarmac-cli/issues/53)) ([1468092](https://github.com/nickdchristian/tarmac-cli/commit/14680921cd634ee8a9fe0fbf08c1a1905a7e269f))

## [0.1.7](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.6...v0.1.7) (2026-10-20)


### Features

* add destroy --everything to remove all tarmac-created resources ([#50](https://github.com/nickdchristian/tarmac-cli/issues/50)) ([ae2ddfd](https://github.com/nickdchristian/tarmac-cli/commit/ae2ddfd05de2ac2df34a9d58c2010bed8a22cb58))
* add tarmac import to generate config from an existing organization ([#49](https://github.com/nickdchristian/tarmac-cli/issues/49)) ([014200e](https://github.com/nickdchristian/tarmac-cli/commit/014200e76617fbdbc79c4415f55925c1e3a32582))

## [0.1.6](https://github.com/nickdchristian/tarmac-cli/compare/v0.1.5...v0.1.6) (2026-10-20)


### Features

* guard against the mistakes that adopting an existing organization invites ([#45](https://github.com/nickdchristian/tarmac-cli/issues/45)) ([4060528](https://github.com/nickdchristian/tarmac-cli/commit/4060528601b9b902b7ea372fc227b89e4ebdc042))


### Bug Fixes

* enable config-multiaccountsetup trusted access before delegating Config ([#43](https://github.com/nickdchristian/tarmac-cli/issues/43)) ([a1db61b](https://github.com/nickdchristian/tarmac-cli/commit/a1db61b9e2b08915ab134cef1de8c04ab786f38b))
* make the run log say what actually changed ([#44](https://github.com/nickdchristian/tarmac-cli/issues/44)) ([0cccbbe](https://github.com/nickdchristian/tarmac-cli/commit/0cccbbe4c5a730886a2c81caec4d918983c45574))


### Documentation

* CloudShell and SSO setup, adopting an existing organization, troubleshooting ([#46](https://github.com/nickdchristian/tarmac-cli/issues/46)) ([d2f0aad](https://github.com/nickdchristian/tarmac-cli/commit/d2f0aad49b821eeeb408f2b682b6c40aac02964a))

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
