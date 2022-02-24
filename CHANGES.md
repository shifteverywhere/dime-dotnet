# CHANGES

## Version 1.0.1 - 2022-02-24
- Allows for systemName to be set when issuing a new identity. If none is provided, then the systemName from the issuing identity is used
- Adds an option to exclude the trust chain from an issued identity, allows for more flexible usage and trust verification
- Method Identity:IsTrusted() and Identity:IsTrusted(Identity) is added for more fine-grained verification of trust chains
- Method Identity:VerifyTrust() is deprecated and will be removed in future versions

**NOTE:** *Version 1.0.1 includes changes that will break 1.0.0. These are only code-breaking changes, so all previously issued identities and other created Di:ME items will continue to work.*


## Version 1.0.0 - 2022-02-19
- Official version 1.0.0 (**Hurray!**)

**Copyright © 2022 Shift Everywhere AB. All rights reserved.**
