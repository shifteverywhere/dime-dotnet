# CHANGES

## Version 1.0.4 - 2022-05-04
- Minor fix to prepare for an upcoming change that allows for more than one item to be linked to a Message item.

**NOTE:** *Version 1.0.4 is most likely the last version that will support .NET 5, this since end-of-support for .NET 5 is May 10, 2022. Future versions of Dime will support .NET 6 instead. *

## Version 1.0.3 - 2022-03-29
- Includes a fix where the public copy of a key did not receive the claims from the source key.

## Version 1.0.2 - 2022-03-11
- Includes documentation in packaged NUGET to support IntelliSense (etc.)

## Version 1.0.1 - 2022-02-24
- Allows for systemName to be set when issuing a new identity. If none is provided, then the systemName from the issuing identity is used
- Adds an option to exclude the trust chain from an issued identity, allows for more flexible usage and trust verification
- Method Identity:IsTrusted() and Identity:IsTrusted(Identity) is added for more fine-grained verification of trust chains
- Method Identity:VerifyTrust() is deprecated and will be removed in future versions

**NOTE:** *Version 1.0.1 includes changes that will break 1.0.0. These are only code-breaking changes, so all previously issued identities and other created Di:ME items will continue to work.*


## Version 1.0.0 - 2022-02-19
- Official version 1.0.0 (**Hurray!**)

**Copyright © 2022 Shift Everywhere AB. All rights reserved.**
