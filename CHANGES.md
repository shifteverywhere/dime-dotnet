# CHANGE LOG

## Version 1.2.1 - 2022-10-25
- Conforms to DiME data format version 1.001
- Cryptographic suite changed to 'DSC'
  - Key encoded changes to Base64 (from Base58), massive performance gain
  - 'STN' cryptographic suite still supported, need to set Crypto#setDefaultSuiteName(string) to use it as default
  - Item links created using 'DSC' will not work in versions before 1.2.2
  - Keys, Identities, IIRs (and Messages using 'pub') created using 'DSC' will not work in versions before 1.2.2
- Instance method Item#thumbprint changes name to Item#generateThumbprint (code-breaking change)

## Version 1.2.0 - 2022-10-21
- Full implementation of DiME data format specification (1.000)
- Many methods marked as deprecated in version 1.1.0 and earlier removed
- Introduces KeyRing to hold multiple keys and identities as trusted
  - Removes trusted Identity in Dime and Identity
  - Verify has been reworked to support key ring
  - isTrusted has been replaced with Verify in Identity
- IntegrityState introduced to hold result of a verification
- Introduced GetClaim/PutClaim/RemoveClaim to allow for more flexible claim handling
  - Removes many claim convenience methods, simplifies usage and code
- Cleaned up, removed and renamed package specific exceptions

**NOTE** *Version 1.2.0 includes changes that will break 1.1.0 and earlier. These are only code-breaking changes, so all previously created DiME items will continue to work.*

## Version 1.1.0 - 2022-10-17
- Changes to .NET 6.0
- Introduces Dime class for global settings
- Adds support for legacy DiME format (before 1.1.0)
- Adds possibility for multiple signatures for items
- Adds feature to strip an item of any signatures, so it can be modified and then resigned
- Refactors item linking and allows linking to multiple items
- Adds plugin model for other cryptographic suites
- Introduces JSON canonicalization to guarantee some order of JSON data, avoiding breaking of signatures
- Implements Tag item
- Implements Data item
- Introduces KeyCapability/IdentityCapability for Keys and Identities (this means breaking changes from 1.0.5)
- Breaking changes in Envelope (sign/verify) removes return item
- Grace period added to Dime as a global setting (this means breaking changes from 1.0.5 in verify methods)
- Adds the possibility to override the current time, intended for troubleshooting

## Version 1.0.5 - 2022-06-11
- Fixes an issue where Message did not consider original data from alien messages (received externally), which caused re-export and verify to fail.
- Add a few more tests for key exchange (encrypted payload for messages).

**NOTE:** *Version 1.0.5 is most likely one of last version that will support .NET 5, this since end-of-support is reached for .NET 5. Future versions of Dime will at some point support .NET 6 instead. *

## Version 1.0.4 - 2022-05-04
- Minor fix to prepare for an upcoming change that allows for more than one item to be linked to a Message item.

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
