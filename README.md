# oath-authenticator

OATH authenticator [Trussed][trussed]<sup>®</sup> app.

Implementation of reverse-engineered specification of Yubico's [OATH application][yubico-oath].

[trussed]: https://trussed.dev

[yubico-oath]: https://developers.yubico.com/OATH/YKOATH_Protocol.html

### Current Features

OATH authenticator supports the following features:

- HOTP implementation - [RFC4226],
- TOTP implementation - [RFC6238],
- Reverse HOTP implementation - [original client][hotp-verif].

The pynitrokey library can be used to communicate with this application over CTAPHID, and nitropy provides the CLI using
it.

CCID transport is also available, and while not supported in the mentioned library yet, it can be potentially used by
the protocol-compatible applications, like the [Yubico Authenticator for Android] (potentially with some small
modifications needed).

[Yubico Authenticator for Android]: https://github.com/Yubico/yubioath-android

[RFC4226]: https://www.rfc-editor.org/rfc/rfc4226

[RFC6238]: https://www.rfc-editor.org/rfc/rfc6238

[hotp-verif]: https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code

#### OTP

OTP support works reasonably well, with the following remarks:

1. Shared secret key length: 320+ bits.
2. HOTP implementation allows using only 32 bit counter for the initialization as of now.
3. Usage confirmation through the touch button gesture (aka UP confirmation) can be set during the credential
   registration.

#### Reverse HOTP

Reverse HOTP is an operation that allows to verify the HOTP code coming from a PC host, and shows visually to user, that
the code is correct or not, with a green or red LED respectively.
Does not need authorization by design, so the process would be automatically executed during the boot, without any
additional user intervention when possible.

This is used for the Measured Boot feature provided by Heads, which in turn is used in Nitrokey Nitropads. With
that, the Nitrokey 3 could be used in place of the sold until now Nitrokey Pro and Nitrokey Storage.

See the original description at:

- https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code

Solution contains means to avoid desynchronization between the host's and device's counters. Device calculates up to 9
values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10 subsequent
counter positions). In case:

- no code would match - the on-device counter will not be changed;
- incoming code parsing would fail - the on-device counter will not be changed;
- code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched
  code-generated HOTP counter and incremented by 1;
- code would match, and the code matches counter without offset - the counter will be incremented by 1;
- the HOTP counter overflows while searching for the matching code - error is returned, and counter is not changed.

Device will stop verifying the HOTP codes, when the difference between the host and on-device counters will be greater
or equal to 9.

Credentials registered to use with this operation cannot be used with regular HOTP calls by design.

#### CTAPHID Extension

This implementation uses CTAPHID to transfer commands to the Oath Authenticator application. This transport was used to
improve compatibility on platforms, where the default transport for this application, CCID, is not easily available (
e.g. due to being taken by other services, or requiring Administrator
privileges). In CTAPHID, a custom vendor command number was selected `0x70`, thus allowing for a compatible extension of
any FIDO compliant device.

See [CTAPHID](ctaphid.md) for the further documentation regarding the NLnet funded CTAPHID extension.

### Further work

While most of the features needed for the daily use are implemented, there are still some tasks to do:

- test remaining commands from the OATH protocol, e.g. SELECT, VALIDATE, CALCULATE ALL and SEND REMAINING;
- stability improvements, e.g. handling errors found through fuzzing;
- introducing UP confirmation for some operations, like credential registration or factory reset;
- authorization for the credentials use or modification through device's global PIN - right now PIN handling is done by
  the application, while ideally should be offloaded to the upstream framework;
- proper LED blinking for the Reverse HOTP feature - since the upstream framework does not handle any LED animations
  yet, the failing and successful cases can be distinguished only by the blinking length at the moment (10 seconds for
  the pass, 1000 for the failed case). There is no support for the animation priority in the upstream framework as well,
  hence any other operation can overwrite the animation;
- better error reporting over CTAPHID - right now only two status codes are reported - success and failure. It would be
  nice for the production release to distinguish the actual case of the failed operation, like counter overflow, no
  space available for the new credential, or timing out UP confirmation.

Tasks and features still discussed to be done:

- extend HOTP feature to handle 64-bit counter - right now only 32-bit value is supported to stay compatible with the
  original protocol, however this should be easily extended by introducing a new TLV tag, which would mark the wider
  value;
- support SHA512 if that would be ever needed;
- test and support [OATH application][yubico-oath] protocol-compatible applications;
- extend with Password Safe features - keep login and password together within the same credential structure - the idea
  is to avoid the extra work needed to implement the similar functionality for the Password Safe, which is essentially a
  Key-Value store with the extra steps, and instead piggy-back on the current CRUD application we have.

### License

<sup>`oath-authenticator` is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.</sup>
<br>
<sub>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.</sub>

## Funding

[<img src="https://nlnet.nl/logo/banner.svg" width="200" alt="Logo NLnet: abstract logo of four people seen from above" hspace="20">](https://nlnet.nl/)
[<img src="https://nlnet.nl/image/logos/NGI0PET_tag.svg" width="200" alt="Logo NGI Zero: letterlogo shaped like a tag" hspace="20">](https://nlnet.nl/NGI0/)

Changes in this project were funded through the [NGI0 PET](https://nlnet.nl/PET) Fund, a fund established
by [NLnet](https://nlnet.nl/) with financial support from the European
Commission's [Next Generation Internet programme](https://ngi.eu/), under the aegis of DG Communications Networks,
Content and Technology under grant agreement No 825310.
