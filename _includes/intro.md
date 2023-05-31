The Grub `cryptomount` command can mount [LUKS][1] volumes. This extension augments that capability
with support for detached headers and key files as well as adding support for plain [DMCrypt][2]
volumes.

> **Deprecation Notice**

> Grub gained detached header support on 8th June 2022 with commit [1deb5214](https://gitlab.com/gnu-grub/grub/-/commit/1deb521452b288fe8256dcc7bc14228aa42b568e).

> As of this notice the current Grub version 2.06 predates this change, however the [Arch Linux Grub package](https://archlinux.org/packages/core/x86_64/grub) is based of the master branch and therefore includes this support. Other distributionss may have to wait for the next Grub release.

> Thanks to contributors here and on the mailing lists who have helped get this functionality supported upstream. Please direct any further queries to a [Grub mailing list](https://www.gnu.org/software/grub/grub-mailinglist.html).


This makes it possible to boot from [LUKS][1] and [DMCrypt][2] volumes. The LUKS header may
be detached and stored on a separate device such as a removable USB key. Key files may be
stored in a similar way and used instead of interactive passphrase entry.

This extension also adds these features:

* allow a crypto volume UUID to be specified with or without embedded hyphens.
* give the user a second chance to enter a passphrase after failing to unlock a LUKS volume
  with a given passphrase or key file.

The extension provides the `cryptomount` command with several new command-line options. Use `cryptomount --help` to display them. The options parrallel those offered by [cryptsetup][3].

![help screenshot](/assets/grub-crypto.png)

This work has [the same license as Grub](http://git.savannah.gnu.org/cgit/grub.git/tree/COPYING) (GPL v3).

### Installation

Get from [GitHub]({{ site.github.repo }}).

    $ git clone {{ site.github.repo }}

Alternatively, check out [upstream](https://savannah.gnu.org/git/?group=grub) and apply these patches:

* [0001-Cryptomount-support-LUKS-detached-header.patch](/assets/0001-Cryptomount-support-LUKS-detached-header.patch)
* [0002-Cryptomount-support-key-files.patch](/assets/0002-Cryptomount-support-key-files.patch)
* [0003-Cryptomount-luks-allow-multiple-passphrase-attempts.patch](/assets/0003-Cryptomount-luks-allow-multiple-passphrase-attempts.patch)
* [0004-Cryptomount-support-plain-dm-crypt.patch](/assets/0004-Cryptomount-support-plain-dm-crypt.patch)
* [0005-Cryptomount-support-for-hyphens-in-UUID.patch](/assets/0005-Cryptomount-support-for-hyphens-in-UUID.patch)
* [0006-Retain-constness-of-parameters.patch](/assets/0006-Retain-constness-of-parameters.patch)
* [0007-Add-support-for-using-a-whole-device-as-a-keyfile.patch](/assets/0007-Add-support-for-using-a-whole-device-as-a-keyfile.patch)

Follow the build and install instructions in the upstream Grub [INSTALL](http://git.savannah.gnu.org/cgit/grub.git/tree/INSTALL) file.

<small>Patches compatible with upstream HEAD ([28b0d190](http://git.savannah.gnu.org/cgit/grub.git/commit/?id=28b0d19061d66e3633148ac8e44decda914bf266)) at time of writing, 2018/03/14. Patches 6 and 7 are contributed [pull requests](https://github.com/johnlane/grub/pulls?q=is%3Apr+is%3Aclosed).</small>

### UUID availability

The `cryptomount` command can identify an encrypted LUKS device by its UUID. The UUID value
can be specified with or without being delimited by hyphens. Because the given UUID is
compared against the UUID in the LUKS header, such lookups only work with LUKS volumes with
attached headers.

Specifically, the UUID cannot be used with plain DMCrypt volumes or when a LUKS detached
header is used.

### Key Files

A key file contains the cryptographic material required to unlock a volume. This is a passphrase
for a LUKS volume or a key for a plain volume. The required data is usually read from the beginning
of the given file but the `offset` command-line option allows it to be read from within the file.

When used in plain mode, the amount of data read is the number of bytes required for the key and an
error will occur if insufficient data can be read.

When used in LUKS mode, all of the available data (up to a maximum of 8KiB) is read and used as a
passphrase. The `keyfile-size` command-line option can be used to limit the amount of data that is
read. (This option does not apply to plain mode.)

These options can be used together to embed a key or passhrase in a larger file.

A key file may be either a file (`-k (hd0,1)/keyfile`) or a raw device (`-k (hd0,1)`). Thanks to
[@giddie](https://github.com/johnlane/grub/pull/8) for the patch.

### No Automatic Configuration

This extension does not alter Grub's automated configuration (e.g. `grub-mkconfig`) in any way. Use of the extended options will require manual configuration of `grub.cfg`.

### Examples

#### 1. Plain DMCrypt

This example assumes the default cipher and passphrase hash. These defaults are the same as
the ones in [cryptsetup][3]: `aes-cbc-essiv:sha256` and `ripemd160` passphrase hash.

    insmod cryptodisk
    cryptomount -p hd1,1

#### 2. Plain DMCrypt access to LUKS volume

This example opens a LUKS volume using plain DMCrypt. The volume master key is read from a
file and the LUKS cipher and payload offset details are supplied as parameters.

    insmod cryptodisk
    cryptomount -p -k (hd0,1)/keyfile -K 256 -c aes-xts-plain64 -o 4096 hd1,1


#### 3. LUKS

This example opens a LUKS voume and is the only method supported by upstream Grub.

    insmod luks
    cryptomount hd1,1

The device may alternatively be specified using the UUID contained in the LUKS header.

    cryptomount -u af4b9159-8cbb-4122-b801-0c18adf26b3e

#### 4. LUKS with detached header

This example opens a LUKS volume using a detached LUKS header.

    insmod luks
    cryptomount -H (hd0,1)/header hd1,1
    
#### 5. LUKS with detached header and key file

    insmod luks
    cryptomount -H (hd0,1)/header -k (hd0,1)/keyfile hd1,1

#### 6. LUKS with a 50 character passphrase embedded 30 bytes into key file.

    insmod luks
    cryptomount -k (hd0,1)/keyfile -O 30 -S 50 hd1,1

<small>Read _[A GRUBby USB Stick](/grubby-usb.html)_ for supplementary information, including a way to create a USB boot stick to boot encrypted filesystems.</small>


<div class="message" style="font-size:75%">
GRUB is free software; you can redistribute it and/or modify it under the terms of the <a href="http://www.gnu.org/licenses/gpl.html">GNU General Public License</a> as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
</div>

[1]:https://code.google.com/p/cryptsetup
[2]:https://code.google.com/p/cryptsetup/wiki/DMCrypt
[3]:http://www.dsm.fordham.edu/cgi-bin/man-cgi.pl?topic=cryptsetup
