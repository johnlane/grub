The Grub `cryptomount` command can mount [LUKS][1] volumes. This extension augments that capability
with support for detached headers and key files as well as adding support for plain [DMCrypt][2]
volumes.

It also allows a crypto volume UUID to be specified with or without embedded hyphens.

This makes it possible to boot from [LUKS][1] and [DMCrypt][2] volumes. The LUKS header may
be detached and stored on a separate device such as a removable USB key. Key files may be
stored in a similar way and used instead of interactive passphrase entry.

The extension provides the `cryptomount` command with several new command-line options. Use `cryptomount --help` to display them. The options parrallel those offered by [cryptsetup][3].

![help screenshot](/assets/grub-crypto.png)

This work has [the same license as Grub](http://git.savannah.gnu.org/cgit/grub.git/tree/COPYING) (GPL v3).

### Installation

Get from [GitHub]({{ site.github.repo }}).

    $ git clone {{ site.github.repo }}

Alternatively, check out [upstream](https://savannah.gnu.org/git/?group=grub) and apply these patches:

0001-Cryptomount-support-LUKS-detached-header.patch
0002-Cryptomount-support-key-files.patch
0003-Cryptomount-support-plain-dm-crypt.patch
0004-Cryptomount-support-for-hyphens-in-UUID.patch
grub-crypto.png

* [0001-Cryptomount-support-LUKS-detached-header.patch](/assets/0001-Cryptomount-support-LUKS-detached-header.patch)
* [0002-Cryptomount-support-key-files.patch](/assets/0002-Cryptomount-support-key-files.patch)
* [0003-Cryptomount-support-plain-dm-crypt.patch](/assets/0003-Cryptomount-support-plain-dm-crypt.patch)
* [0004-Cryptomount-support-for-hyphens-in-UUID.patch](/assets/0004-Cryptomount-support-for-hyphens-in-UUID.patch)

Follow the build and install instructions in the upstream Grub [INSTALL](http://git.savannah.gnu.org/cgit/grub.git/tree/INSTALL) file.

<small>Patches compatible with upstream HEAD (c945ca75) at time of writing, 2015/06/12</small>

### UUID availability

The `cryptomount` command can identify an encrypted LUKS device by its UUID. The UUID value
can be specified with or without being delimited by hyphens. Because the given UUID is
compared against the UUID in the LUKS header, such lookups only work with LUKS volumes with
attached headers.

Specifically, the UUID cannot be used with plain DMCrypt volumes or when a LUKS detached
header is used.

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

<div class="message" style="font-size:75%">
GRUB is free software; you can redistribute it and/or modify it under the terms of the <a href="http://www.gnu.org/licenses/gpl.html">GNU General Public License</a> as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
</div>

[1]:https://code.google.com/p/cryptsetup
[2]:https://code.google.com/p/cryptsetup/wiki/DMCrypt
[3]:http://www.dsm.fordham.edu/cgi-bin/man-cgi.pl?topic=cryptsetup
