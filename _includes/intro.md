The Grub `cryptomount` command can mount [LUKS][1] volumes. This extension augments that capability
with support for detached headers and key files as well as adding support for plain [DMCrypt][2]
volumes.

It also allows a crypto volume UUID to be specified with or without embedded hyphens.

It makes it possible to boot from [LUKS][1] and [DMCrypt][2] volumes. The LUKS header may
be detached and stored on a different device, such as a removable USB key. Key files may be
stored in a similar way and used instead of interactive passphrase entry.

The extension provides the `cryptomount` command with several new command-line options:

* `-p` use plain [DMCrypt][2] mode instead of [LUKS][1] mode.
* `-H` use detached header
* `-k` use key file

`cryptsetup -h` displays all of the available options.

Source repository on [GitHub](https://github.com/johnlane/grub-crypt). Licensed as per Grub.

![My helpful screenshot](/assets/grub-crypto.png)

### UUID availability

The `cryptomount` command can, in certain limited situations, find an encrypted device by its
UUID. The UUID value can be specified with or without being delimited by hyphens. The UUID
is compared against the UUID in the LUKS header and its use is therefore possible for LUKS
volumes with attached headers only.

Specifically, the UUID cannot be used with plain DMCrypt volumes or with a LUKS detached
header.

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

This example opens a LUKS voume. This is possible without the extension.

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
