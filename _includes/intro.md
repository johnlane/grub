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

<div class="message" style="font-size:75%">

GRUB is free software; you can redistribute it and/or modify it under the terms of the <a href="http://www.gnu.org/licenses/gpl.html">GNU General Public License</a> as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

</div>




[1]:https://code.google.com/p/cryptsetup
[2]:https://code.google.com/p/cryptsetup/wiki/DMCrypt
