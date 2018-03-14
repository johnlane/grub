---
layout: post
title: A GRUBby USB Stick
date: 2014-11-05 14:25:19
categories: 
permalink: grubby-usb.html
---
This article describes a way to put GRUB onto a USB stick so that it can be used to boot encrypted filesystems stored on other volumes. The same USB stick can be used as the boot drive for multiple systems in this way.

> **This hitherto unfinished work, originally a _note-to-self_ or _brain-dump_, is presented here in the hope that it may be of some use to those interested in my [Grub Crypt](/) Extension. Some detail may be incorrect, incomplete, irrelevant, out of date, or may only make sense to me. It is what it is, but it may be just what you need. Licensed as [CC BY_SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/). Comments/Questions [welcome](https://github.com/johnlane/grub/issues). <small>© _2017.10.27 John Lane_</small>**

<small>**!** These examples are based on an Arch Linux environment.</small>

The stick contains two filesystems for Grub: a plaintext one and another that is encrypted which is unlocked at boot upon entry of a passphrase.

The systems to be booted can be encrypted. If so, the crypto-material required to boot them can be stored on the USB stick. If the crypto-material includes keys then it should be stored in the encrypted filesystem on the USB stick, otherwise it can be stored in the plaintext filesystem.

The plaintext filesystem can also contain ISO bootable *LiveCD* images such as:

* Arch Linux live CD
* System Rescue CD
* Tails Linux

A second encrypted filesystem can be used as a general purpose filesystem. It is configured so that Tails will recognise it as a _persistent volume_.

A third plaintext filesystem can be used as a general purpose filesystem. This filesystem is configured to be the only one visible if the USB stick is inserted into a Windows computer.

In total there are four partitions.

### Know your GRUB version

There are two versions of Grub in common use: *Legacy Grub* is the original version and *Grub* now refers to the newer version 2 series. The versions are similar but use different configuration files. Legacy Grub does not officially support GPT partition tables but patches exist for it. You can confirm your version of Grub:

    $ grub-install --version
    grub-install (GRUB) 2.02~beta2
 
We'll be using Grub modules to access files on encrypted Linux volumes so, therefore, will be using Grub version 2. 
   
### Know your device

Begin by plugging in the USB device and then use `dmesg` or `fdisk -l` to identify its device node (e.g. `/dev/sdj`, as used in all following examples)

**! WARNING: Ensure you have the correct device node. Using the wrong one may result in unrecoverable data loss!**

### Format

The USB stick will contain the following:

* The GRUB bootloader;
* an unencrypted `ext4` filesystem containing unencrypted GRUB files;
* an encrypted `ext4` filesystem containing the crypto-boot material;
* an encrypted `ext4` filesystem for use as a general-purpose data area and accessible within Tails as a _Tails Persistent Volume_.
* an unencrypted `vfat` filesystem for use as a general-purpose data area.

The USB stick can be used in a non-boot scenario to store general-purpose data. When used in a non-Linux computer, only the data partition is visible.

The partition for the unencrypted GRUB files needs to accommodate the Grub boot files (around 13MiB), plus the ISO images (allow around 1GiB per ISO). It will be sized to 3Gib, less the one Mebibyte already consumed by the disk's partition tables and boot loader and less one Mebibyte for the encrypted partition for the encrypted GRUB files. This will have 2MiB allocated for its own LUKS header plus, inside the filesystem, a LUKS header and key file per volume that GRUB needs to decrypt, each having a combined size of just under 2MiB.

This scheme occupies 3GiB and leaves all remaining space for use as general-purpose data filesystems, split evenly between plaintext and encrypted.

### Partitioning

**! WARNING: any pre-existing data on the USB stick will be lost!**

The USB stick needs a partition table and at least one partition that will house the boot files. You can use either the traditional MSDOS partition table or the newer GPT - it doesn't matter.

What we're going to do here is use both. The master boot record for the MSDOS partition table will be a [Hybrid MBR](http://www.rodsbooks.com/gdisk/hybrid.html) that allows access to the data partition on the USB stick. The GPT will also contain the data partition plus the other partitions to hold the plain and encrypted boot material.

#### GPT partitioning

Begin by creating the GPT partition table. It will have the three partitions described above, plus the GPT *BIOS Boot Partition* where Grub will embed its boot image. 

    $ parted -s /dev/sdj mktable gpt
    $ parted -s /dev/sdj mkpart primary ext4 0% 2972MiB 
    $ parted -s /dev/sdj mkpart primary 2972MiB 3GiB
    $ parted -s /dev/sdj mkpart primary fat32 3GiB 100%
    $ parted -s /dev/sdj unit s mkpart primary 34 2047 set 4 bios_grub on

**!** <small>The BIOS Boot Partitions sectors are, by definition, unaligned; you can safely ignore any warnings about alignment.</small>

Optionally, name the partitions:

    $ parted -s /dev/sdj name 1 '"Grub files (plaintext)"'
    $ parted -s /dev/sdj name 2 '"Grub files (encrypted)"'
    $ parted -s /dev/sdj name 3 '"Data Partition"'
    $ parted -s /dev/sdj name 4 '"BIOS Boot Partition"'

Next, create filesystems on the plaintext partitions. The data partition uses `vfat` to make it accessible on Windows computers.

    $ mkfs.ext4 /dev/sdj1
    $ mkfs.vfat /dev/sdj3
    
Optionally label the filesystems. [Labelled filesystems](https://wiki.archlinux.org/index.php/persistent_block_device_naming#by-label) are listed in `/dev/disk/by-label` and can a label can be used instead of a UUID to identify a disk (doing so would be a matter of personal preference)

    $ e2label /dev/sdj1 boot
    $ dosfslabel /dev/sdj3 DATA
    
<small>**!** Lowercase labels on FAT filesystems might not work properly with DOS or Windows.</small>
    
The next step prepares the partition for the encrypted boot material. Randomise the empty sapce, then create a LUKS volume with a detached header and with a filesystem within.

##### Randomise prior to encryption

This step, to pre-fill the partition with random data, is optional. One way to do this is to use `dm-crypt` to create a temporary enrypted volume and fill it from `/dev/zero`, allowing the encryption cipher to provide the randomness. Here's how:

    $ cryptsetup open /dev/sdj2 temp --type plain --key-file <(head -c 32 /dev/urandom)
    
This opens an encyrpted volume with a temporary random key that will only be used this once. Fill the volume with zeroes; they will be encrypted, which effectively writes pseudorandom data:

    $ dd if=/dev/zero of=/dev/mapper/temp
    
Finally, close the crypt device:
    
    $ cryptsetup close temp

##### Create LUKS volume

Create a LUKS volume on the plaintext boot data filesystem, open it and create a filesystem:

    $ cryptsetup luksFormat --key-size 512 /dev/sdj2
    $ cryptsetup open /dev/sdj2 bootcrypt
    $ mkfs.ext4 /dev/mapper/bootcrypt

<small>Using a non-default `key-size` is optional.</small>
    
##### Install Grub

> This step requires the Grub tools to be installed on a Linux computer. For detached header support this needs to be [grub.johnlane.ie](http://grub.johnlane.ie) until such a time upstream merges it the Grub master codebase.

Put Grub onto the USB stick. It writes to the MBR, the BIOS Boot Partition and the plaintext boot data filesystem that is mounted as `/mnt`.

    $ mount /dev/sdj1 /mnt
    $ grub-install --no-floppy --boot-directory=/mnt /dev/sdj
    
Write a small configuration file for Grub that opens the encrypted partition and loads a second configuration file located therein. Write `/mnt/grub/grub.cfg`:

    insmod luks
    cryptomount hd0,2
    configfile (crypto0)/grub.cfg

Unmount the plaintext filesystem and mount the encrypted one using the `bootcrypt` device mapper created above:

    $ umount /mnt
    $ mount /dev/mapper/bootcrypt /mnt
    
Write the main configuration file here, as `/mnt/grub.cfg`. Its contents will depend on how booting is to be achieved. There is an example in the next section.

When finished, unmount and lock the volume:

    $ umount /mnt
    $ cryptsetup close bootcrypt
    
#### Grub Configuration Examples

The following configuration uses detached LUKS headers and key-files stored in files named after the UUID of the device to be opened with an appended digit: 0 for the header and 1 for the key. Thus, each bootable device requires two files.

The chosen UUID is the LUKS UUID that is contained in the header file and can be seen using `cryptsetup luksDump <header>`. Creating the header file is done when creating the filesystem; that's the subject of another article.

The header and key can be placed on either the plaintext or encrypted partition. The following function will boot using a header and keyfile located on the plaintext partition:

```
insmod part_msdos
insmod gzio
insmod luks

# $1 is the UUID of the encrypted device (as defined in the LUKS header)
# $2 is the Grub device refrence of the encrypted device
# $3 is the Linux device node of the encrypted device
# $4 is the UUID of the root partition (containing /boot) within the encrypted device
# $5 is the UUID of plaintext root partition on the USB stick
# the detached header to be stored at $5/$2
function crypt_start {
    encrypted_device_uuid=$1
    encrypted_device_grub=$2
    encrypted_device_linux=$3
    root_partition_uuid=$4
    boot_device_uuid=$5
    shift 5

    cryptomount -H /${encrypted_device_uuid}0 \
                -k /${encrypted_device_uuid}1 \
                ${encrypted_device_grub}

    echo -n "Loading kernel..."
    linux (crypto0)/boot/vmlinuz-linux root=UUID=${root_partition_uuid} rw "$@" \
          cryptdevice=${encrypted_device_linux}:root \
          cryptheader=UUID=${boot_device_uuid}:ext4:/${encrypted_device_uuid}0 \
          cryptkey=UUID=${boot_device_uuid}:ext4:/${encrypted_device_uuid}1

    echo -n "Loading initial ram filesystem..."
    initrd (crypto0)/boot/initramfs-linux.img

    echo -n "Booting..."
}

```

It would be involed from a menu entry like this:

```
# af4b9159-8cbb-4122-b801-0c18adf26b3e is the encrypted volume (/dev/sda1)
# da9253f8-14ec-43df-8e79-fdf66f71adc8 is the root filesystem (/dev/mapper/root) inside /dev/sda1
# e7bc3210-ee80-4111-a6da-3db1d2e2cbef is the plaintext root partition on the USB stick
menuentry 'Bench PC sda1' {
    crypt_start af4b9159-8cbb-4122-b801-0c18adf26b3e hd1,1 /dev/sda1 \
                da9253f8-14ec-43df-8e79-fdf66f71adc8 \
                e7bc3210-ee80-4111-a6da-3db1d2e2cbef \
                nomodeset
}
```

Placing the header and keyfile on the encrypted partition is a similar but more secure solution. It requires some additional configuration to make the header and key file accessible to the booting kernel (it can only unlock the root partition, not the encrypted volume and can't therefore use the files located on the USB stick).

The header and keyfile are made accessible to the booting kernel by placing copies inside the system's initial ramdisk (which is securely stored on the encrypted root filesystem).

<small>These notes assume:

* the system is booted off an ArchLinux live CD
* the encrypted USB partition is unlocked and mounted as `/mnt1`
* the encrypted root partition is inlocked and mounted as `/mnt2`
* the required UUID is substituted for `<uuid>` in the below
</small>

To do this, First copy them into the `/boot` encrypted root filesystem so that `mkinitcpio` can put them in the `initramfs.img` file. 

    $ cp /mnt1/<uuid>* /mnt2/boot

`chroot` the root fileystem:

    $ arch-chroot /mnt2

Instruct `mkinitcpio` to include the header and key file by amending the `FILES` entry in its configuration `/etc/mkinitcpio.conf`:

    FILES="/boot/<uuid>0 /boot/<uuid>1"
    
Then, regenerate the initial ramdisk; either

    $ mkinitcpio -p linux
    
will make both the `initramfs-linux.img` and `initramfs-linux-fallback.img`. Alternatively, just make the main image:

    $ mkinitcpio -g /boot/initramfs-linux.img
    
<small>If the chroot filesystem contains a different kernel to the live system, append `-k` to specify that kernel, as listed at `/lib/modules` (e.g. `-k 3.17.3-1-ARCH`).</small>

The Grub configuration would be located on the encyrpted partition and would look like this:

```
# $1 is the UUID of the encrypted device (as defined in the LUKS header)
# $2 is the Grub device refrence of the encrypted device
# $3 is the Linux device node of the encrypted device
# $4 is the UUID of the root partition (containing /boot) within the encrypted device
# the detached header to be stored at $5/$2
function crypt_start {
    encrypted_device_uuid=$1
    encrypted_device_grub=$2
    encrypted_device_linux=$3
    root_partition_uuid=$4
    shift 4

    cryptomount -H (crypto0)/${encrypted_device_uuid}0 \
                -k (crypto0)/${encrypted_device_uuid}1 \
                ${encrypted_device_grub}

    echo -n "Loading kernel..."
    linux (crypto1)/boot/vmlinuz-linux root=UUID=${root_partition_uuid} rw "$@" \
          cryptdevice=${encrypted_device_linux}:root \
          cryptheader=rootfs::/boot/${encrypted_device_uuid}0 \
          cryptkey=rootfs:/boot/${encrypted_device_uuid}1

    echo -n "Loading initial ram filesystem..."
    initrd (crypto1)/boot/initramfs-linux.img

    echo -n "Booting..."
}
```

The associated menu entry:
```
# af4b9159-8cbb-4122-b801-0c18adf26b3e is the encrypted volume (/dev/sda1)
# da9253f8-14ec-43df-8e79-fdf66f71adc8 is the root filesystem (/dev/mapper/root) inside /dev/sda1
menuentry 'Bench PC sda1' {
    crypt_start af4b9159-8cbb-4122-b801-0c18adf26b3e hd1,1 /dev/sda1 \
                da9253f8-14ec-43df-8e79-fdf66f71adc8 \
                nomodeset
}

```

#### ISO Booting

The USB stick can contain bootable ISO images. They need to go in the plaintext boot partition. The following grub configuration examples assume the ISOs are placed in an `/iso` subdirectory.

Set up a reference to the device containing the ISO images using either UUID:

    set imgdevpath='/dev/disk/by-uuid/e7bc3210-ee80-4111-a6da-3db1d2e2cbef'  

or disk label:

    set imgdevpath='/dev/disk/by-label/boot'
    
Then build menu items to boot the ISO images. Here are some examples:

```
menuentry 'archlinux i686' {
        set isofile='/iso/archlinux-2014.09.03-dual.iso'
        loopback loop $isofile
        linux (loop)/arch/boot/i686/vmlinuz archisolabel=ARCH_201409 img_dev=$imgdevpath img_loop=$isofile earlymodules=loop nomodeset
        initrd (loop)/arch/boot/i686/archiso.img
}

menuentry 'System Rescue CD' {
  set isofile="/iso/systemrescuecd-x86-4.4.1.iso"
  loopback loop $isofile
  linux (loop)/isolinux/rescue32 isoloop=$isofile nomodeset
  initrd (loop)/isolinux/initram.igz
}

menuentry 'Tails' {
  set isofile="/iso/tails-i386-1.2.1.iso"
  loopback loop $isofile
  linux (loop)/live/vmlinuz fromiso=$imgdevpath/$isofile boot=live config noswap nopersistent nomodeset
  initrd (loop)/live/initrd.img
}

menuentry 'Machines' {
  insmod luks 
  cryptomount hd0,2
  configfile (crypto0)/grub.cfg
}

```

#### MBR Partitioning

The MBR partition table will have one partition, the general data partition.

First, back up the existing MBR:

    $ dd if=/dev/sdj of=mbr.sdj bs=512 count=1
    
Print out the GPT table sectors:

    $ parted -s /dev/sdj unit s print
    Number  Start   End     Size    File system  Name                    Flags
     4      17.4kB  1049kB  1031kB               BIOS Boot Partition     bios_grub
     1      1049kB  5369MB  5368MB  ext4         Grub files (plaintext)
     2      5369MB  10.7GB  5369MB               Grub files (encrypted)
     3      10.7GB  15.8GB  5057MB  fat32        Data Partition          msftdata
    
Note the start and end sectors of the *Data Partition*, the one with the `fat32` filesystem (e.g.`20971520` and `30849023`).

Now use `gdisk` to interactively configure a so-called *hybrid MBR* (there is a good explanation of this [here](http://www.rodsbooks.com/gdisk/hybrid.html) containing partition #3 listed above:

    $ gdisk /dev/sdj
    Command (? for help): r
    Recovery/transformation command (? for help): h
    Type from one to three GPT partition numbers, separated by spaces, to be
    added to the hybrid MBR, in sequence: 3
    
The partition must appear first in the MBR otherwise Windows won't see it. Answer the next prompt in the negative:

    Place EFI GPT (0xEE) partition first in MBR (good for GRUB)? (Y/N): n
    
This creates a protective partition covering the space in front of the data partition. Next, choose the data partition's type. `0c` is *Windows Fat32 LBA*

    Enter an MBR hex code (default 07): 0c
    Set the bootable flag? (Y/N): n
    
The final step creates another protective partition covering the space behind the data partition. Use the default partition type, `0xEE` (Mac OSX is ok with this now).

    Unused partition space(s) found. Use one to protect more partitions? (Y/N): y

You can then select `o` to view the hybrid MBR

Recovery/transformation command (? for help): o

    Disk size is 30851072 sectors (14.7 GiB)
    MBR disk identifier: 0x00000000
    MBR partitions:

    Number  Boot  Start Sector   End Sector   Status      Code
        1              20971520     30849023   primary     0x0C
        2                     1     20971519   primary     0xEE
        4              30849024     30851071   primary     0xEE

Finally, write the changes

    Recovery/transformation command (? for help): w
    The operation has completed successfully.

<small>The above shows the pertinent information but `gdisk` is more verbose; unnecessary detail has been omitted.</small>

The above produced a disk that boots into Grub but appeats as a USB data drive with one partition if inserted into Windows or Mac OS X.

## Annex

### LUKS detached header

Begin by creating a file to accommodate the header. The quick-and-dirty way is to make one equal to the default payload offset (4096 sectors = 2,097,152 bytes; 2MiB). However, it's more space efficient to use the exact size (the space saving with a 256-bit key is about 50%).

#### Header size

The exact size of the LUKS header can be calculated from the LUKS parameters:

    size = num_key_slots * key_size * number_of_stripes / sector_size

There are eight key slots and number of stripes is hard-coded in `cryptsetup` to be 4000. The sector size is 512 bytes. So, for a 512-bit (64 byte) key:

    size = 8 * 64 * 4000 / 512 = 4000 sectors 

Add to this the sector offset of the first key slot; it's had-coded as 8 sectors in `cryptsetup`. The LUKS header is stored in this space.

<small>The actual header is 592 bytes (see the [spec](http://wiki.cryptsetup.googlecode.com/git/LUKS-standard/on-disk-format.pdf)), so there's some unused space there.</small>

Finally, each subsequent key slot's material begins on a sector-aligned boundary. This results in a 4 sector gap between them, or 7 * 4 = 28 sectors. Adding everything together gives the minimum size of the detached header file:

    4000 + 8 + 28 = 4036 sectors (2,066,432 bytes; just under 2MiB)
    
<small>**!** The required size is calculated by function [LUKS_device_sectors](https://code.google.com/p/cryptsetup/source/browse/lib/luks1/keymanage.c#40) in the `cryptsetup` source code.</small>
<small>**!** The surplus space under 2MiB is 30,720 bytes. The maximum size of a LUKS key file is [hard-coded](https://code.google.com/p/cryptsetup/source/browse/configure.ac#423) in `cryptsetup` at 8192 bytes. Allowing 2MiB per header and up to 3 keys is sufficient.</small>

Similarly, a 256-bit (32-byte) key, results in six-bytes of padding between each key material, giving:

    8 * 32 * 4000 / 512 = 2000 sectors
    2000 + 8 + 42 = 2050 sectors (1,049,600 bytes; just over 1MiB)
    
The space between the last key slot and the payload offset is unused and does not need to be preserved in the detached header (although it doesn't matter if it is - copying up to the payload offset is the easiest way to extract the header).

To create a LUKS volume header in a file on the plaintext boot data filesystem:

    $ mount /dev/sdj1 /mnt
    $ head -c 2066432 /dev/urandom > /mnt/header
    $ cryptsetup luksFormat --header /mnt/header --align-payload 0 --key-size 512 /dev/sdj2

The `align-payload` prepares the header so the entire partition can be used for data. Using a non-default `key-size` is optional (the default key size for LUKS is 256 bits).

Next, use the header to open LUKS volume and create a filesystem on it:

    $ cryptsetup open /dev/sdj2 --header /mnt/header bootcrypt
    
<small>`dmsetup table --target crypt | awk '{print $1}'` will confirm that the sector offset is zero.</small>

    $ mkfs.ext4 /dev/mapper/bootcrypt
    
#### Detached header for plain volume

To create a LUKS header for an already existing plain volume, you need its master key in a file, say `keyfile`, and knowledge of the cipher and key size. Use this information to create the header. First, work out its size (e.g. for a 512 bit (64 byte) key):

    size = 8 + (8 * 64 * 4000 / 512) + 28 = 4036 sectors = 2,066,432 bytes
    
Create the header

    $ head -c 2066432 /dev/urandom > header
    $ cryptsetup luksFormat --master-key-file keyfile --cipher aes-cbc-essiv:sha256 --key-size 256 --align-payload 0 --header header header
    
<small>The `--align-payload` parameter has no effect unless the `--header` parameter is also given. If `--align-payload` is not neded then the --header` parameter can be omitted also (the header must still be specified as the positional device parameter)</small>

This will ask for a new passphrase which is assigned to the LUKS header slot containing an encrypted copy of the supplied master key.

### Finding the UUID

With the hard drive attached, look up the devices by UUID and cross reference the relevant volume:

    $ pvs
    PV         VG     Fmt  Attr PSize PFree
    /dev/sda   mydisk lvm2 a--  3.64t 1.55t

That confirms we need to look for `/dev/sda`. Now

    $ ls -l /dev/disk/by-uuid
    ...
    48e89c4b-c82c-48da-8fbb-43651d19b925 -> ../../dm-1
    ...
    $ ls -l /dev/mydisk/root-volume
    /dev/mydisk/root-volume -> ../dm-1

#### The Grub device.map file

The `device.map` file is an optional configuration that thells the *Grub Shell* (the command-line Grub tool) how to map operating system device names onto Grub device names.

It is only used by the Grub Shell and other tools that use it, like `grub-install`; it has no effect during the boot process.

The terminal command `grub-install [install device]` will read the `device.map` file each time it starts, as does `grub --device-map=/boot/grub/device.map`. The latter example is most notable because, in contrast, starting the Grub shell as `grub` does not read the device map file.

This is more thoroughly explained [here](http://forums.fedoraforum.org/showthread.php?t=153679).

#### Grub Commands

* `ls` shows the devices and partitions
* `ls (hd0,1)` shows that partition's details
* `ls (hd0,1)/` shows that partition's files

#### Grub Device Syntax

See https://www.gnu.org/software/grub/manual/html_node/Device-syntax.html. Here are some examples:

```
(fd0)
(hd0)
(cd)
(ahci0)
(ata0)
(crypto0)
(usb0)
(cryptouuid/123456789abcdef0123456789abcdef0)
(mduuid/123456789abcdef0123456789abcdef0)
(lv/system-root)
(md/myraid)
(md/0)
(ieee1275/disk2)
(ieee1275//pci@1f\,0/ide@d/disk@2)
(nand)
(memdisk)
(host)
(myloop)
(hostdisk//dev/sda)
(hd0,msdos1)
(hd0,msdos1,msdos5)
(hd0,msdos1,bsd3)
(hd0,netbsd1)
(hd0,gpt1)
(hd0,1,3)
```

#### General Purpose Encryption

A general-purpose encryption tool allows ad-hoc files to be encrypted. Recommended for this is [EncFS](https://vgough.github.io/encfs) and there is a Windows port called [encfs4win](http://members.ferrara.linux.it/freddy77/encfs.html) with a static Windows binary that can be stored in the general-purpose partition for use on such machines.

* download http://members.ferrara.linux.it/freddy77/encfs.zip
* md5 e2ea05ac92f195c32a82ab79066ff333
* usage `C:> encfs <crypt_dir> <plain_dir>` 

where `crypt_dir` is encrypted directory and `plain_dir` is the directory used to read/write plaintext files.

Another Windows/OSX port is [Safe](http://www.getsafe.org).

Other possibilities:

* [DoxBox](https://github.com/t-d-k/doxbox), a fork of the now-defunct [FreeOTFE](http://sourceforge.net/projects/freeotfe.mirror) project, offers LUKS functionality on Windows but requires administrator rights.

### Using USB stick in VirtualBox

Insert the USB stick, don't mount it. Use `dmesg` to identify the assigned device (e.g. `/dev/sdj`) and then create a *raw vmdk* like this:

    $ VBoxManage internalcommands createrawvmdk -rawdisk /dev/sdj -filename usb-stick.vmdk
    
Then create a new VirtualBox VM and, instead of creating a hard drive, use the `usb-stick.vmdk` instead. Start the VM and it will boot from the USB.

* http://www.metashock.de/2012/11/booting-your-usb-stick-using-virtual-box-on-a-linux-host/

### Copy from another USB stick

This file-based copy can be used to load a freshly prepared USB stick that contains the required plaintext and encrypted filesystems, formatted but empty.

Use two mount points: `/mnt` is for the new filesystem and `/mnt2` i for the existing one (which should be mounted read-only to protect against mistakes).

    mount /dev/sdj1 /mnt
    mount -o ro /dev/sdk1 /mnt2
    rsync -aHAXv /mnt2/ /mnt/
    umount /mnt /mnt2

After copying the boot files, edit `/mnt/grub/grub.cfg` to change the `imagedevpath` to reflect the new USB stick's partition.

    cryptsetup open /dev/sdj2 new-keyring
    cryptsetup open /dev/sdk2 old-keyring
    mount /dev/mapper/new-keyring /mnt
    mount -o ro /dev/mapper/old-keyring /mnt2
    umount /mnt /mnt2
    cryptsetup close new-keyring
    cryptsetup close old-keyring


### USB stick notes

disk info:

    Disk /dev/sdj: 14.7 GiB, 15795748864 bytes, 30851072 sectors
    Logical sector size: 512 bytes 
    I/O size (minimum/optimal): 512 bytes / 512 bytes
    First usable sector is 34, last usable sector is 30851038
    
Partitioning as new:

    Disklabel type: dos
    Disk identifier: 0xc3072e18
    Device     Boot Start      End  Sectors  Size Id Type
    /dev/sdj1         112 30851071 30850960 14.7G  c W95 FAT32 (LBA)
    Number  Start (sector)    End (sector)  Size       Code  Name
       1             112        30851071   14.7 GiB    0700  Microsoft basic data
    
### Tails Persistent Volume

These notes describe how I put a Tails persistent volume on the USB stick that can be used from the Tails ISO previousy described. <small>This section was added on 20161005.</small>

First, I installed Tails on a new USB stick following the official instructions, including configuring a persistent volume on it. I then boot the Tails ISO with the second USB stick also connected and was pleased to see that it automatically recognised and used the persistent volume.  The persistent volume is a LUKS volume and its passphrase is that given when creating it in Tails. I made a note that it was using 33MB (`df -h` whilst mounted).

Next, I made some space on the USB stick for a fifth partition to house the persistent volume. This involved:

* reducing the VFAT "DATA" partition using `fatresize` [AUR](https://aur.archlinux.org/packages/fatresize) by 50%.
* making a new partition in the freed space (starting at the end of the "DATA" partition which is 9508MB and using all space - 100%). I used `parted print` to get the starting position.
* reducing the persistent volume so that it is smaller than the new partition. I made it as small as possible (48934 * 4k blocks, which is larger than the 33MB in use) to minimise the amount of data to copy.
* identify the LUKS header offset is 4096 sectors (`dmsetup`, as explained [here](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt#example-of-full-mapping-table), or `cryptsetup luksDump`).
* identify the ext4 filesystem size (48934 blocks of 4096 bytes in 512 byte sectors => 48934 * 4096 / 512 = 391472 sectors)
* identify total size = 4096 + 391472 = 395568 sectors
* double-check that there is sufficient space at dest  (`gdisk -l /dev/sdc` reports start and end sectors as 18571264 and 30849023, so there are 30849023 - 18571264 = 12277759 sectors available
* copy the LUKS header and filesystem (4096 + 391472 = 395568 sectors)
* verify the copy (`cryptsetup open` and `e2fsck`)
* enlarge copy to occupy the whole partiton
* verify again (`e2fsck` then `mount` and `df` to confirm size)
* unmount and close LUKS
* test in Tails

Command Summary:

    $ sudo -i
    # fatresize -i /dev/sdc3
    size: 12573474816
    # fatresize -s $(( 12573474816 / 2 )) /dev/sdc3
    # parted mkpart primary ext4 9508MB 100%
    # parted name 5 tails
    # cryptsetup open /dev/sdd2 tailsdata
    # e2fsck -f /dev/mapper/tailsdata
    # resize2fs /dev/mapper/tailsdata 48934
    The filesystem on /dev/mapper/tailsdata is now 48934 (4k) blocks long.
    # e2fsck -f /dev/mapper/tailsdata
    TailsData: 50/16352 files (0.0% non-contiguous), 36017/48934 blocks
    # dmsetup table tailsdata | awk '{print $NF}'
    4096
    # cryptsetup luksDump /dev/sdd2 | grep 'Payload offset'
    Payload offset:	4096
    # cryptsetup close tailsdata
    # dd if=/dev/sdd2 of=/dev/sdc5 bs=512 count=395568
    # cryptsetup open /dev/sdc5 tailsdata
    # e2fsck -f /dev/mapper/tailsdata
    TailsData: 50/16352 files (0.0% non-contiguous), 36017/48934 blocks
    # resize2fs /dev/mapper/tailsdata
    The filesystem on /dev/mapper/tailsdata is now 1534208 (4k) blocks long
    # e2fsck -f /dev/mapper/tailsdata
    TailsData: 50/384272 files (0.0% non-contiguous), 65252/1534208 blocks
    # mount -o ro /dev/mapper/tailsdata /mnt
    # df -h /mnt
    Filesystem             Size  Used Avail Use% Mounted on
    /dev/mapper/tailsdata  5.7G   33M  5.3G   1% /mnt
    # umount /mnt
    # cryptsetup close tailsdata

The new partition needs to be named "TailsData" for Tails to recognise it (use `gdisk` option `c` to change this).

The partition type of a persistent volume creatd by Tails is 8301 (Linux Reserved) but it does not matter (it works with the default 8300 partition type). Use `gdisk` option `t` to change this if you wish.

The above is sufficient for Tails to open and recognise the persistent volume which it mounts as `...`. However, the following sets up links and directories to make it usable:

    echo '/home/amnesia/Persistent source=Persistent' > /mnt/persistence.conf
    chown 115:122 /mnt/persistence.conf
    mkdir -m 700 /mnt/Persistent
    chown 1000:1000 /mnt/Persistent
    

The final piece is to update the Hybrid MBR using the instructions described earlier.

Interesting observation: the FAT partition that was resized with `fatresize` was not recognised in Windows 10.

Alternate: create Tails volume from scratch (instead of copying an existing one).

    # cryptsetup luksFormat /dev/sdc5
    # cryptsetup open /dev/sdc5 tails
    # cryptsetup close tails

### Multiboot

* https://gist.github.com/aguslr/6041441
* https://revoltingworld.net/blog/2012/12/12/multi-partition-usb-key-with-bootable-iso-tails/
* http://www.wikihow.com/Boot-an-Ubuntu-ISO-from-Your-Hard-Drive
* http://www.supergrubdisk.org/wiki/Loopback.cfg
* http://www.sysresccd.org/Sysresccd-manual-en_Easy_install_SystemRescueCd_on_harddisk#Boot_the_ISO_image_from_the_disk_using_Grub2

### 32GB USB example with Tails Persistence

An alternative scheme on a 32GB USB stick accommodates more ISO images:

    parted -s /dev/sdd mktable gpt
    parted -s /dev/sdd mkpart primary 0% 5972MiB
    parted -s /dev/sdd mkpart primary 5972MiB 6GiB
    parted -s /dev/sdd mkpart primary 6GiB 16GiB
    parted -s /dev/sdd mkpart primary fat32 16GiB 100%
    parted -s /dev/sdd unit s mkpart primary 34 2047 set 5 bios_grub on
    parted -s /dev/sdd name 1 '"Grub files (plaintext)"'
    parted -s /dev/sdd name 2 '"Grub files (encrypted)"'
    parted -s /dev/sdd name 3 '"TailsData"'
    parted -s /dev/sdd name 4 '"Data Partition"'
    parted -s /dev/sdd name 5 '"BIOS Boot Partition"'
    mkfs.ext4 /dev/sdd1
    mkfs.vfat /dev/sdd4
    e2label /dev/sdd1 boot
    dosfslabel /dev/sdd4 DATA
    cryptsetup open /dev/sdd2 temp --type plain --key-file <(head -c 32 /dev/urandom)
    dd if=/dev/zero of=/dev/mapper/temp
    cryptsetup close temp
    cryptsetup open /dev/sdd3 temp --type plain --key-file <(head -c 32 /dev/urandom)
    dd if=/dev/zero of=/dev/mapper/temp
    cryptsetup close temp
    cryptsetup luksFormat --key-size 512 /dev/sdd2
    cryptsetup open /dev/sdd2 bootcrypt
    mkfs.ext4 /dev/mapper/bootcrypt
    cryptsetup close bootcrypt
    cryptsetup luksFormat --key-size 512 /dev/sdd3
    cryptsetup open /dev/sdd3 tailsdata
    mkfs.ext4 /dev/mapper/tailsdata
    mount /dev/mapper/tailsdata /mnt
    echo '/home/amnesia/Persistent source=Persistent' > /mnt/persistence.conf
    chown 115:122 /mnt/persistence.conf
    chmod 600 /mnt/persistence.conf
    setfacl -m user:115:rwx,group::rwx,mask::rwx /mnt
    umount /mnt
    cryptsetup close tailsdata
    mount /dev/sdd1 /mnt
    grub-install --no-floppy --boot-directory=/mnt /dev/sdd
    umount /mnt

### Changing LUKS passwords

Check which slots are in use:

    cryptsetup luksDump /dev/sdd2 | grep BLED

Change passphrase in slot 0 (requires entry of existing passphrase)

    cryptsetup luksChangeKey /dev/sdd3 -S 0

Add another passphrase (8 max)

    cryptsetup luksAddKey /dev/sdd3

Delete passphrase (requires entry of passphrase to delete)

    cryptsetup luksRemoveKey /dev/sdd3

Delete passphrase in slot (requirs any valid passphrase)

    cryptsetup luksKillSlot /dev/sdd3 1

### Links
    
* http://current.workingdirectory.net/posts/2009/grub-on-usb/
* https://bootless.sarava.org/
