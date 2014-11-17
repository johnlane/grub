/*
 * devmapper.c - Device mapper (w/ crypto support)
 *
 * Copyright (C) 2007 Simon Peter <dn.tlp@gmx.net>
 * Thanks to Raoul Boenisch <jkl345@gmx.net> for the initial idea.
 */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/normal.h>
#include <grub/extcmd.h>
#include <grub/disk.h>
#include <grub/crypto.h>

#define DEFAULT_HASH	"ripemd160"
#define DEFAULT_CIPHER	"aes-cbc"
#define MAX_KEYSIZE	64
#define MAX_PASSPHRASE	256

#define MIN(a, b)	(a < b ? a : b)

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_crypto
{
  char *devname, *source_devname;
  int has_partitions;
  grub_crypto_cipher_handle_t cipher;
  grub_disk_t srcdisk;
  int keysize;

  struct grub_crypto *next;
};

typedef struct grub_crypto *grub_crypto_t;

struct crypto_private
{
  grub_crypto_t crypto;
  grub_disk_t srcdisk;
};

typedef struct crypto_private *crypto_private_t;

static grub_crypto_t crypto_list = NULL;

/* Delete a registered crypto device. */
static grub_err_t
delete_crypto (const char *name)
{
  grub_crypto_t dev, *prev;

  /* Search for the device */
  for (dev = crypto_list, prev = &crypto_list; dev;
       prev = &dev->next, dev = dev->next)
    if (grub_strcmp (dev->devname, name) == 0)
      break;

  if (!dev)
    return grub_error (GRUB_ERR_BAD_DEVICE, "Device not found");

  /* Remove the device from the list */
  *prev = dev->next;
  grub_free (dev->devname);
  grub_free (dev->source_devname);
  grub_crypto_cipher_close (dev->cipher);
  grub_free (dev);

  return GRUB_ERR_NONE;
}

/* Hashes a passphrase into a key and stores it with cipher. */
static gcry_err_code_t
set_passphrase (grub_crypto_t dev, const gcry_md_spec_t *hashparams,
		const char *passphrase)
{
  grub_uint8_t hash[MAX_KEYSIZE * 2], *key = hash;
  char *p;
  unsigned int round, i, size = dev->keysize;
  unsigned int len;

  /* Need no passphrase if there's no key */
  if (size == 0)
    return GPG_ERR_INV_KEYLEN;

  /* Hack to support the "none" hash */
  if (hashparams)
    len = hashparams->mdlen;
  else
    len = grub_strlen (passphrase);

  if (size > MAX_KEYSIZE || len > MAX_KEYSIZE)
    return GPG_ERR_INV_KEYLEN;

  p = grub_malloc (grub_strlen (passphrase) + 2 + size / len);
  if (!p)
    return grub_errno;

  for (round = 0; size; round++, key += len, size -= len)
    {
      /* hack from hashalot to avoid null bytes in key */
      for (i = 0; i < round; i++)
	p[i] = 'A';

      grub_strcpy (p + i, passphrase);

      if (len > size)
	len = size;

      grub_crypto_hash (hashparams, key, p, grub_strlen (p));
    }

  return grub_crypto_cipher_set_key (dev->cipher, hash, size);
}

/***** GRUB command line interface *****************************************/


static const struct grub_arg_option options[] = {
  {"delete", 'd', 0, "delete the crypto device entry", 0, ARG_TYPE_NONE},
  {"partitions", 'p', 0, "set that the device has partitions", 0,
   ARG_TYPE_NONE},
  {"cipher", 'c', 0, "set cipher (default=" DEFAULT_CIPHER ")", 0,
   ARG_TYPE_STRING},
  {"hash", 'h', 0, "set hash function (default=" DEFAULT_HASH ")", 0,
   ARG_TYPE_STRING},
  {"passphrase", 'P', 0, "set decryption passphrase", 0, ARG_TYPE_STRING},
  {"keysize", 'k', 0, "set key size (default is cipher specific)", 0,
   ARG_TYPE_INT},
  {0, 0, 0, 0, 0, 0}
};

static grub_err_t
grub_cmd_devmap (grub_extcmd_context_t ctxt, int argc, char **args)
{
  grub_disk_t disk;
  grub_crypto_t newdev;
  const char *cipher, *hash;
  const gcry_md_spec_t *hashparams;
  grub_err_t err = GRUB_ERR_NONE;
  char *passphrase = "";
  /* char cmdphrase[MAX_PASSPHRASE]; */
  const gcry_cipher_spec_t *ciph;
  struct grub_arg_list *state = ctxt->state;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Device name required");

  /* Check whether delete is requested */
  if (state[0].set)
    return delete_crypto (args[0]);

  if (argc < 2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Source device name required");

  /*** Create device is requested ***/

  /* Choke on already existing devices */
  for (newdev = crypto_list; newdev != NULL; newdev = newdev->next)
    if (grub_strcmp (newdev->devname, args[0]) == 0)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "Device already exists");

  /* Check whether source device can be opened */
  disk = grub_disk_open (args[1]);
  if (!disk)
    return grub_errno;
  grub_disk_close (disk);

  /* Parse remaining options */
  if (state[2].set)
    cipher = state[2].arg;
  else
    cipher = DEFAULT_CIPHER;
  if (state[3].set)
    hash = state[3].arg;
  else
    hash = DEFAULT_HASH;

  /* Create new device entry */
  newdev = grub_malloc (sizeof (struct grub_crypto));
  if (!newdev)
    return grub_errno;
  newdev->devname = grub_strdup (args[0]);
  if (!newdev->devname)
    {
      grub_free (newdev);
      return grub_errno;
    }
  newdev->source_devname = grub_strdup (args[1]);
  if (!newdev->source_devname)
    {
      grub_free (newdev->devname);
      grub_free (newdev);
      return grub_errno;
    }
  newdev->has_partitions = state[1].set;
  ciph = grub_crypto_lookup_cipher_by_name (cipher);
  if (!ciph)
    {
      grub_free (newdev->source_devname);
      grub_free (newdev->devname);
      grub_free (newdev);
      return grub_error (GRUB_ERR_CIPHER_NOT_FOUND, "Unknown cipher %s", cipher);
    }
  newdev->cipher = grub_crypto_cipher_open (ciph);
  if (!newdev->cipher)
    {
      grub_free (newdev->source_devname);
      grub_free (newdev->devname);
      grub_free (newdev);
      return grub_errno;
    }
  hashparams = grub_crypto_lookup_md_by_name (hash);
  if (!hashparams)
    {
      grub_free (newdev->source_devname);
      grub_free (newdev->devname);
      grub_free (newdev);
      grub_crypto_cipher_close (newdev->cipher);
      return grub_error (GRUB_ERR_CIPHER_NOT_FOUND, "Unknown digest %s", hash);
    }
  newdev->srcdisk = NULL;
  if (state[5].set)
    newdev->keysize = grub_strtoul (state[5].arg, NULL, 10);
  else
    newdev->keysize = 16;

  /* Get passphrase */
  if (state[4].set)		/* Passphrase supplied on commandline */
    passphrase = state[4].arg;
  else
    {
#if 1
      return 0;
#else
      if (grub_strcmp (cipher, "none"))
	{
	  grub_cmdline_get ("Passphrase: ", cmdphrase, MAX_PASSPHRASE, '*',
			    0);
	  passphrase = cmdphrase;
	}
#endif
    }
  err = set_passphrase (newdev, hashparams, passphrase);
  if (err)
    {
      grub_crypto_cipher_close (newdev->cipher);
      grub_free (newdev->source_devname);
      grub_free (newdev->devname);
      grub_free (newdev);
      return err;
    }

  /* Add new entry to list and return */
  newdev->next = crypto_list;
  crypto_list = newdev;

  /* Error conditions */
  return GRUB_ERR_NONE;
}

/***** GRUB disk device interface ******************************************/

static int
grub_crypto_iterate (int (*hook) (const char *name))
{
  grub_crypto_t i;

  for (i = crypto_list; i != NULL; i = i->next)
    if (hook (i->devname))
      return 1;

  return 0;
}

static grub_err_t
grub_crypto_open (const char *name, grub_disk_t disk)
{
  grub_crypto_t dev;
  crypto_private_t private;

  for (dev = crypto_list; dev != NULL; dev = dev->next)
    if (grub_strcmp (dev->devname, name) == 0)
      break;

  if (!dev)
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "Can't open device");

  /* Setup crypto private structure */
  if (!(private = grub_malloc (sizeof (struct crypto_private))))
    return grub_errno;
  private->crypto = dev;

  /* Open underlying device */
  private->srcdisk = grub_disk_open (dev->source_devname);
  if (!private->srcdisk)
    {
      return grub_errno;
    }

  /* Populate requested disk */
  disk->total_sectors = grub_disk_get_size (private->srcdisk);
  disk->id = (int) dev;
  /*disk->has_partitions = dev->has_partitions;*/
  disk->data = private;

  return 0;
}

static void
grub_crypto_close (grub_disk_t disk)
{
  crypto_private_t private = (crypto_private_t) disk->data;

  grub_disk_close (private->srcdisk);
  grub_free (private);
}

static grub_err_t
grub_crypto_read (grub_disk_t disk, grub_disk_addr_t sector,
		  grub_size_t size, char *buf)
{
  crypto_private_t private = (crypto_private_t) disk->data;
  grub_err_t err;
  grub_crypto_cipher_handle_t cipher = private->crypto->cipher;
  grub_size_t i;

  /* Read sectors from underlying disk */
  err =
    grub_disk_read (private->srcdisk, sector, 0,
		    size << GRUB_DISK_SECTOR_BITS, buf);
  if (err)
    return err;

  /* Decrypt sectors */
  for (i = 0; i < size; i++)
    {
      grub_disk_addr_t s = grub_cpu_to_le64 (sector + i);
      grub_uint8_t iv[cipher->cipher->blocksize];
      gcry_err_code_t gcry_err;

      /* Set IV from raw sector number (plain mode) */
      grub_memset (iv, 0, cipher->cipher->blocksize);
      grub_memcpy (iv, &s,
		   MIN (sizeof (grub_disk_addr_t),
			cipher->cipher->blocksize));

      gcry_err = grub_crypto_cbc_decrypt (cipher,
					  buf + (i << GRUB_DISK_SECTOR_BITS),
					  buf + (i << GRUB_DISK_SECTOR_BITS),
					  GRUB_DISK_SECTOR_SIZE, iv);
      if (gcry_err)
	return grub_crypto_gcry_error (gcry_err);
    }

  return 0;
}

static grub_err_t
grub_crypto_write (grub_disk_t disk __attribute ((unused)),
		   grub_disk_addr_t sector __attribute ((unused)),
		   grub_size_t size __attribute ((unused)),
		   const char *buf __attribute ((unused)))
{
  return GRUB_ERR_NOT_IMPLEMENTED_YET;
}

static struct grub_disk_dev grub_crypto_dev = {
  .name = "crypto",
  .id = GRUB_DISK_DEVICE_DEVMAP_ID,
  .iterate = grub_crypto_iterate,
  .open = grub_crypto_open,
  .close = grub_crypto_close,
  .read = grub_crypto_read,
  .write = grub_crypto_write,
  .next = 0
};

/***** GRUB module (de-)initialization *************************************/

static grub_extcmd_t cmd;

GRUB_MOD_INIT (devmapper)
{
  cmd = grub_register_extcmd ("devmap", grub_cmd_devmap, 0,
			      "devmap [OPTIONS...] [DEVICE] [SRC-DEV]",
			      "Map one device onto another (w/ cryptography support).",
			      options);
  grub_disk_dev_register (&grub_crypto_dev);
}

GRUB_MOD_FINI (devmapper)
{
  grub_unregister_extcmd (cmd);
  grub_disk_dev_unregister (&grub_crypto_dev);
}
