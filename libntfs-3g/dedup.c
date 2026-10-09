/**
 * dedup.c - Reading files deduplicated by Windows Data Deduplication
 *
 *      This module is part of ntfs-3g library
 *
 * Copyright (c) 2026 Stefano Moioli
 *
 * Based on the NTFS-3G deduplication plugin,
 * Copyright (c) 2016-2018 Jean-Pierre Andre
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *	A deduplicated file is made of one or more parts, each of which
 *	is described by a stream map located in a Stream container of the
 *	chunk store. The stream map lists the data chunks of the part,
 *	together with the location of each one in a Data container.
 *
 *	The location of a chunk is recorded as a container id, a container
 *	generation and an offset. When the container has been compacted
 *	since, its generation has changed and the chunk has to be located
 *	through the redirection table of the container, using the sequence
 *	number of the chunk.
 *
 *	Opening a file only parses its reparse data. The stream map of
 *	the part being read and the last chunk read are kept in the
 *	context, so that sequential reads only decompress each chunk once.
 *	Everything read from the chunk store is checked before use.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "layout.h"
#include "attrib.h"
#include "inode.h"
#include "dir.h"
#include "index.h"
#include "volume.h"
#include "unistr.h"
#include "security.h"
#include "decompress.h"
#include "dedup.h"
#include "misc.h"
#include "logging.h"

#define DEDUP_STORE_PATH "System Volume Information/Dedup/ChunkStore"
#define DEDUP_MAX_PATH 128

	/* Windows limits stream maps to 1 MiB and chunks to 128 KiB */
#define DEDUP_MAX_SMAP_SIZE 0x400000
#define DEDUP_MAX_CHUNK_SIZE 0x100000
#define DEDUP_MAX_RRTL_COUNT 0x100000
#define DEDUP_CONTAINER_CACHE 8

/* "xxxxxxxx.xxxxxxxx.ccc" */
#define DEDUP_CONTAINER_NAME_LEN 21

	/* Size of the part of chunk headers recorded in header_size */
#define DEDUP_CHUNK_HEADER_BASE 0x30

#define DEDUP_STREAM_ENTRY_SIZE 64

enum {
	DEDUP_STREAM_DIR,
	DEDUP_DATA_DIR,
	DEDUP_DIR_COUNT
} ;

static const char *dedup_dir_names[DEDUP_DIR_COUNT] = { "Stream", "Data" };

struct DEDUP_CONTAINER {
	u32 id;
	u32 generation;
	int dir;
	MFT_REF mref;
	BOOL rrtl_loaded;
	u32 rrtl_count;
	DEDUP_RRTL_ENTRY *rrtl;
} ;

struct DEDUP_PART {
	u64 begin;
	u64 end;
	DEDUP_STREAM_ENTRY entry;
} ;

struct DEDUP_FILE {
	ntfs_volume *vol;
	u64 size;
	char store_path[DEDUP_MAX_PATH];
	MFT_REF dir_mref[DEDUP_DIR_COUNT];
	int part_count;
	struct DEDUP_PART *parts;
		/* stream map of the current part */
	int smap_part;
	u32 smap_count;
	DEDUP_SMAP_ENTRY *smap;
		/* containers recently used */
	int container_count;
	int container_next;
	struct DEDUP_CONTAINER containers[DEDUP_CONTAINER_CACHE];
		/* last chunk read */
	u64 chunk_begin;
	u64 chunk_end;
	u8 *chunk;
	u8 *cbuf;
} ;

/*
 *		Compute the CRC-32 of the reparse data and property sets
 */

static u32 dedup_crc32(const u8 *p, u32 n)
{
	u32 crc;
	int k;

	crc = 0xffffffff;
	while (n--) {
		crc ^= *p++;
		for (k=0; k<8; k++)
			crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1));
	}
	return (~crc);
}

/*
 *		Compute the CRC-64 of a chunk store header
 *
 *	This is the CRC-64 used by Microsoft KTL, with a polynomial
 *	0x9a6c9329ac4bc9b5 (reflected), a null initial value and an
 *	inverted result.
 */

static u64 dedup_crc64(const u8 *p, u32 n)
{
	u64 crc;
	int k;

	crc = 0;
	while (n--) {
		crc ^= *p++;
		for (k=0; k<8; k++)
			crc = (crc >> 1)
				^ (0x9a6c9329ac4bc9b5ULL & -(crc & 1));
	}
	return (~crc);
}

/*
 *		Compute a SHA-512 digest
 *
 *	The digest of a data chunk is the SHA-512 of its uncompressed
 *	data truncated to 32 bytes. This is a plain implementation of
 *	FIPS 180-4, only used for checking chunks.
 */

static const u64 sha512_k[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
} ;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_block(u64 *h, const u8 *p)
{
	u64 w[80];
	u64 a, b, c, d, e, f, g, x;
	u64 t1, t2;
	int i;
	int j;

	for (i=0; i<16; i++) {
		w[i] = 0;
		for (j=0; j<8; j++)
			w[i] = (w[i] << 8) | p[8*i + j];
	}
	for (i=16; i<80; i++)
		w[i] = (ROR64(w[i-2], 19) ^ ROR64(w[i-2], 61) ^ (w[i-2] >> 6))
			+ w[i-7]
			+ (ROR64(w[i-15], 1) ^ ROR64(w[i-15], 8)
				^ (w[i-15] >> 7))
			+ w[i-16];
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; x = h[7];
	for (i=0; i<80; i++) {
		t1 = x + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41))
			+ ((e & f) ^ (~e & g)) + sha512_k[i] + w[i];
		t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39))
			+ ((a & b) ^ (a & c) ^ (b & c));
		x = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += x;
}

static void dedup_sha512(const u8 *p, u32 n, u8 *digest)
{
	u64 h[8] = {
		0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
		0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
		0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
	} ;
	u8 tail[256];
	u64 bits;
	u32 rest;
	u32 len;
	int i;

	bits = (u64)n << 3;
	while (n >= 128) {
		sha512_block(h, p);
		p += 128;
		n -= 128;
	}
	rest = n;
	memcpy(tail, p, rest);
	tail[rest++] = 0x80;
	len = (rest <= 112 ? 128 : 256);
	memset(&tail[rest], 0, len - rest);
		/* the 128-bit length, the upper half is zero */
	for (i=0; i<8; i++)
		tail[len - 1 - i] = bits >> (8*i);
	sha512_block(h, tail);
	if (len == 256)
		sha512_block(h, &tail[128]);
	for (i=0; i<64; i++)
		digest[i] = h[i >> 3] >> (56 - 8*(i & 7));
}

static BOOL dedup_valid_crc64(const void *hdr, u32 size)
{
	return (dedup_crc64((const u8*)hdr, size - sizeof(le64))
		== le64_to_cpup((const le64*)((const u8*)hdr
				+ size - sizeof(le64))));
}

static int dedup_corrupt(const char *what)
{
	ntfs_log_error("Deduplication store : bad %s\n", what);
	errno = EIO;
	return (-1);
}

/*
 *		Get a property from a property set
 *
 *	The property set is checked when getting its first property.
 *
 *	Returns the location of the property value,
 *		or NULL if it is not present or the property set is bad
 */

static const u8 *dedup_property(const u8 *set, u32 set_size, le32 magic,
			int index, int type, u32 *psize)
{
	const DEDUP_PROPERTY_SET *head;
	const DEDUP_PROPERTY *prop;
	u32 size;
	u32 offset;
	u32 count;

	head = (const DEDUP_PROPERTY_SET*)set;
	if (set_size < sizeof(DEDUP_PROPERTY_SET))
		goto bad;
	size = le32_to_cpu(head->size);
	count = le16_to_cpu(head->count);
	if ((head->magic != magic)
	    || (size < sizeof(DEDUP_PROPERTY_SET))
	    || (size > set_size)
	    || (dedup_crc32(&set[8], size - 8)
			!= le32_to_cpu(head->checksum))
	    || (count > ((size - sizeof(DEDUP_PROPERTY_SET))
				/ sizeof(DEDUP_PROPERTY))))
		goto bad;
	if (index >= (int)count)
		goto bad;
	prop = (const DEDUP_PROPERTY*)&set[sizeof(DEDUP_PROPERTY_SET)];
	prop += index;
	offset = le32_to_cpu(prop->offset);
	if ((le16_to_cpu(prop->type) != type)
	    || (offset > size)
	    || (le16_to_cpu(prop->size) > (size - offset)))
		goto bad;
	*psize = le16_to_cpu(prop->size);
	return (&set[offset]);
bad :
	dedup_corrupt("reparse property");
	return ((const u8*)NULL);
}

static BOOL dedup_property_version(const u8 *set, u32 set_size, le32 magic,
			int index)
{
	const u8 *value;
	u32 size;

	value = dedup_property(set, set_size, magic, index,
			DEDUP_PROPERTY_VERSION, &size);
	return (value && (size == sizeof(le32))
		&& (le32_to_cpup((const le32*)value) == 1));
}

/*
 *		Set the parts of a file from an array of stream entries
 *
 *	The parts must be contiguous and cover the whole file.
 */

static int dedup_set_parts(ntfs_dedup *dd, const u8 *entries, int count)
{
	struct DEDUP_PART *part;
	u64 previous;
	int i;

	dd->parts = (struct DEDUP_PART*)ntfs_malloc(count
				* sizeof(struct DEDUP_PART));
	if (!dd->parts)
		return (-1);
	previous = 0;
	for (i=0; i<count; i++) {
		part = &dd->parts[i];
		memcpy(&part->entry, &entries[i*DEDUP_STREAM_ENTRY_SIZE],
					DEDUP_STREAM_ENTRY_SIZE);
		part->begin = le64_to_cpu(part->entry.part_begin);
		part->end = le64_to_cpu(part->entry.part_end);
		if ((part->begin != previous) || (part->end <= part->begin))
			return (dedup_corrupt("file part"));
		previous = part->end;
	}
	dd->part_count = count;
	if (previous != dd->size)
		return (dedup_corrupt("file size"));
	return (0);
}

/*
 *		Parse the reparse data made of property sets
 *
 *	The data is made of a FeRp property set describing the file,
 *	which contains a DdRp property set designating the stream maps.
 */

static int dedup_parse_properties(ntfs_dedup *dd, const u8 *data, u32 size)
{
	const u8 *ddrp;
	const u8 *value;
	u32 ddrp_size;
	u32 value_size;
	char guid[37];
	int i;

	if (!dedup_property_version(data, size, DEDUP_FERP_MAGIC,
					DEDUP_FERP_VERSION))
		return (dedup_corrupt("reparse version"));
	value = dedup_property(data, size, DEDUP_FERP_MAGIC,
			DEDUP_FERP_STORE_GUID, DEDUP_PROPERTY_GUID,
			&value_size);
	if (!value || (value_size != sizeof(GUID))
	    || !ntfs_guid_to_mbs((const GUID*)value, guid))
		return (dedup_corrupt("store guid"));
	for (i=0; guid[i]; i++)
		if ((guid[i] >= 'a') && (guid[i] <= 'f'))
			guid[i] += 'A' - 'a';
	snprintf(dd->store_path, DEDUP_MAX_PATH, "%s/{%s}.ddp",
			DEDUP_STORE_PATH, guid);
	value = dedup_property(data, size, DEDUP_FERP_MAGIC,
			DEDUP_FERP_FILE_SIZE, DEDUP_PROPERTY_U64, &value_size);
	if (!value || (value_size != sizeof(le64)))
		return (dedup_corrupt("file size"));
	dd->size = le64_to_cpup((const le64*)value);
	ddrp = dedup_property(data, size, DEDUP_FERP_MAGIC,
			DEDUP_FERP_DDRP, DEDUP_PROPERTY_BLOB, &ddrp_size);
	if (!ddrp
	    || !dedup_property_version(ddrp, ddrp_size, DEDUP_DDRP_MAGIC,
					DEDUP_DDRP_VERSION))
		return (dedup_corrupt("dedup properties"));
	value = dedup_property(ddrp, ddrp_size, DEDUP_DDRP_MAGIC,
			DEDUP_DDRP_STREAMS, DEDUP_PROPERTY_BLOB, &value_size);
	if (!value || !value_size || (value_size % DEDUP_STREAM_ENTRY_SIZE))
		return (dedup_corrupt("stream entries"));
	return (dedup_set_parts(dd, value,
			value_size / DEDUP_STREAM_ENTRY_SIZE));
}

/*
 *		Open a deduplicated file for reading
 *
 *	Only the reparse data is parsed, the chunk store is accessed
 *	when reading.
 *
 *	Returns a reading context, or NULL with errno set
 *		(EOPNOTSUPP if the reparse data has an unsupported format)
 */

ntfs_dedup *ntfs_dedup_open(ntfs_inode *ni, const REPARSE_POINT *reparse)
{
	ntfs_dedup *dd;
	const u8 *data;
	u32 size;
	int format;
	int res;

	if (!ni || !reparse || (reparse->reparse_tag != IO_REPARSE_TAG_DEDUP)) {
		errno = EINVAL;
		return ((ntfs_dedup*)NULL);
	}
	data = reparse->reparse_data;
	size = le16_to_cpu(reparse->reparse_data_length);
		/* format, length and the final crc32 */
	if ((size < 8)
	    || (le16_to_cpup((const le16*)&data[2]) != size)
	    || (dedup_crc32(data, size - 4)
			!= le32_to_cpup((const le32*)&data[size - 4]))) {
		dedup_corrupt("reparse data");
		return ((ntfs_dedup*)NULL);
	}
	dd = (ntfs_dedup*)ntfs_calloc(sizeof(ntfs_dedup));
	if (!dd)
		return ((ntfs_dedup*)NULL);
	dd->vol = ni->vol;
	dd->smap_part = -1;
	format = le16_to_cpup((const le16*)data);
	switch (format) {
	case DEDUP_FORMAT_PROPERTIES :
		res = dedup_parse_properties(dd, &data[4], size - 8);
		break;
	default :
		ntfs_log_error("Unsupported deduplication format 0x%04x"
				" in inode %lld\n", format,
				(long long)ni->mft_no);
		errno = EOPNOTSUPP;
		res = -1;
		break;
	}
	if (res) {
		ntfs_dedup_close(dd);
		dd = (ntfs_dedup*)NULL;
	}
	return (dd);
}

s64 ntfs_dedup_size(const ntfs_dedup *dd)
{
	return (dd->size);
}

static void dedup_drop_containers(ntfs_dedup *dd)
{
	int i;

	for (i=0; i<dd->container_count; i++)
		free(dd->containers[i].rrtl);
	dd->container_count = 0;
	dd->container_next = 0;
}

void ntfs_dedup_close(ntfs_dedup *dd)
{
	if (dd) {
		dedup_drop_containers(dd);
		free(dd->parts);
		free(dd->smap);
		free(dd->chunk);
		free(dd->cbuf);
		free(dd);
	}
}

/*
 *		Open a directory of the chunk store
 */

static ntfs_inode *dedup_open_dir(ntfs_dedup *dd, int dir)
{
	char path[DEDUP_MAX_PATH + 16];
	ntfs_inode *ni;

	if (dd->dir_mref[dir])
		return (ntfs_inode_open(dd->vol, dd->dir_mref[dir]));
	snprintf(path, sizeof(path), "%s/%s", dd->store_path,
			dedup_dir_names[dir]);
	ni = ntfs_pathname_to_inode(dd->vol, (ntfs_inode*)NULL, path);
	if (ni)
		dd->dir_mref[dir] = MK_MREF(ni->mft_no,
				le16_to_cpu(ni->mrec->sequence_number));
	else
		ntfs_log_perror("Could not open deduplication store %s",
				path);
	return (ni);
}

/*
 *		Check whether a file name is "<id>.<generation>.ccc"
 *
 *	Returns TRUE if so, and sets the generation
 */

static BOOL dedup_container_name(const ntfschar *name, int len, u32 id,
			u32 *generation)
{
	char expected[10];
	u32 gen;
	int c;
	int i;

	if (len != DEDUP_CONTAINER_NAME_LEN)
		return (FALSE);
	snprintf(expected, sizeof(expected), "%08lx.", (long)id);
	for (i=0; i<9; i++) {
		c = le16_to_cpu(name[i]);
		if ((c >= 'A') && (c <= 'F'))
			c += 'a' - 'A';
		if (c != expected[i])
			return (FALSE);
	}
	gen = 0;
	for (i=9; i<17; i++) {
		c = le16_to_cpu(name[i]);
		if ((c >= '0') && (c <= '9'))
			gen = (gen << 4) + c - '0';
		else if ((c >= 'a') && (c <= 'f'))
			gen = (gen << 4) + c - 'a' + 10;
		else if ((c >= 'A') && (c <= 'F'))
			gen = (gen << 4) + c - 'A' + 10;
		else
			return (FALSE);
	}
	if ((le16_to_cpu(name[17]) != '.')
	    || ((le16_to_cpu(name[18]) | 0x20) != 'c')
	    || ((le16_to_cpu(name[19]) | 0x20) != 'c')
	    || ((le16_to_cpu(name[20]) | 0x20) != 'c'))
		return (FALSE);
	*generation = gen;
	return (TRUE);
}

/*
 *		Locate the current generation of a container
 *
 *	Several generations may temporarily coexist, the latest one is
 *	the valid one. The names "<id>.<generation>.ccc" collate in the
 *	order of generations, so the directory index is walked from the
 *	position of "<id>.00000000.ccc" while names begin with "<id>.".
 *
 *	Returns 0 if found, -1 otherwise
 */

static int dedup_find_container(ntfs_inode *dir_ni, u32 id,
			MFT_REF *mref, u32 *generation)
{
	char name[DEDUP_CONTAINER_NAME_LEN + 1];
	struct {
		FILE_NAME_ATTR attr;
		ntfschar more[DEDUP_CONTAINER_NAME_LEN];
	} key;
	ntfs_index_context *xctx;
	INDEX_ENTRY *entry;
	ntfschar *uname;
	const FILE_NAME_ATTR *fn;
	const ntfschar *fname;
	u32 gen;
	int len;
	int res;

	res = -1;
	snprintf(name, sizeof(name), "%08lx.00000000.ccc", (long)id);
	uname = (ntfschar*)NULL;
	len = ntfs_mbstoucs(name, &uname);
	if (len != DEDUP_CONTAINER_NAME_LEN) {
		free(uname);
		return (-1);
	}
	memset(&key, 0, sizeof(key));
	memcpy((ntfschar*)&key.attr.file_name, uname, len*sizeof(ntfschar));
	key.attr.file_name_length = len;
	key.attr.file_name_type = FILE_NAME_WIN32;
	xctx = ntfs_index_ctx_get(dir_ni, NTFS_INDEX_I30, 4);
	if (!xctx) {
		free(uname);
		return (-1);
	}
		/* not found is expected, giving the next entry */
	if (ntfs_index_lookup(&key, sizeof(key), xctx) && (errno != ENOENT))
		entry = (INDEX_ENTRY*)NULL;
	else
		entry = xctx->entry;
	if (entry && (entry->ie_flags & INDEX_ENTRY_END))
		entry = ntfs_index_next(entry, xctx);
	while (entry && !(entry->ie_flags & INDEX_ENTRY_END)) {
		fn = &entry->key.file_name;
		fname = (const ntfschar*)((const char*)fn
				+ offsetof(FILE_NAME_ATTR, file_name));
		if (dedup_container_name(fname,
				fn->file_name_length, id, &gen)) {
			if (res || (gen > *generation)) {
				*generation = gen;
				*mref = le64_to_cpu(entry->indexed_file);
				res = 0;
			}
		} else {
			/* stop when the name no longer begins with id */
			if ((fn->file_name_length < 9)
			    || (le16_to_cpu(fname[8]) != '.')
			    || (ntfs_ucsncasecmp(fname, uname, 8,
					dir_ni->vol->upcase,
					dir_ni->vol->upcase_len)))
				break;
		}
		entry = ntfs_index_next(entry, xctx);
	}
	ntfs_index_ctx_put(xctx);
	free(uname);
	return (res);
}

/*
 *		Get a container, from the cache or from the store
 */

static struct DEDUP_CONTAINER *dedup_get_container(ntfs_dedup *dd,
			int dir, u32 id)
{
	struct DEDUP_CONTAINER *cont;
	ntfs_inode *dir_ni;
	MFT_REF mref;
	u32 generation;
	int i;
	int res;

	for (i=0; i<dd->container_count; i++) {
		cont = &dd->containers[i];
		if ((cont->dir == dir) && (cont->id == id))
			return (cont);
	}
	dir_ni = dedup_open_dir(dd, dir);
	if (!dir_ni)
		return ((struct DEDUP_CONTAINER*)NULL);
	generation = 0;
	res = dedup_find_container(dir_ni, id, &mref, &generation);
	ntfs_inode_close(dir_ni);
	if (res) {
		ntfs_log_error("Deduplication container %s/%08lx.*.ccc"
				" not found\n",
				dedup_dir_names[dir], (long)id);
		errno = EIO;
		return ((struct DEDUP_CONTAINER*)NULL);
	}
	if (dd->container_count < DEDUP_CONTAINER_CACHE)
		cont = &dd->containers[dd->container_count++];
	else {
		cont = &dd->containers[dd->container_next];
		dd->container_next = (dd->container_next + 1)
					% DEDUP_CONTAINER_CACHE;
		free(cont->rrtl);
	}
	cont->dir = dir;
	cont->id = id;
	cont->generation = generation;
	cont->mref = mref;
	cont->rrtl_loaded = FALSE;
	cont->rrtl_count = 0;
	cont->rrtl = (DEDUP_RRTL_ENTRY*)NULL;
	return (cont);
}

/*
 *		Read from a container, failing on a short read
 */

static int dedup_pread(ntfs_attr *na, s64 pos, u32 count, void *b)
{
	s64 got;

	got = ntfs_attr_pread(na, pos, count, b);
	if (got == (s64)count)
		return (0);
	if (got >= 0)
		dedup_corrupt("container size");
	return (-1);
}

/*
 *		Load the redirection table of a container
 */

static int dedup_load_rrtl(struct DEDUP_CONTAINER *cont, ntfs_attr *na)
{
	DEDUP_RRTL_HEADER head;
	u32 count;
	u32 size;

	if (dedup_pread(na, DEDUP_RRTL_OFFSET, sizeof(head), &head))
		return (-1);
	count = le32_to_cpu(head.count);
	if ((head.common.magic != DEDUP_RRTL_MAGIC)
	    || !dedup_valid_crc64(&head, sizeof(head))
	    || (le32_to_cpu(head.entry_size) != sizeof(DEDUP_RRTL_ENTRY))
	    || (count > DEDUP_MAX_RRTL_COUNT))
		return (dedup_corrupt("redirection table"));
	if (count) {
		size = count*sizeof(DEDUP_RRTL_ENTRY);
		cont->rrtl = (DEDUP_RRTL_ENTRY*)ntfs_malloc(size);
		if (!cont->rrtl)
			return (-1);
		if (dedup_pread(na, DEDUP_RRTL_OFFSET + sizeof(head),
					size, cont->rrtl))
			goto fail;
		if (dedup_crc64((const u8*)cont->rrtl, size)
				!= le64_to_cpu(head.body_checksum)) {
			dedup_corrupt("redirection table");
			goto fail;
		}
	}
	cont->rrtl_count = count;
	cont->rrtl_loaded = TRUE;
	return (0);
fail :
	free(cont->rrtl);
	cont->rrtl = (DEDUP_RRTL_ENTRY*)NULL;
	return (-1);
}

/*
 *		Translate a chunk sequence number through the redirection table
 *
 *	Returns the redirected offset, or 0 if there is none
 *		or -1 if there was an error
 */

static s64 dedup_redirect(struct DEDUP_CONTAINER *cont, ntfs_attr *na,
			u32 sequence)
{
	u32 lower;
	u32 upper;
	u32 middle;
	u32 seq;

	if (!cont->rrtl_loaded && dedup_load_rrtl(cont, na))
		return (-1);
	lower = 0;
	upper = cont->rrtl_count;
	while (lower < upper) {
		middle = (lower + upper) >> 1;
		seq = le32_to_cpu(cont->rrtl[middle].sequence);
		if (seq == sequence)
			return (le32_to_cpu(cont->rrtl[middle].offset));
		if (seq < sequence)
			lower = middle + 1;
		else
			upper = middle;
	}
	return (0);
}

/*
 *		Check a chunk header
 */

static BOOL dedup_valid_chunk(const DEDUP_CHUNK_HEADER *chunk, u32 hsize,
			int type, u32 sequence, u32 data_size,
			const u8 *digest, const u8 *expected, u32 digest_size)
{
	return ((chunk->common.magic == DEDUP_CKHR_MAGIC)
		&& (le16_to_cpu(chunk->type) == type)
		&& (le16_to_cpu(chunk->header_size)
				== (hsize - DEDUP_CHUNK_HEADER_BASE))
		&& (le32_to_cpu(chunk->sequence) == sequence)
		&& (le32_to_cpu(chunk->data_size) == data_size)
		&& !memcmp(digest, expected, digest_size)
		&& dedup_valid_crc64(chunk, hsize));
}

/*
 *		Read and check the header of a chunk
 *
 *	The recorded offset is tried first if the generation of the
 *	container is the expected one, otherwise the redirected offset is
 *	tried first.
 *
 *	Returns the offset of the chunk, or -1 if it could not be found
 */

static s64 dedup_locate_chunk(struct DEDUP_CONTAINER *cont, ntfs_attr *na,
			BOOL same_generation, u32 offset, int type,
			u32 sequence, u32 data_size,
			const u8 *expected, u32 digest_size,
			void *hdr, u32 hsize)
{
	DEDUP_CHUNK_HEADER *chunk;
	const u8 *digest;
	s64 tries[2];
	s64 redirected;
	int i;

		/* a bad redirection table does not prevent direct access */
	redirected = dedup_redirect(cont, na, sequence);
	if (redirected < 0)
		redirected = 0;
	tries[0] = (same_generation ? offset : redirected);
	tries[1] = (same_generation ? redirected : offset);
	chunk = (DEDUP_CHUNK_HEADER*)hdr;
	if (type == DEDUP_CHUNK_DATA)
		digest = ((DEDUP_DATA_CHUNK_HEADER*)hdr)->digest;
	else
		digest = ((DEDUP_STREAM_CHUNK_HEADER*)hdr)->digest;
	for (i=0; i<2; i++) {
		if (!tries[i] || ((i == 1) && (tries[1] == tries[0])))
			continue;
		if (dedup_pread(na, tries[i], hsize, hdr))
			continue;
		if (dedup_valid_chunk(chunk, hsize, type, sequence,
				data_size, digest, expected, digest_size))
			return (tries[i]);
	}
	ntfs_log_error("Chunk %lu not found in deduplication container"
			" %s/%08lx.%08lx.ccc\n", (unsigned long)sequence,
			dedup_dir_names[cont->dir], (long)cont->id,
			(long)cont->generation);
	errno = EIO;
	return (-1);
}

/*
 *		Open the data attribute of a container
 */

static ntfs_attr *dedup_open_container(ntfs_dedup *dd,
			struct DEDUP_CONTAINER *cont)
{
	ntfs_inode *ni;
	ntfs_attr *na;

	na = (ntfs_attr*)NULL;
	ni = ntfs_inode_open(dd->vol, cont->mref);
	if (ni) {
		na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
		if (!na)
			ntfs_inode_close(ni);
	}
	if (!na)
		ntfs_log_perror("Could not open deduplication container"
				" %s/%08lx.%08lx.ccc",
				dedup_dir_names[cont->dir], (long)cont->id,
				(long)cont->generation);
	return (na);
}

static void dedup_close_container(ntfs_attr *na)
{
	ntfs_inode *ni;

	ni = na->ni;
	ntfs_attr_close(na);
	ntfs_inode_close(ni);
}

/*
 *		Load the stream map of a part of the file
 *
 *	The stream map must describe exactly the expected part.
 */

static int dedup_load_smap(ntfs_dedup *dd, int part)
{
	const DEDUP_STREAM_ENTRY *entry;
	struct DEDUP_CONTAINER *cont;
	DEDUP_STREAM_CHUNK_HEADER hdr;
	DEDUP_SMAP *smap;
	ntfs_attr *na;
	u64 previous;
	u64 end;
	u32 size;
	u32 count;
	u32 i;
	s64 offset;

	entry = &dd->parts[part].entry;
	size = le32_to_cpu(entry->data_size);
	if ((size < (sizeof(DEDUP_SMAP) + sizeof(DEDUP_SMAP_ENTRY)))
	    || (size > DEDUP_MAX_SMAP_SIZE)
	    || ((size - sizeof(DEDUP_SMAP)) % sizeof(DEDUP_SMAP_ENTRY)))
		return (dedup_corrupt("stream map size"));
	cont = dedup_get_container(dd, DEDUP_STREAM_DIR,
			le32_to_cpu(entry->container_id));
	if (!cont)
		return (-1);
	na = dedup_open_container(dd, cont);
	if (!na)
		return (-1);
	smap = (DEDUP_SMAP*)NULL;
		/* no generation is recorded for the stream map */
	offset = dedup_locate_chunk(cont, na, TRUE,
			le32_to_cpu(entry->offset), DEDUP_CHUNK_STREAM,
			le32_to_cpu(entry->sequence), size,
			entry->digest, sizeof(entry->digest),
			&hdr, sizeof(hdr));
	if (offset >= 0) {
		smap = (DEDUP_SMAP*)ntfs_malloc(size);
		if (smap && dedup_pread(na, offset + sizeof(hdr), size, smap)) {
			free(smap);
			smap = (DEDUP_SMAP*)NULL;
		}
	}
	dedup_close_container(na);
	if (!smap)
		return (-1);
	count = (size - sizeof(DEDUP_SMAP)) / sizeof(DEDUP_SMAP_ENTRY);
	previous = dd->parts[part].begin;
	for (i=0; i<count; i++) {
		end = le64_to_cpu(smap->entries[i].data_end);
		if ((end <= previous)
		    || ((end - previous) > DEDUP_MAX_CHUNK_SIZE))
			break;
		previous = end;
	}
	if ((smap->common.magic != DEDUP_SMAP_MAGIC)
	    || (i < count) || (previous != dd->parts[part].end)) {
		free(smap);
		return (dedup_corrupt("stream map"));
	}
		/* keep the entries only */
	memmove(smap, smap->entries, count*sizeof(DEDUP_SMAP_ENTRY));
	free(dd->smap);
	dd->smap = (DEDUP_SMAP_ENTRY*)smap;
	dd->smap_count = count;
	dd->smap_part = part;
	return (0);
}

/*
 *		Uncompress the body of a data chunk
 */

static int dedup_uncompress(int format, const u8 *in, u32 in_size,
			u8 *out, u32 out_size)
{
	s32 got;

	switch (format) {
	case DEDUP_COMPRESSION_LZNT1 :
		got = ntfs_lznt1_decompress(in, in_size, out, out_size);
		break;
	case DEDUP_COMPRESSION_XPRESS :
		got = ntfs_xpress_decompress(in, in_size, out, out_size);
		break;
	case DEDUP_COMPRESSION_XPRESS_HUFF :
		got = ntfs_xpress_huff_decompress(in, in_size, out, out_size);
		break;
	default :
		ntfs_log_error("Unsupported deduplication compression %d\n",
				format);
		got = -1;
		break;
	}
	if (got != (s32)out_size)
		return (dedup_corrupt("compressed chunk"));
	return (0);
}

/*
 *		Load a data chunk of the current stream map
 */

static int dedup_load_chunk(ntfs_dedup *dd, u32 index)
{
	const DEDUP_SMAP_ENTRY *entry;
	struct DEDUP_CONTAINER *cont;
	DEDUP_DATA_CHUNK_HEADER hdr;
	ntfs_attr *na;
	u8 digest[64];
	u64 begin;
	u64 end;
	u32 usize;
	u32 csize;
	s64 offset;
	int res;

	entry = &dd->smap[index];
	begin = (index ? le64_to_cpu(entry[-1].data_end)
			: dd->parts[dd->smap_part].begin);
	end = le64_to_cpu(entry->data_end);
	usize = end - begin;
	csize = le32_to_cpu(entry->data_size);
	if (!csize || (csize > usize))
		return (dedup_corrupt("chunk size"));
	if (!dd->chunk) {
		dd->chunk = (u8*)ntfs_malloc(DEDUP_MAX_CHUNK_SIZE);
		if (!dd->chunk)
			return (-1);
	}
	cont = dedup_get_container(dd, DEDUP_DATA_DIR,
			le32_to_cpu(entry->container_id));
	if (!cont)
		return (-1);
	na = dedup_open_container(dd, cont);
	if (!na)
		return (-1);
	res = -1;
	dd->chunk_end = 0; /* invalidate */
	offset = dedup_locate_chunk(cont, na,
			le32_to_cpu(entry->generation) == cont->generation,
			le32_to_cpu(entry->offset), DEDUP_CHUNK_DATA,
			le32_to_cpu(entry->sequence), csize,
			entry->digest, sizeof(entry->digest),
			&hdr, sizeof(hdr));
	if (offset < 0)
		goto out;
	offset += sizeof(hdr);
	if (csize == usize) {
		/* stored uncompressed */
		if (dedup_pread(na, offset, csize, dd->chunk))
			goto out;
	} else {
		if (!dd->cbuf) {
			dd->cbuf = (u8*)ntfs_malloc(DEDUP_MAX_CHUNK_SIZE);
			if (!dd->cbuf)
				goto out;
		}
		if (dedup_pread(na, offset, csize, dd->cbuf)
		    || dedup_uncompress(le32_to_cpu(hdr.compression),
				dd->cbuf, csize, dd->chunk, usize))
			goto out;
	}
	dedup_sha512(dd->chunk, usize, digest);
	if (memcmp(digest, entry->digest, sizeof(entry->digest))) {
		ntfs_log_error("Bad digest for chunk %lu in deduplication"
				" container Data/%08lx.%08lx.ccc\n",
				(unsigned long)le32_to_cpu(entry->sequence),
				(long)cont->id, (long)cont->generation);
		errno = EIO;
		goto out;
	}
	dd->chunk_begin = begin;
	dd->chunk_end = end;
	res = 0;
out :
	dedup_close_container(na);
	return (res);
}

/*
 *		Make the chunk containing a file position the current one
 */

static int dedup_seek_chunk(ntfs_dedup *dd, u64 pos)
{
	u32 lower;
	u32 upper;
	u32 middle;
	int part;

	if ((pos >= dd->chunk_begin) && (pos < dd->chunk_end))
		return (0);
	for (part=0; (part<dd->part_count) && (pos>=dd->parts[part].end);
				part++) { }
	if (part >= dd->part_count) {
		errno = EINVAL;
		return (-1);
	}
	if ((part != dd->smap_part) && dedup_load_smap(dd, part))
		return (-1);
		/* locate the first chunk ending beyond pos */
	lower = 0;
	upper = dd->smap_count - 1;
	while (lower < upper) {
		middle = (lower + upper) >> 1;
		if (le64_to_cpu(dd->smap[middle].data_end) <= pos)
			lower = middle + 1;
		else
			upper = middle;
	}
	return (dedup_load_chunk(dd, lower));
}

/*
 *		Read from a deduplicated file
 *
 *	Returns the number of bytes read, which is less than requested
 *		only at end of file or after an error,
 *		or -1 with errno set if nothing could be read.
 */

s64 ntfs_dedup_pread(ntfs_dedup *dd, s64 pos, s64 count, void *b)
{
	s64 total;
	s64 n;
	u64 cur;

	if (!dd || (pos < 0) || (count < 0) || !b) {
		errno = EINVAL;
		return (-1);
	}
	if ((u64)pos >= dd->size)
		return (0);
	if ((u64)count > (dd->size - pos))
		count = dd->size - pos;
	total = 0;
	while (total < count) {
		cur = pos + total;
		if (dedup_seek_chunk(dd, cur))
			return (total ? total : -1);
		n = dd->chunk_end - cur;
		if (n > (count - total))
			n = count - total;
		memcpy((char*)b + total, &dd->chunk[cur - dd->chunk_begin], n);
		total += n;
	}
	return (total);
}
