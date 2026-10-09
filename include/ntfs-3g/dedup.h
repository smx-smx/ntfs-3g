/*
 * dedup.h - Exported definitions for Data Deduplication support
 *
 * Copyright (c) 2026 Stefano Moioli
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_DEDUP_H
#define _NTFS_DEDUP_H

#include "types.h"
#include "layout.h"
#include "inode.h"

/*
 *	On-disk structures of the Windows Data Deduplication chunk store
 *
 *	The content of a deduplicated file is replaced by a reparse point
 *	(tag IO_REPARSE_TAG_DEDUP) designating a stream map in the chunk
 *	store located in "System Volume Information/Dedup/ChunkStore".
 *	The stream map lists the data chunks which make up the file.
 *
 *	The chunk store is made of containers, files named
 *	"{store-guid}.ddp/{Stream,Data,Hotspot}/<id>.<generation>.ccc".
 *	A container begins with a header (Cthr), a redirection table
 *	(Rrtl) and then holds the chunks, each one made of a chunk header
 *	(Ckhr) followed by the chunk body. When a container is compacted,
 *	its generation is incremented and the chunk offsets which were
 *	recorded before are translated through the redirection table.
 *
 *	All the headers have a common prefix made of a magic number and
 *	a version, and they end with a CRC-64 of the preceding bytes.
 *	All integers are little-endian.
 */

#define DEDUP_CTHR_MAGIC const_cpu_to_le32(0x72687443) /* "Cthr" */
#define DEDUP_RRTL_MAGIC const_cpu_to_le32(0x6c747252) /* "Rrtl" */
#define DEDUP_CKHR_MAGIC const_cpu_to_le32(0x72686b43) /* "Ckhr" */
#define DEDUP_SMAP_MAGIC const_cpu_to_le32(0x70616d53) /* "Smap" */
#define DEDUP_FERP_MAGIC const_cpu_to_le32(0x70526546) /* "FeRp" */
#define DEDUP_RBRP_MAGIC const_cpu_to_le32(0x70526252) /* "RbRp" */
#define DEDUP_DDRP_MAGIC const_cpu_to_le32(0x70526444) /* "DdRp" */

/*
 *	Formats of reparse data, as major and minor bytes
 */
enum {
	DEDUP_FORMAT_SHORT = 0x0201,	/* Windows 8 era, single part */
	DEDUP_FORMAT_LONG = 0x0102,	/* Windows 8 era, multiple parts */
	DEDUP_FORMAT_PROPERTIES = 0x0103, /* Windows 10 / Server 2016+ */
} ;

/*
 *	Common prefix of the chunk store structures
 */
typedef struct {
	le32 magic;
	u8 version[4];
} __attribute__((__packed__)) DEDUP_COMMON_HEADER;

/*
 *	Container header (Cthr), at the beginning of a container
 */
typedef struct {
/*  0*/	DEDUP_COMMON_HEADER common;
/*  8*/	le64 sequence;
/* 10*/	le32 container_id;
/* 14*/	le32 generation;
/* 18*/	le32 unknown1[2];
/* 20*/	le64 valid_data_length;
/* 28*/	le64 unknown2;
/* 30*/	le32 data_offset;	/* End of redirection table area */
/* 34*/	le32 unknown3;
/* 38*/	le64 checksum;
} __attribute__((__packed__)) DEDUP_CONTAINER_HEADER;

#define DEDUP_RRTL_OFFSET 0x3000

/*
 *	Redirection table header (Rrtl), at offset 0x3000 in a container
 *	It is followed by entries sorted by sequence number.
 */
typedef struct {
/*  0*/	DEDUP_COMMON_HEADER common;
/*  8*/	le32 count;
/*  c*/	le32 entry_size;
/* 10*/	le64 body_checksum;
/* 18*/	le64 checksum;
} __attribute__((__packed__)) DEDUP_RRTL_HEADER;

typedef struct {
	le32 sequence;
	le32 offset;
} __attribute__((__packed__)) DEDUP_RRTL_ENTRY;

enum {
	DEDUP_CHUNK_DATA = 1,
	DEDUP_CHUNK_STREAM = 2,
} ;

/*
 *	Common part of a chunk header (Ckhr)
 */
typedef struct {
/*  0*/	DEDUP_COMMON_HEADER common;
/*  8*/	le32 sequence;
/*  c*/	le32 data_size;		/* size of chunk body */
/* 10*/	le16 type;		/* DEDUP_CHUNK_DATA or DEDUP_CHUNK_STREAM */
/* 12*/	le16 header_size;	/* size of the specific part */
/* 14*/	le32 unknown[3];
} __attribute__((__packed__)) DEDUP_CHUNK_HEADER;

/*
 *	Formats of data chunks, mapped to the RtlDecompressBuffer() ones
 */
enum {
	DEDUP_COMPRESSION_NONE = 0,
	DEDUP_COMPRESSION_LZNT1 = 1,
	DEDUP_COMPRESSION_XPRESS = 2,
	DEDUP_COMPRESSION_XPRESS_HUFF = 3,
} ;

/*
 *	Header of a data chunk, in a Data or Hotspot container
 *	The digest is a SHA-512 of the uncompressed data truncated to
 *	32 bytes.
 */
typedef struct {
/*  0*/	DEDUP_CHUNK_HEADER chunk;
/* 20*/	le32 compression;
/* 24*/	le32 unknown1;
/* 28*/	u8 digest[32];
/* 48*/	le64 unknown2;
/* 50*/	le64 checksum;
} __attribute__((__packed__)) DEDUP_DATA_CHUNK_HEADER;

/*
 *	Header of a stream map chunk, in a Stream container
 */
typedef struct {
/*  0*/	DEDUP_CHUNK_HEADER chunk;
/* 20*/	le32 unknown1[6];
/* 38*/	u8 digest[16];
/* 48*/	le32 unknown2[4];
/* 58*/	le64 unknown3;
/* 60*/	le64 checksum;
} __attribute__((__packed__)) DEDUP_STREAM_CHUNK_HEADER;

/*
 *	Stream map, the body of a stream map chunk
 */
typedef struct {
/*  0*/	le32 sequence;
/*  4*/	le32 container_id;
/*  8*/	le32 offset;
/*  c*/	le32 generation;
/* 10*/	le64 data_end;		/* end of chunk in file */
/* 18*/	u8 digest[32];
/* 38*/	le32 data_size;		/* size of chunk body */
/* 3c*/	le32 unknown;
} __attribute__((__packed__)) DEDUP_SMAP_ENTRY;

typedef struct {
	DEDUP_COMMON_HEADER common;
	DEDUP_SMAP_ENTRY entries[0];
} __attribute__((__packed__)) DEDUP_SMAP;

/*
 *	Designation of the stream map for a part of a file, as stored
 *	in the reparse data.
 */
typedef struct {
/*  0*/	le32 sequence;
/*  4*/	le32 container_id;
/*  8*/	le32 offset;
/*  c*/	le32 unknown1[3];
/* 18*/	le32 data_size;		/* size of stream map */
/* 1c*/	le32 unknown2;
/* 20*/	u8 digest[16];
/* 30*/	le64 part_end;		/* le64 not aligned in older formats */
/* 38*/	le64 part_begin;
} __attribute__((__packed__)) DEDUP_STREAM_ENTRY;

/*
 *	Property sets (FeRp, RbRp and DdRp) in the reparse data of the
 *	DEDUP_FORMAT_PROPERTIES format. The offset of each property is
 *	relative to the beginning of the property set, and the checksum
 *	is a CRC-32 of the rest of the property set.
 */
typedef struct {
	le32 magic;
	le32 checksum;
	le32 size;		/* size of the whole property set */
	le16 reserved;
	le16 count;
} __attribute__((__packed__)) DEDUP_PROPERTY_SET;

typedef struct {
	le16 type;
	le16 size;
	le32 offset;
} __attribute__((__packed__)) DEDUP_PROPERTY;

enum {
	DEDUP_PROPERTY_U32 = 5,
	DEDUP_PROPERTY_U64 = 6,
	DEDUP_PROPERTY_FLAGS = 9,
	DEDUP_PROPERTY_VERSION = 10,
	DEDUP_PROPERTY_TIME = 11,
	DEDUP_PROPERTY_GUID = 12,
	DEDUP_PROPERTY_BLOB = 13,
	DEDUP_PROPERTY_CHUNK_ID = 14,
} ;

/*
 *	Indexes of the properties in the FeRp (file) and DdRp (dedup)
 *	property sets
 */
enum {
	DEDUP_FERP_VERSION = 0,
	DEDUP_FERP_STORE_GUID = 2,
	DEDUP_FERP_FILE_SIZE = 4,
	DEDUP_FERP_DDRP = 8,
	DEDUP_DDRP_VERSION = 0,
	DEDUP_DDRP_STREAMS = 2,
} ;

/*
 *	Reparse data of the older formats, used by Windows Server 2012.
 *	The offsets are relative to the beginning of the reparse data,
 *	after the generic reparse point header.
 */
typedef struct {
/*  0*/	le16 format;		/* DEDUP_FORMAT_LONG */
/*  2*/	le16 length;
/*  4*/	le32 unknown1[16];
/* 44*/	le16 size1;
/* 46*/	le16 offset1;
/* 48*/	le32 unknown2;
/* 4c*/	le16 streams_size;	/* size of the stream entries */
/* 4e*/	le16 streams_offset;	/* location of the stream entries */
/* 50*/	le32 unknown3[9];
/* 74*/	GUID store_guid;
/* 84*/	le32 unknown4[4];
} __attribute__((__packed__)) DEDUP_REPARSE_LONG;

typedef struct {
/*  0*/	le16 format;		/* DEDUP_FORMAT_SHORT */
/*  2*/	le16 length;
/*  4*/	le32 unknown1;
/*  8*/	le64 file_size;
/* 10*/	le32 unknown2[2];
/* 18*/	GUID store_guid;
/* 28*/	le32 unknown3[4];
		/* followed by a stream entry with a 32-byte digest */
} __attribute__((__packed__)) DEDUP_REPARSE_SHORT;

typedef struct DEDUP_FILE ntfs_dedup;

ntfs_dedup *ntfs_dedup_open(ntfs_inode *ni, const REPARSE_POINT *reparse);
s64 ntfs_dedup_pread(ntfs_dedup *dd, s64 pos, s64 count, void *b);
s64 ntfs_dedup_size(const ntfs_dedup *dd);
void ntfs_dedup_close(ntfs_dedup *dd);

#endif /* _NTFS_DEDUP_H */
