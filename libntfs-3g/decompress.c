/**
 * decompress.c - Decompressors for the Windows RTL compression formats
 *
 *      This module is part of ntfs-3g library
 *
 * Copyright (c) 2026 Stefano Moioli
 *
 * The plain LZ77 decoder is based on the one from the NTFS-3G
 * deduplication plugin, Copyright (c) 2016-2018 Jean-Pierre Andre
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
 *	These are the formats which RtlDecompressBuffer() accepts, as
 *	specified in [MS-XCA] :
 *
 *	- LZNT1 (COMPRESSION_FORMAT_LZNT1)
 *	- Plain LZ77 (COMPRESSION_FORMAT_XPRESS)
 *	- LZ77+Huffman (COMPRESSION_FORMAT_XPRESS_HUFF)
 *
 *	LZNT1 is the format used for NTFS compressed attributes, however
 *	the decoder in compress.c works on full compression blocks made of
 *	4096-byte sub-blocks, whereas a buffer produced by RtlCompressBuffer()
 *	may end with a short uncompressed chunk.
 *
 *	The decoders only depend on the buffers they are given, the
 *	output size is expected to be known by the caller. Every access
 *	to the input and output buffers is checked, the input may come
 *	from a corrupted or crafted volume.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
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
#include "endians.h"
#include "decompress.h"
#include "misc.h"
#include "logging.h"

#define LZNT1_CHUNK_SIZE 4096
#define LZNT1_CHUNK_COMPRESSED 0x8000
#define LZNT1_CHUNK_SIZE_MASK 0x0fff

#define XPRESS_HUFF_SYMBOLS 512
#define XPRESS_HUFF_MAX_CODE_LEN 15
#define XPRESS_HUFF_BLOCK_SIZE 65536
#define XPRESS_HUFF_INVALID 0xffff

static inline u16 get_le16(const u8 *p)
{
	return (p[0] | (p[1] << 8));
}

static inline u32 get_le32(const u8 *p)
{
	return (p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24));
}

/*
 *		Copy a match, the source and the target may overlap
 */

static inline void copy_match(u8 *out, u32 pos, u32 offset, u32 length)
{
	u8 *dst;
	const u8 *src;

	dst = &out[pos];
	src = &out[pos - offset];
	while (length--)
		*dst++ = *src++;
}

/*
 *		Decompress a LZNT1 buffer
 *
 *	The buffer is a sequence of chunks, each one decompressing to
 *	4096 bytes, but for the last one. A chunk begins with a 16-bit
 *	header made of the chunk size minus 3, a signature and a flag
 *	telling whether the chunk is compressed.
 *
 *	Returns the number of bytes produced, or -1 if the data is bad
 */

s32 ntfs_lznt1_decompress(const u8 *in, u32 in_size, u8 *out, u32 out_size)
{
	const u8 *cp;
	const u8 *cend;
	u32 ipos;
	u32 opos;
	u32 cstart;
	u32 climit;
	u32 csize;
	u32 pos;
	u32 disp;
	u32 len;
	u32 j;
	u16 hdr;
	u16 pt;
	u8 tag;
	int lg;
	int i;

	ipos = 0;
	opos = 0;
	while (((ipos + 2) <= in_size) && (opos < out_size)) {
		hdr = get_le16(&in[ipos]);
		if (!hdr)
			break;
		csize = (hdr & LZNT1_CHUNK_SIZE_MASK) + 1;
		if (csize > (in_size - ipos - 2))
			goto corrupt;
		cp = &in[ipos + 2];
		cend = cp + csize;
		ipos += 2 + csize;
			/* A short chunk is padded with zeroes */
		if (opos % LZNT1_CHUNK_SIZE) {
			len = LZNT1_CHUNK_SIZE - (opos % LZNT1_CHUNK_SIZE);
			if (len > (out_size - opos))
				len = out_size - opos;
			memset(&out[opos], 0, len);
			opos += len;
			if (opos >= out_size)
				break;
		}
		if (!(hdr & LZNT1_CHUNK_COMPRESSED)) {
			if (csize > LZNT1_CHUNK_SIZE)
				goto corrupt;
			len = csize;
			if (len > (out_size - opos))
				len = out_size - opos;
			memcpy(&out[opos], cp, len);
			opos += len;
			continue;
		}
		cstart = opos;
		climit = cstart + LZNT1_CHUNK_SIZE;
		if (climit > out_size)
			climit = out_size;
		while ((cp < cend) && (opos < climit)) {
			tag = *cp++;
			for (i=0; (i<8) && (cp<cend) && (opos<climit);
						i++, tag >>= 1) {
				if (!(tag & 1)) {
					out[opos++] = *cp++;
					continue;
				}
				if ((cend - cp) < 2)
					goto corrupt;
				pt = get_le16(cp);
				cp += 2;
				pos = opos - cstart;
				if (!pos)
					goto corrupt;
				/*
				 * The split between displacement and length
				 * depends on the position within the chunk.
				 */
				lg = 0;
				for (j=pos-1; j>=0x10; j>>=1)
					lg++;
				disp = (pt >> (12 - lg)) + 1;
				len = (pt & (0xfff >> lg)) + 3;
				if (disp > pos)
					goto corrupt;
				if (len > (climit - opos))
					len = climit - opos;
				copy_match(out, opos, disp, len);
				opos += len;
			}
		}
	}
	return (opos);
corrupt :
	ntfs_log_error("Bad LZNT1 data at input offset 0x%lx\n", (long)ipos);
	errno = EINVAL;
	return (-1);
}

/*
 *		Decompress a plain LZ77 buffer
 *
 *	Literals and matches are selected by 32-bit flag words. Long
 *	match lengths are extended by a nibble shared by two matches,
 *	then by a byte, then by a 16-bit or 32-bit word.
 *
 *	Returns the number of bytes produced, or -1 if the data is bad
 */

s32 ntfs_xpress_decompress(const u8 *in, u32 in_size, u8 *out, u32 out_size)
{
	u32 flags;
	u32 ipos;
	u32 opos;
	u32 half;
	u32 mlen;
	u32 moff;
	u16 mbytes;
	int nflags;

	flags = 0;
	nflags = 0;
	ipos = 0;
	opos = 0;
	half = 0;	/* position of shared nibble plus one */
	while (opos < out_size) {
		if (!nflags) {
			if ((in_size - ipos) < 4)
				break;
			flags = get_le32(&in[ipos]);
			ipos += 4;
			nflags = 32;
		}
		nflags--;
		if (!(flags & ((u32)1 << nflags))) {
			if (ipos >= in_size)
				break;
			out[opos++] = in[ipos++];
			continue;
		}
		if (ipos == in_size)
			break;
		if ((in_size - ipos) < 2)
			goto corrupt;
		mbytes = get_le16(&in[ipos]);
		ipos += 2;
		mlen = mbytes & 7;
		moff = (mbytes >> 3) + 1;
		if (mlen == 7) {
			if (!half) {
				if (ipos >= in_size)
					goto corrupt;
				mlen = in[ipos] & 15;
				half = ++ipos;
			} else {
				mlen = in[half - 1] >> 4;
				half = 0;
			}
			if (mlen == 15) {
				if (ipos >= in_size)
					goto corrupt;
				mlen = in[ipos++];
				if (mlen == 255) {
					if ((in_size - ipos) < 2)
						goto corrupt;
					mlen = get_le16(&in[ipos]);
					ipos += 2;
					if (!mlen) {
						if ((in_size - ipos) < 4)
							goto corrupt;
						mlen = get_le32(&in[ipos]);
						ipos += 4;
					}
					if (mlen < (15 + 7))
						goto corrupt;
					mlen -= 15 + 7;
				}
				mlen += 15;
			}
			mlen += 7;
		}
		mlen += 3;
		if (moff > opos)
			goto corrupt;
		if (mlen > (out_size - opos))
			mlen = out_size - opos;
		copy_match(out, opos, moff, mlen);
		opos += mlen;
	}
	return (opos);
corrupt :
	ntfs_log_error("Bad XPRESS data at input offset 0x%lx\n", (long)ipos);
	errno = EINVAL;
	return (-1);
}

/*
 *		Build the decoding table for a LZ77+Huffman block
 *
 *	The block begins with the lengths of the 512 canonical Huffman
 *	codes, two 4-bit lengths per byte. The table is indexed by the
 *	next 15 bits of input and gives the decoded symbol.
 *
 *	Returns 0 if the table is valid, -1 otherwise
 */

static int xpress_huff_build(const u8 *lengths_in, u8 *lengths, u16 *table)
{
	u32 pos;
	u32 cnt;
	int sym;
	int len;

	for (sym=0; sym<XPRESS_HUFF_SYMBOLS; sym+=2) {
		lengths[sym] = lengths_in[sym >> 1] & 15;
		lengths[sym + 1] = lengths_in[sym >> 1] >> 4;
	}
	pos = 0;
	for (len=1; len<=XPRESS_HUFF_MAX_CODE_LEN; len++) {
		cnt = (u32)1 << (XPRESS_HUFF_MAX_CODE_LEN - len);
		for (sym=0; sym<XPRESS_HUFF_SYMBOLS; sym++) {
			if (lengths[sym] != len)
				continue;
			if ((pos + cnt) > ((u32)1 << XPRESS_HUFF_MAX_CODE_LEN))
				return (-1);
			while (cnt--)
				table[pos++] = sym;
			cnt = (u32)1 << (XPRESS_HUFF_MAX_CODE_LEN - len);
		}
	}
	if (!pos)
		return (-1);
		/* An incomplete code is tolerated, unused codes are invalid */
	while (pos < ((u32)1 << XPRESS_HUFF_MAX_CODE_LEN))
		table[pos++] = XPRESS_HUFF_INVALID;
	return (0);
}

/*
 *		Get the next 16 bits of a LZ77+Huffman bit stream
 *
 *	Reading beyond the end of input yields zeroes, the bit stream
 *	is prefetched and may legitimately extend beyond the input.
 */

static inline u32 xpress_huff_get16(const u8 *in, u32 in_size, u32 pos)
{
	u32 v;

	if ((pos + 2) <= in_size)
		v = get_le16(&in[pos]);
	else if ((pos + 1) == in_size)
		v = in[pos];
	else
		v = 0;
	return (v);
}

/*
 *		Decompress a LZ77+Huffman buffer
 *
 *	The data is split into blocks of 65536 output bytes, each of
 *	which begins with a new Huffman table. The bit stream is made of
 *	16-bit little-endian words, the most significant bit first.
 *	Extended match lengths are stored as bytes inserted in the stream
 *	of 16-bit words.
 *
 *	Returns the number of bytes produced, or -1 if the data is bad
 */

s32 ntfs_xpress_huff_decompress(const u8 *in, u32 in_size,
				u8 *out, u32 out_size)
{
	u8 lengths[XPRESS_HUFF_SYMBOLS];
	u16 *table;
	u32 nextbits;
	u32 ipos;
	u32 opos;
	u32 block_end;
	u32 mlen;
	u32 moff;
	int extra;
	int obits;
	int sym;

	table = (u16*)ntfs_malloc(sizeof(u16)
				<< XPRESS_HUFF_MAX_CODE_LEN);
	if (!table)
		return (-1);
	ipos = 0;
	opos = 0;
	while (opos < out_size) {
		if (((in_size - ipos) < (XPRESS_HUFF_SYMBOLS / 2))
		    || xpress_huff_build(&in[ipos], lengths, table))
			goto corrupt;
		ipos += XPRESS_HUFF_SYMBOLS / 2;
		nextbits = xpress_huff_get16(in, in_size, ipos) << 16;
		ipos += 2;
		nextbits |= xpress_huff_get16(in, in_size, ipos);
		ipos += 2;
		extra = 16;
		block_end = opos + XPRESS_HUFF_BLOCK_SIZE;
		if (block_end > out_size)
			block_end = out_size;
		while (opos < block_end) {
			/* there are always 16 bits or more available */
			sym = table[nextbits >> (32
					- XPRESS_HUFF_MAX_CODE_LEN)];
			if (sym == XPRESS_HUFF_INVALID)
				goto corrupt;
			nextbits <<= lengths[sym];
			extra -= lengths[sym];
			if (extra < 0) {
				nextbits |= xpress_huff_get16(in, in_size,
						ipos) << -extra;
				extra += 16;
				ipos += 2;
			}
			if (sym < 256) {
				out[opos++] = sym;
				continue;
			}
			sym -= 256;
			mlen = sym & 15;
			obits = sym >> 4;
			if (mlen == 15) {
				if (ipos >= in_size)
					goto corrupt;
				mlen = in[ipos++];
				if (mlen == 255) {
					if ((in_size - ipos) < 2)
						goto corrupt;
					mlen = get_le16(&in[ipos]);
					ipos += 2;
					if (!mlen) {
						if ((in_size - ipos) < 4)
							goto corrupt;
						mlen = get_le32(&in[ipos]);
						ipos += 4;
					}
					if (mlen < 15)
						goto corrupt;
					mlen -= 15;
				}
				mlen += 15;
			}
			mlen += 3;
			moff = (u32)1 << obits;
			if (obits) {
				moff += nextbits >> (32 - obits);
				nextbits <<= obits;
				extra -= obits;
				if (extra < 0) {
					nextbits |= xpress_huff_get16(in,
						in_size, ipos) << -extra;
					extra += 16;
					ipos += 2;
				}
			}
			if (moff > opos)
				goto corrupt;
			/* a match may extend beyond the end of block */
			if (mlen > (out_size - opos))
				mlen = out_size - opos;
			copy_match(out, opos, moff, mlen);
			opos += mlen;
		}
	}
	free(table);
	return (opos);
corrupt :
	free(table);
	ntfs_log_error("Bad XPRESS Huffman data at input offset 0x%lx\n",
				(long)ipos);
	errno = EINVAL;
	return (-1);
}
