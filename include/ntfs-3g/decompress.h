/*
 * decompress.h - Exported definitions for the Windows RTL decompressors
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

#ifndef _NTFS_DECOMPRESS_H
#define _NTFS_DECOMPRESS_H

#include "types.h"

/*
 * Decompressors for the formats produced by RtlCompressBuffer(),
 * as described in [MS-XCA]. They operate on memory buffers only and
 * stop when either the input is exhausted or the output buffer is full.
 *
 * They return the number of bytes written to the output buffer,
 * or -1 with errno set to EINVAL when the input is malformed.
 */

s32 ntfs_lznt1_decompress(const u8 *in, u32 in_size, u8 *out, u32 out_size);

s32 ntfs_xpress_decompress(const u8 *in, u32 in_size, u8 *out, u32 out_size);

s32 ntfs_xpress_huff_decompress(const u8 *in, u32 in_size,
				u8 *out, u32 out_size);

#endif /* _NTFS_DECOMPRESS_H */
