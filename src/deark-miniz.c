// This file is part of Deark.
// Copyright (C) 2016-2019 Jason Summers
// See the file COPYING for terms of use.

// This file is a kludge, to compile together the code that requires miniz.h.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"

#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_STDIO
#define MINIZ_NO_ARCHIVE_APIS
#include "../foreign/miniz.h"

#include "deark-zip-src.h"

// For a one-shot CRC calculations, or the first part of a multi-part
// calculation.
// buf can be NULL (in which case buf_len should be 0, but is ignored)
u32 de_crc32(const void *buf, i64 buf_len)
{
	return (u32)mz_crc32(MZ_CRC32_INIT, (const mz_uint8*)buf, (size_t)buf_len);
}

u32 de_crc32_continue(u32 prev_crc, const void *buf, i64 buf_len)
{
	return (u32)mz_crc32(prev_crc, (const mz_uint8*)buf, (size_t)buf_len);
}

#include "deark-fmtutil.h"

#include "deark-png-src.h"

#include "fmtutil-miniz-src.h"
