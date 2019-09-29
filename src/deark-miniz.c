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

#include "deark-fmtutil.h"

#include "fmtutil-miniz-src.h"
