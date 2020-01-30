// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#if defined(_WIN32)
#define DE_WINDOWS
#else
#define DE_UNIX
#define DE_USE_FSEEKO
#endif

#ifdef DE_WINDOWS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // 0x0501=WinXP, 0x0600=Vista
#endif

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#endif

#ifdef __GNUC__
#define de_gnuc_attribute __attribute__
#else
#define de_gnuc_attribute(x)
#endif
