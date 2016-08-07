// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#if defined(_WIN32) && !defined(__GNUC__)
#define DE_WINDOWS
#endif

#ifdef DE_WINDOWS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // 0x0501=WinXP, 0x0600=Vista
#endif
#endif
