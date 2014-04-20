// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#if defined(_WIN32) && !defined(__GNUC__)
#define DE_WINDOWS
#endif

#ifdef DE_WINDOWS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // 0x0501=WinXP, 0x0600=Vista
#endif
#endif

