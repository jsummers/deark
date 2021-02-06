// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// This file is for things that need to happen before the system header files
// are #included. That includes #defines that might help us decide which system
// headers to #include.

#ifdef DEARK_CONFIG_H_INC
#error "deark-config.h included multiple times"
#endif
#define DEARK_CONFIG_H_INC

#ifdef _WIN32
#define DE_WINDOWS
#else
#define DE_UNIX
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

#define DE_USE_WINDOWS_INTTYPES

#endif

#ifdef DE_UNIX
#ifndef __INTSIZE
#define DE_USE_FSEEKO
#else
#define lstat(fn, stbuf) stat(fn, stbuf) // because of vbcc's PosixLib
#endif
#endif

// Post-system-header platform-specific things can optionally go in a
// deark-config2.h file. See deark.h.
//#define DE_USE_CONFIG2_H
