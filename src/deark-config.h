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

#if !defined(DE_WINDOWS) && !defined(DE_UNIX)
#ifdef _WIN32
#define DE_WINDOWS
#else
#define DE_UNIX
#endif
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

#ifndef DE_USE_WINDOWS_INTTYPES
#define DE_USE_WINDOWS_INTTYPES 1
#endif

#endif

#ifdef DE_UNIX

#if defined(__amigaos4__) || defined(AMIGA)
#ifndef DE_BUILDFLAG_AMIGA
#define DE_BUILDFLAG_AMIGA 1
#endif
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#define _TIME_BITS 64
#endif

#ifndef DE_USE_FSEEKO
#define DE_USE_FSEEKO 1
#endif

#ifndef DE_USE_LSTAT
#define DE_USE_LSTAT 1
#endif

#ifndef DE_USE_WINDOWS_INTTYPES
#define DE_USE_WINDOWS_INTTYPES 0
#endif

#endif

// Post-system-header platform-specific things can optionally go in a
// deark-config2.h file. See deark.h.
//#define DE_USE_CONFIG2_H
