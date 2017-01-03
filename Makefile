
CFLAGS:=-g -O2 -Wall -Wextra -Wmissing-prototypes -Wformat-security -Wno-unused-parameter -Isrc
LDFLAGS:=-Wall

ifeq ($(OS),Windows_NT)
EXE_EXT:=.exe
else
EXE_EXT:=
endif
DEARK_EXE:=deark$(EXE_EXT)

all: $(DEARK_EXE)

OBJDIR=obj
OFILES_MODS:=$(addprefix $(OBJDIR)/modules/,os2bmp.o eps.o bsave.o ilbm.o \
 atari-img.o tga.o sunras.o pnm.o \
 jpeg.o tiff.o psd.o misc.o msp.o pcpaint.o grasp.o amigaicon.o macpaint.o \
 pcx.o epocimage.o psionpic.o psionapp.o exe.o riff.o iff.o \
 boxes.o zip.o atari.o mscompress.o \
 fnt.o nokia.o grob.o d64.o t64.o cardfile.o jovianvi.o \
 tivariable.o basic-c64.o ico.o rpm.o cpio.o \
 rosprite.o binhex.o icns.o awbm.o printshop.o qtif.o portfolio.o bpg.o shg.o \
 insetpix.o ansiart.o bintext.o tim.o ar.o tar.o \
 rsc.o gemras.o gemfont.o pff2.o jbf.o psf.o pkfont.o png.o cfb.o hlp.o \
 gif.o compress.o wmf.o pict.o xfer.o gemmeta.o alphabmp.o abk.o mbk.o \
 makichan.o bmp.o iccprofile.o iptc.o gzip.o unsupported.o)
OFILES_MODUTILS:=$(addprefix $(OBJDIR)/modules/,fmtutil.o)
OFILES_LIB:=$(addprefix $(OBJDIR)/src/,deark-miniz.o deark-util.o deark-data.o \
 deark-dbuf.o deark-bitmap.o deark-char.o deark-font.o deark-ucstring.o \
 deark-core.o deark-modules.o deark-unix.o)
OFILES_ALL:=$(OBJDIR)/src/deark-cmd.o $(OFILES_LIB) $(OFILES_MODS) \
 $(OFILES_MODUTILS)

# Prerequisites
$(addprefix $(OBJDIR)/modules/,alphabmp.o ansiart.o atari-img.o amigaicon.o \
 bintext.o boxes.o bpg.o exe.o fmtutil.o gemras.o ico.o ilbm.o \
 jbf.o jpeg.o macpaint.o mbk.o misc.o os2bmp.o pict.o psd.o nokia.o \
 qtif.o tga.o tiff.o wmf.o bmp.o riff.o iff.o cfb.o): modules/fmtutil.h

$(OBJDIR)/src/deark-miniz.o: foreign/miniz.h
$(OBJDIR)/modules/compress.o: foreign/liblzw.h
$(OBJDIR)/src/deark-modules.o: src/deark-modules.h
$(OFILES_LIB) $(OFILES_MODS) $(OFILES_MODUTILS): src/deark-private.h
$(OFILES_ALL): src/deark-config.h src/deark.h

$(OBJDIR)/src/deark-miniz.o: CFLAGS+=-fno-strict-aliasing

$(DEARK_EXE): $(OFILES_ALL)
	$(CC) $(LDFLAGS) -o $@ $(OFILES_ALL)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJDIR)/src/*.o $(OBJDIR)/modules/*.o $(DEARK_EXE)

.PHONY: all clean

