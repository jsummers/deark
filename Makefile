
-include local1.mk

CFLAGS ?= -std=c99 -g -O2 -Wall -Wextra -Wmissing-prototypes -Wformat-security -Wno-unused-parameter
LDFLAGS ?= -Wall

ifdef DEARK_OBJDIR
OBJDIR:=$(DEARK_OBJDIR)
else
OBJDIR:=obj
endif
ifdef DEARK_WINDRES
ifndef DEARK_RC
DEARK_RC:=src/deark.rc
endif
DEARK_RC_O:=$(OBJDIR)/src/deark-rc.o
else
DEARK_RC_O:=
endif
ifdef DEARK_ARFLAGS
ARFLAGS:=$(DEARK_ARFLAGS)
else
ARFLAGS:=urcs
endif

INCLUDES:=-Isrc

ifeq ($(OS),Windows_NT)
EXE_EXT:=.exe
else
EXE_EXT:=
endif
DEARK_EXE_BASENAME:=deark$(EXE_EXT)
DEARK_EXE:=$(DEARK_EXE_BASENAME)

DEARK_MAN:=deark.1
DEPS_MK:=deps.mk

ifneq ($(OBJDIR),obj)
DEARK_EXE:=$(OBJDIR)/$(DEARK_EXE_BASENAME)
DEARK_MAN:=$(OBJDIR)/$(DEARK_MAN)
DEPS_MK:=$(OBJDIR)/$(DEPS_MK)
endif

-include local2.mk

ifeq ($(MAKECMDGOALS),dep)

# Regenerate deps.mk only when someone runs "make dep".
# (I'm aware that there are ways to do this automatically, and that one might
# have to run "make clean" before "make dep" in some cases. But only
# developers need to worry about this. Everyone else can just run "make".)
dep: $(DEPS_MK)

else

all: $(DEARK_EXE)

include $(DEPS_MK)

endif

.PHONY: all clean dep install

OFILES_MODS_AB:=$(addprefix $(OBJDIR)/modules/,abk.o alphabmp.o amigaicon.o \
 ansiart.o ar.o asf.o atari-dsk.o atari-img.o autocad.o awbm.o basic-c64.o \
 arcfs.o apm.o afcp.o arc.o amiga-dsk.o binscii.o \
 bmff.o apple2-dsk.o applesd.o binhex.o bintext.o bmi.o bmp.o \
 arj.o bpg.o bsave.o aldus.o adex.o)
OFILES_MODS_CH:=$(addprefix $(OBJDIR)/modules/,cab.o cardfile.o cfb.o \
 cpio.o d64.o drhalo.o ebml.o emf.o epocimage.o eps.o exe.o \
 exepack.o dms.o colorix.o diet.o divgs.o dosbackup.o \
 flif.o fnt.o gemfont.o gemmeta.o gemras.o gif.o grasp.o grob.o gzip.o \
 corel.o hfs.o hlp.o dsstore.o fli.o fat.o flac.o dlmaker.o crush.o \
 cdiimage.o clp.o comicchat.o dskexp.o exectext.o grabber.o gws.o)
OFILES_MODS_IO:=$(addprefix $(OBJDIR)/modules/,misc.o misc2.o misc3.o \
 misc-font.o iccprofile.o icns.o \
 id3.o ico.o iff.o ilbm.o insetpix.o iptc.o jbf.o jovianvi.o jpeg.o lha.o \
 j2c.o ogg.o olepropset.o iso9660.o macbinary.o macrsrc.o lzexe.o nufx.o \
 macpaint.o makichan.o mbk.o mmm.o mp3.o mscompress.o mac-arch.o \
 mahjong.o msp.o mmfw.o nokia.o os2bmp.o ole1.o os2pack.o \
 officeart.o lbr.o megapaint.o nie.o installshld.o os2ea.o os2bootlogo.o)
OFILES_MODS_PQ:=$(addprefix $(OBJDIR)/modules/,psd.o palmbitmap.o palmpdb.o \
 pcpaint.o pcx.o pff2.o pict.o pkfont.o png.o pnm.o portfolio.o printptnr.o \
 packdir.o pack.o packit.o pkm.o pklite.o pif.o \
 printshop.o psf.o psionapp.o psionpic.o pcf.o plist.o qtif.o)
OFILES_MODS_RZ:=$(addprefix $(OBJDIR)/modules/,riff.o rosprite.o rpm.o \
 rsc.o shg.o spectrum512.o sunras.o t64.o tar.o tga.o tiff.o tim.o \
 tivariable.o unsupported.o vort.o wad.o wmf.o wpg.o wri.o xface.o \
 stuffit.o sis.o sauce.o xfer.o zip.o zoo.o rar.o rodraw.o unifont.o rm.o \
 reko.o sgiimage.o storyboard.o xwd.o)
OFILES_MODS:=$(OFILES_MODS_AB) $(OFILES_MODS_CH) $(OFILES_MODS_IO) \
 $(OFILES_MODS_PQ) $(OFILES_MODS_RZ)

OFILES_DEARK1:=$(addprefix $(OBJDIR)/src/,fmtutil-miniz.o deark-util.o \
 deark-util2.o deark-data.o deark-zip.o deark-tar.o deark-png.o \
 deark-dbuf.o deark-bitmap.o deark-char.o deark-font.o deark-ucstring.o \
 fmtutil.o fmtutil-cmpr.o fmtutil-advfile.o fmtutil-arch.o fmtutil-zip.o \
 fmtutil-fax.o fmtutil-lzh.o fmtutil-lzw.o fmtutil-huffman.o \
 fmtutil-exe.o fmtutil-lzah.o fmtutil-rle.o fmtutil-iff.o \
 deark-user.o deark-unix.o deark-win.o)
OFILES_DEARK2:=$(addprefix $(OBJDIR)/src/,deark-modules.o)
OFILES_ALL:=$(OFILES_DEARK1) $(OFILES_DEARK2) $(OFILES_MODS) $(OBJDIR)/src/deark-cmd.o $(DEARK_RC_O)

DEARK1_A:=$(OBJDIR)/src/deark1.a
$(DEARK1_A): $(OFILES_DEARK1)
	$(AR) $(ARFLAGS) $@ $^

DEARK2_A:=$(OBJDIR)/src/deark2.a
$(DEARK2_A): $(OFILES_DEARK2)
	$(AR) $(ARFLAGS) $@ $^

MODS_AB_A:=$(OBJDIR)/modules/mods-ab.a
MODS_CH_A:=$(OBJDIR)/modules/mods-ch.a
MODS_IO_A:=$(OBJDIR)/modules/mods-io.a
MODS_PQ_A:=$(OBJDIR)/modules/mods-pq.a
MODS_RZ_A:=$(OBJDIR)/modules/mods-rz.a
$(MODS_AB_A): $(OFILES_MODS_AB)
	$(AR) $(ARFLAGS) $@ $^
$(MODS_CH_A): $(OFILES_MODS_CH)
	$(AR) $(ARFLAGS) $@ $^
$(MODS_IO_A): $(OFILES_MODS_IO)
	$(AR) $(ARFLAGS) $@ $^
$(MODS_PQ_A): $(OFILES_MODS_PQ)
	$(AR) $(ARFLAGS) $@ $^
$(MODS_RZ_A): $(OFILES_MODS_RZ)
	$(AR) $(ARFLAGS) $@ $^

# I'm sorry if your linker doesn't like this library order, but the link
# command was getting so long that I've decided to start using helper
# libraries. I'll consider adding "-Wl,--start-group" and "-Wl,--end-group"
# options if that would help.
$(DEARK_EXE): $(OBJDIR)/src/deark-cmd.o $(DEARK_RC_O) $(DEARK2_A) $(MODS_AB_A) \
 $(MODS_CH_A) $(MODS_IO_A) $(MODS_PQ_A) $(MODS_RZ_A) $(DEARK1_A)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

ifdef DEARK_WINDRES
$(DEARK_RC_O): $(DEARK_RC) src/deark.ico
	$(DEARK_WINDRES) $< $@
$(DEARK_RC_O:.o=.d):
	> $@
endif

DEARK_INSTALLDIR ?= /usr/local/bin
INSTALL_TARGET:=$(DEARK_INSTALLDIR)/$(DEARK_EXE_BASENAME)
install: $(INSTALL_TARGET)
$(INSTALL_TARGET): $(DEARK_EXE)
	install -s $(DEARK_EXE) $(DEARK_INSTALLDIR)

# Quick & dirty man page generation. (experimental/temporary)
# Note that this assumes DEARK_EXE does not have an absolute path.
.PHONY: man install-man
man: $(DEARK_MAN)
$(DEARK_MAN): $(DEARK_EXE)
	help2man -n "extract data from various file formats" -o $@ -N ./$(DEARK_EXE)
install-man: $(DEARK_MAN)
	install $(DEARK_MAN) /usr/share/man/man1

clean:
	rm -f $(OBJDIR)/src/*.[oad] $(OBJDIR)/modules/*.[oad] $(DEARK_MAN) $(DEARK_EXE)

ifeq ($(MAKECMDGOALS),dep)

$(DEPS_MK): $(OFILES_ALL:.o=.d)
	cat $(sort $^) > $@

$(OBJDIR)/%.d: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -MM -MT '$$(OBJDIR)/$*.o' -MF $@ $<

endif

