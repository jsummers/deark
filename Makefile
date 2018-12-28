
CFLAGS:=-g -O2 -Wall -Wextra -Wmissing-prototypes -Wformat-security -Wno-unused-parameter -Isrc
LDFLAGS:=-Wall

ifeq ($(OS),Windows_NT)
EXE_EXT:=.exe
else
EXE_EXT:=
endif
DEARK_EXE:=deark$(EXE_EXT)

ifeq ($(MAKECMDGOALS),dep)

# Regenerate deps.mk only when someone runs "make dep".
# (I'm aware that there are ways to do this automatically, and that one might
# have to run "make clean" before "make dep" in some cases. But only
# developers need to worry about this. Everyone else can just run "make".)
dep: deps.mk

else

all: $(DEARK_EXE)

include deps.mk

endif

.PHONY: all clean dep

OBJDIR:=obj

OFILES_MODS_AB:=$(addprefix $(OBJDIR)/modules/,abk.o alphabmp.o amigaicon.o \
 ansiart.o ar.o asf.o atari-dsk.o atari-img.o autocad.o awbm.o basic-c64.o \
 arcfs.o \
 bmff.o apple2-dsk.o applesd.o binhex.o bintext.o bmi.o bmp.o bpg.o bsave.o)
OFILES_MODS_CH:=$(addprefix $(OBJDIR)/modules/,cab.o cardfile.o cfb.o \
 cpio.o d64.o drhalo.o ebml.o emf.o epocimage.o eps.o exe.o \
 flif.o fnt.o gemfont.o gemmeta.o gemras.o gif.o grasp.o grob.o gzip.o \
 hlp.o dsstore.o flac.o)
OFILES_MODS_IO:=$(addprefix $(OBJDIR)/modules/,misc.o iccprofile.o icns.o \
 id3.o ico.o iff.o ilbm.o insetpix.o iptc.o jbf.o jovianvi.o jpeg.o lha.o \
 j2c.o ogg.o olepropset.o macbinary.o macrsrc.o \
 macpaint.o makichan.o mbk.o mp3.o mscompress.o msp.o nokia.o os2bmp.o)
OFILES_MODS_PQ:=$(addprefix $(OBJDIR)/modules/,psd.o palmbitmap.o palmpdb.o \
 pcpaint.o pcx.o pff2.o pict.o pkfont.o png.o pnm.o portfolio.o printptnr.o \
 printshop.o psf.o psionapp.o psionpic.o pcf.o plist.o qtif.o)
OFILES_MODS_RZ:=$(addprefix $(OBJDIR)/modules/,riff.o rosprite.o rpm.o \
 rsc.o shg.o spectrum512.o sunras.o t64.o tar.o tga.o tiff.o tim.o \
 tivariable.o unsupported.o vort.o wad.o wmf.o wpg.o wri.o xface.o \
 stuffit.o sis.o xfer.o zip.o zoo.o rodraw.o unifont.o)
OFILES_MODS:=$(OFILES_MODS_AB) $(OFILES_MODS_CH) $(OFILES_MODS_IO) \
 $(OFILES_MODS_PQ) $(OFILES_MODS_RZ)

OFILES_DEARK1:=$(addprefix $(OBJDIR)/src/,deark-miniz.o deark-util.o deark-data.o \
 deark-dbuf.o deark-bitmap.o deark-char.o deark-font.o deark-ucstring.o \
 deark-fmtutil.o deark-liblzw.o deark-user.o deark-unix.o)
OFILES_DEARK2:=$(addprefix $(OBJDIR)/src/,deark-modules.o)
OFILES_ALL:=$(OFILES_DEARK1) $(OFILES_DEARK2) $(OFILES_MODS) $(OBJDIR)/src/deark-cmd.o

DEARK1_A:=$(OBJDIR)/src/deark1.a
$(DEARK1_A): $(OFILES_DEARK1)
	ar rcs $@ $^

DEARK2_A:=$(OBJDIR)/src/deark2.a
$(DEARK2_A): $(OFILES_DEARK2)
	ar rcs $@ $^

ARFLAGS:=urcs
MODS_AB_A:=$(OBJDIR)/modules/mods-ab.a
MODS_CH_A:=$(OBJDIR)/modules/mods-ch.a
MODS_IO_A:=$(OBJDIR)/modules/mods-io.a
MODS_PQ_A:=$(OBJDIR)/modules/mods-pq.a
MODS_RZ_A:=$(OBJDIR)/modules/mods-rz.a
$(MODS_AB_A): $(OFILES_MODS_AB)
	ar $(ARFLAGS) $@ $^
$(MODS_CH_A): $(OFILES_MODS_CH)
	ar $(ARFLAGS) $@ $^
$(MODS_IO_A): $(OFILES_MODS_IO)
	ar $(ARFLAGS) $@ $^
$(MODS_PQ_A): $(OFILES_MODS_PQ)
	ar $(ARFLAGS) $@ $^
$(MODS_RZ_A): $(OFILES_MODS_RZ)
	ar $(ARFLAGS) $@ $^

# I'm sorry if your linker doesn't like this library order, but the link
# command was getting so long that I've decided to start using helper
# libraries. I'll consider adding "-Wl,--start-group" and "-Wl,--end-group"
# options if that would help.
$(DEARK_EXE): $(OBJDIR)/src/deark-cmd.o $(DEARK2_A) $(MODS_AB_A) \
 $(MODS_CH_A) $(MODS_IO_A) $(MODS_PQ_A) $(MODS_RZ_A) $(DEARK1_A)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJDIR)/src/*.[oad] $(OBJDIR)/modules/*.[oad] $(DEARK_EXE)

ifeq ($(MAKECMDGOALS),dep)

deps.mk: $(OFILES_ALL:.o=.d)
	cat $(sort $^) > $@

$(OBJDIR)/%.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(OBJDIR)/$*.o -MF $@ $<

endif

