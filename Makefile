
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
OFILES_MODS:=$(addprefix $(OBJDIR)/modules/,misc.o unsupported.o \
 psd.o tiff.o zoo.o cfb.o atari-img.o jpeg.o pict.o wmf.o \
 ilbm.o exe.o ansiart.o xface.o tga.o bmp.o pcpaint.o zip.o \
 amigaicon.o xfer.o gif.o abk.o bintext.o hlp.o iccprofile.o \
 palmpdb.o palmbitmap.o epocimage.o bsave.o emf.o \
 pcx.o pnm.o icns.o insetpix.o os2bmp.o \
 mp3.o pkfont.o rsc.o shg.o makichan.o wpg.o rosprite.o jbf.o \
 iptc.o cpio.o gemras.o boxes.o spectrum512.o tivariable.o riff.o \
 png.o psf.o grasp.o mbk.o compress.o ico.o macpaint.o fnt.o wri.o \
 tar.o nokia.o atari.o binhex.o d64.o sunras.o gzip.o gemmeta.o lha.o \
 awbm.o rpm.o qtif.o printshop.o printptnr.o mscompress.o jovianvi.o drhalo.o \
 cab.o ebml.o portfolio.o eps.o ar.o gemfont.o psionpic.o flif.o wad.o \
 autocad.o grob.o alphabmp.o bpg.o iff.o cardfile.o pff2.o \
 asf.o vort.o tim.o t64.o msp.o basic-c64.o psionapp.o)
OFILES_DEARK1:=$(addprefix $(OBJDIR)/src/,deark-miniz.o deark-util.o deark-data.o \
 deark-dbuf.o deark-bitmap.o deark-char.o deark-font.o deark-ucstring.o \
 deark-fmtutil.o deark-user.o deark-unix.o)
OFILES_DEARK2:=$(addprefix $(OBJDIR)/src/,deark-modules.o)
OFILES_ALL:=$(OFILES_DEARK1) $(OFILES_DEARK2) $(OFILES_MODS) $(OBJDIR)/src/deark-cmd.o

DEARK1_A:=$(OBJDIR)/src/deark1.a
$(DEARK1_A): $(OFILES_DEARK1)
	ar rcs $@ $^

DEARK2_A:=$(OBJDIR)/src/deark2.a
$(DEARK2_A): $(OFILES_DEARK2)
	ar rcs $@ $^

MODS_A:=$(OBJDIR)/modules/mods.a
$(MODS_A): $(OFILES_MODS)
	ar rcs $@ $^

# I'm sorry if your linker doesn't like this library order, but the link
# command was getting so long that I've decided to start using helper
# libraries. I'll consider adding "-Wl,--start-group" and "-Wl,--end-group"
# options if that would help.
$(DEARK_EXE): $(OBJDIR)/src/deark-cmd.o $(DEARK2_A) $(MODS_A) $(DEARK1_A)
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

