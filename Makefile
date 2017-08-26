
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
OFILES_MODS:=$(addprefix $(OBJDIR)/modules/,fmtutil.o misc.o unsupported.o \
 psd.o tiff.o zoo.o cfb.o atari-img.o jpeg.o pict.o wmf.o \
 ilbm.o exe.o ansiart.o xface.o tga.o bmp.o pcpaint.o zip.o \
 amigaicon.o xfer.o gif.o abk.o bintext.o hlp.o iccprofile.o \
 epocimage.o bsave.o pcx.o pnm.o icns.o insetpix.o os2bmp.o \
 pkfont.o rsc.o shg.o makichan.o wpg.o rosprite.o jbf.o \
 iptc.o cpio.o gemras.o boxes.o spectrum512.o tivariable.o riff.o \
 png.o psf.o grasp.o mbk.o compress.o ico.o macpaint.o fnt.o \
 tar.o nokia.o atari.o binhex.o d64.o sunras.o gzip.o gemmeta.o lha.o \
 awbm.o rpm.o qtif.o printshop.o mscompress.o jovianvi.o \
 portfolio.o eps.o ar.o gemfont.o psionpic.o flif.o wad.o \
 grob.o alphabmp.o bpg.o iff.o cardfile.o pff2.o \
 tim.o t64.o msp.o basic-c64.o psionapp.o)
OFILES_LIB:=$(addprefix $(OBJDIR)/src/,deark-miniz.o deark-util.o deark-data.o \
 deark-dbuf.o deark-bitmap.o deark-char.o deark-font.o deark-ucstring.o \
 deark-core.o deark-modules.o deark-unix.o)
OFILES_ALL:=$(OBJDIR)/src/deark-cmd.o $(OFILES_LIB) $(OFILES_MODS)

$(DEARK_EXE): $(OFILES_ALL)
	$(CC) $(LDFLAGS) -o $@ $(OFILES_ALL)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJDIR)/src/*.[od] $(OBJDIR)/modules/*.[od] $(DEARK_EXE)

ifeq ($(MAKECMDGOALS),dep)

deps.mk: $(OFILES_ALL:.o=.d)
	cat $(sort $^) > $@

$(OBJDIR)/%.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(OBJDIR)/$*.o -MF $@ $<

endif

