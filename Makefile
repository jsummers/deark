
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
OFILES_MODS:=$(addprefix $(OBJDIR)/modules/,fmtutil.o os2bmp.o eps.o \
 bsave.o ilbm.o \
 atari-img.o spectrum512.o tga.o sunras.o pnm.o \
 jpeg.o tiff.o psd.o misc.o msp.o pcpaint.o grasp.o amigaicon.o macpaint.o \
 pcx.o epocimage.o psionpic.o psionapp.o exe.o riff.o iff.o \
 zoo.o boxes.o zip.o atari.o mscompress.o \
 fnt.o nokia.o grob.o d64.o t64.o cardfile.o jovianvi.o \
 tivariable.o basic-c64.o ico.o rpm.o cpio.o \
 rosprite.o binhex.o icns.o awbm.o printshop.o qtif.o portfolio.o bpg.o shg.o \
 wpg.o insetpix.o ansiart.o bintext.o tim.o ar.o tar.o \
 rsc.o gemras.o gemfont.o pff2.o jbf.o psf.o pkfont.o png.o cfb.o hlp.o \
 gif.o compress.o wmf.o pict.o xfer.o gemmeta.o alphabmp.o abk.o mbk.o \
 makichan.o bmp.o iccprofile.o iptc.o gzip.o unsupported.o)
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
	cat $^ > $@

$(OBJDIR)/%.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(OBJDIR)/$*.o -MF $@ $<

endif

