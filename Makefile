
CFLAGS:=-g -O2 -Wall -Wmissing-prototypes -Wformat-security -Isrc
LDFLAGS:=-Wall

ifeq ($(OS),Windows_NT)
DEARK_EXE:=deark.exe
else
DEARK_EXE:=deark
endif

all: $(DEARK_EXE)

OBJDIR=obj
OFILES_MODS:=$(addprefix $(OBJDIR)/modules/,os2bmp.o eps.o zlib.o bsave.o \
 jpeg.o tiff.o psd.o copy.o msp.o pcpaint.o graspgl.o amigaicon.o macpaint.o \
 epocimage.o psionpic.o psionapp.o hpicn.o exe.o ani.o jpeg2000.o unsupported.o)
OFILES_MODUTILS:=$(addprefix $(OBJDIR)/modules/,fmtutil.o)
OFILES_LIB:=$(addprefix $(OBJDIR)/src/,deark-miniz.o deark-util.o deark-data.o \
 deark-core.o deark-modules.o)
OFILES_ALL:=$(OBJDIR)/src/deark-cmd.o $(OFILES_LIB) $(OFILES_MODS) \
 $(OFILES_MODUTILS)

# Prerequisites
$(OBJDIR)/modules/fmtutil.o $(OBJDIR)/modules/exe.o \
 $(OBJDIR)/modules/jpeg.o $(OBJDIR)/modules/jpeg2000.o \
 $(OBJDIR)/modules/tiff.o $(OBJDIR)/modules/psd.o \
 $(OBJDIR)/modules/os2bmp.o: modules/fmtutil.h

$(OBJDIR)/src/deark-miniz.o: src/miniz.h
$(OFILES_MODS) $(OBJDIR)/src/deark-modules.o: src/deark-modules.h
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

