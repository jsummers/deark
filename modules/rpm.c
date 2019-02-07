// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// RPM package manager

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_rpm);

#define DE_RPM_STRING_TYPE 6

#define DE_RPMTAG_NAME               1000
#define DE_RPMTAG_VERSION            1001
#define DE_RPMTAG_RELEASE            1002
#define DE_RPMTAG_PAYLOADFORMAT      1124
#define DE_RPMTAG_PAYLOADCOMPRESSOR  1125

#define DE_RPM_CMPR_UNKNOWN 0
#define DE_RPM_CMPR_GZIP    1
#define DE_RPM_CMPR_BZIP2   2
#define DE_RPM_CMPR_LZMA    3
#define DE_RPM_CMPR_XZ      4

typedef struct localctx_struct {
	u8 ver_major, ver_minor;
	int cmpr_type;

	struct de_stringreaderdata *name_srd;
	struct de_stringreaderdata *version_srd;
	struct de_stringreaderdata *release_srd;
} lctx;

static int do_lead_section(deark *c, lctx *d)
{
	int retval = 0;

	de_dbg(c, "lead section at %d", 0);
	de_dbg_indent(c, 1);

	d->ver_major = de_getbyte(4);
	d->ver_minor = de_getbyte(5);
	de_dbg(c, "RPM format version: %d.%d", (int)d->ver_major, (int)d->ver_minor);
	if(d->ver_major < 3) {
		de_err(c, "Unsupported RPM version (%d.%d)", (int)d->ver_major, (int)d->ver_minor);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void read_compression_type(deark *c, lctx *d, i64 pos)
{
	u8 buf[16];

	de_dbg(c, "compression type at %d", (int)pos);

	de_read(buf, pos, sizeof(buf));

	if(!de_memcmp(buf, "lzma\0", 5)) {
		d->cmpr_type = DE_RPM_CMPR_LZMA;
	}
	// Other valid compression types are "gzip", "bzip2", and "xz".
	// We'll autodetect most of them, but lzma is hard to detect.
}

// Note that a header *structure* is distinct from the header *section*.
// Both the signature section and the header section use a header structure.
static int do_header_structure(deark *c, lctx *d, int is_sig, i64 pos1,
	i64 *section_size)
{
	i64 pos;
	i64 indexcount;
	i64 storesize;
	u8 buf[4];
	u8 header_ver;
	i64 i;
	i64 tag_id, tag_type, tag_offset, tag_count;
	i64 data_store_pos;
	const char *hdrname;
	int retval = 0;

	hdrname = is_sig?"sig":"hdr";
	pos = pos1;
	de_dbg(c, "%s section at %d", hdrname, (int)pos1);
	de_dbg_indent(c, 1);

	de_read(buf, pos, 4);
	if(buf[0]!=0x8e || buf[1]!=0xad || buf[2]!=0xe8) {
		de_err(c, "Bad header signature at %d", (int)pos);
		goto done;
	}
	header_ver = buf[3];
	if(header_ver != 1) {
		de_err(c, "Unsupported header version");
		goto done;
	}
	pos += 8;

	indexcount = de_getu32be(pos);
	storesize = de_getu32be(pos+4);
	de_dbg(c, "%s: pos=%d indexcount=%d storesize=%d", hdrname,
		(int)pos, (int)indexcount, (int)storesize);
	pos += 8;

	if(indexcount>1000) goto done;

	data_store_pos = pos + 16*indexcount;

	de_dbg(c, "%s: tag table at %d", hdrname, (int)pos);
	de_dbg_indent(c, 1);

	for(i=0; i<indexcount; i++) {
		tag_id = de_getu32be(pos);
		tag_type = de_getu32be(pos+4);
		tag_offset = de_getu32be(pos+8);
		tag_count = de_getu32be(pos+12);

		de_dbg2(c, "tag #%d type=%d offset=%d count=%d", (int)tag_id,
			(int)tag_type, (int)tag_offset, (int)tag_count);


		if(is_sig==0 && tag_id==DE_RPMTAG_PAYLOADCOMPRESSOR && tag_type==DE_RPM_STRING_TYPE) {
			read_compression_type(c, d, data_store_pos+tag_offset);
		}
		else if(is_sig==0 && tag_id==DE_RPMTAG_NAME && tag_type==DE_RPM_STRING_TYPE) {
			if(!d->name_srd) {
				d->name_srd = dbuf_read_string(c->infile, data_store_pos+tag_offset,
					DE_DBG_MAX_STRLEN, DE_DBG_MAX_STRLEN,
					DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
				de_dbg(c, "name: \"%s\"", ucstring_getpsz(d->name_srd->str));
			}
		}
		else if(is_sig==0 && tag_id==DE_RPMTAG_VERSION && tag_type==DE_RPM_STRING_TYPE) {
			if(!d->version_srd) {
				d->version_srd = dbuf_read_string(c->infile, data_store_pos+tag_offset,
					DE_DBG_MAX_STRLEN, DE_DBG_MAX_STRLEN,
					DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
				de_dbg(c, "version: \"%s\"", ucstring_getpsz(d->version_srd->str));
			}
		}
		else if(is_sig==0 && tag_id==DE_RPMTAG_RELEASE && tag_type==DE_RPM_STRING_TYPE) {
			if(!d->release_srd) {
				d->release_srd = dbuf_read_string(c->infile, data_store_pos+tag_offset,
					DE_DBG_MAX_STRLEN, DE_DBG_MAX_STRLEN,
					DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
				de_dbg(c, "release: \"%s\"", ucstring_getpsz(d->release_srd->str));
			}
		}

		pos += 16;
	}

	de_dbg_indent(c, -1);

	pos = data_store_pos;
	de_dbg(c, "%s: data store at %d", hdrname, (int)pos);
	pos += storesize;

	*section_size = pos - pos1;
	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static void de_run_rpm(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;
	u8 buf[8];
	const char *ext;
	i64 section_size = 0;
	de_finfo *fi = NULL;
	char filename[128];

	d = de_malloc(c, sizeof(lctx));

	if(!do_lead_section(c, d)) {
		goto done;
	}

	pos = 96;

	if(!do_header_structure(c, d, 1, pos, &section_size)) {
		goto done;
	}
	pos += section_size;

	// Header structures are 8-byte aligned. The first one always starts at
	// offset 96, so we don't have to worry about it. But we need to make
	// sure the second one is aligned.
	pos = ((pos + 7)/8)*8;

	if(!do_header_structure(c, d, 0, pos, &section_size)) {
		goto done;
	}
	pos += section_size;

	de_dbg(c, "data pos: %d", (int)pos);
	if(pos > c->infile->len) goto done;

	// There is usually a tag that indicates the compression format, but we
	// primarily figure out the format by sniffing its magic number, on the
	// theory that that's more reliable.

	// TODO: I think it's also theoretically possible that it could use an archive
	// format other than cpio.

	de_read(buf, pos, 8);

	if(buf[0]==0x1f && buf[1]==0x8b) {
		ext = "cpio.gz";
	}
	else if(buf[0]==0x42 && buf[1]==0x5a && buf[2]==0x68) {
		ext = "cpio.bz2";
	}
	else if(buf[0]==0xfd && buf[1]==0x37 && buf[2]==0x7a) {
		ext = "cpio.xz";
	}
	else if(d->cmpr_type==DE_RPM_CMPR_LZMA || buf[0]==0x5d) {
		ext = "cpio.lzma";
	}
	else {
		de_warn(c, "Unidentified compression or archive format");
		ext = "cpio.bin";
	}

	if(d->name_srd && c->filenames_from_file) {
		const char *version2 = "x";
		const char *release2 = "x";

		if(d->version_srd) version2 = d->version_srd->sz;
		if(d->release_srd) release2 = d->release_srd->sz;

		fi = de_finfo_create(c);
		de_snprintf(filename, sizeof(filename), "%s-%s.%s",
			d->name_srd->sz, version2, release2);
		de_finfo_set_name_from_sz(c, fi, filename, 0, DE_ENCODING_ASCII);
	}

	dbuf_create_file_from_slice(c->infile, pos, c->infile->len - pos, ext, fi, 0);

done:
	de_finfo_destroy(c, fi);
	if(d) {
		de_destroy_stringreaderdata(c, d->name_srd);
		de_destroy_stringreaderdata(c, d->release_srd);
		de_destroy_stringreaderdata(c, d->version_srd);
		de_free(c, d);
	}
}

static int de_identify_rpm(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\xed\xab\xee\xdb", 4))
		return 100;
	return 0;
}

void de_module_rpm(deark *c, struct deark_module_info *mi)
{
	mi->id = "rpm";
	mi->desc = "RPM Package Manager";
	mi->run_fn = de_run_rpm;
	mi->identify_fn = de_identify_rpm;
}
