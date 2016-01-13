// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Generic RIFF format
// Windows animated cursor format

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	int is_le;
	int char_codes_are_reversed;
} lctx;

static void extract_frame(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	de_byte buf[4];
	const char *ext;

	de_dbg(c, "frame at %d, len=%d\n", (int)pos, (int)len);

	de_read(buf, pos, 4);

	// Try to identify the format of this frame.
	if(!de_memcmp(buf, "\x00\x00\x01\x00", 4)) {
		ext = "ico";
	}
	else if(!de_memcmp(buf, "\x00\x00\x02\x00", 4)) {
		ext = "cur";
	}
	else {
		ext = "bin";
	}

	// TODO: Most embedded CUR files don't seem to have a meaningful "hotspot"
	// set. Can we patch that up? Maybe we should even convert ICO files to CUR
	// files, so that we can give them a hotspot.

	dbuf_create_file_from_slice(c->infile, pos, len, ext, NULL);
}

#define CHUNK_LIST 0x4c495354U
#define CHUNK_RIFF 0x52494646U
#define CHUNK_RIFX 0x52494658U
#define CHUNK_icon 0x69636f6eU

static void process_riff_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len1)
{
	de_int64 chunk_pos;
	de_int64 chunk_data_len;
	de_int64 endpos;
	de_byte chunk_id_buf[4];
	de_uint32 chunk_id;
	char chunk_id_printable[16];
	de_byte list_id_buf[4];
	char list_id_printable[16];

	endpos = pos+len1;
	if(endpos > c->infile->len) {
		// Don't read past the end of file.

		// There seems to be some confusion about whether the "length" field
		// of the main RIFF chunk represents the full length of the file, or
		// the length of the data inside the RIFF chunk. Logically it should
		// be the latter, but the documentation is inconsistent, and we've seen
		// both types of files.

		// We'll assume it should be the length of the data inside the RIFF
		// chunk, and correct "errors" here.
		endpos = c->infile->len;
	}

	while(pos < endpos) {
		chunk_pos = pos;
		de_read(chunk_id_buf, chunk_pos, 4);
		if(d->char_codes_are_reversed) {
			de_byte tmpc;
			tmpc=chunk_id_buf[0]; chunk_id_buf[0]=chunk_id_buf[3]; chunk_id_buf[3]=tmpc;
			tmpc=chunk_id_buf[1]; chunk_id_buf[1]=chunk_id_buf[2]; chunk_id_buf[2]=tmpc;
		}
		pos+=4;
		chunk_id = (de_uint32)de_getui32be_direct(chunk_id_buf);
		chunk_data_len = dbuf_getui32x(c->infile, pos, d->is_le);
		pos+=4;

		de_make_printable_ascii(chunk_id_buf, 4, chunk_id_printable, sizeof(chunk_id_printable), 0);
		de_dbg(c, "chunk '%s' at %d, dlen=%d\n", chunk_id_printable, (int)chunk_pos, (int)chunk_data_len);

		de_dbg_indent(c, 1);
		if(chunk_id==CHUNK_icon) {
			extract_frame(c, d, pos, chunk_data_len);
		}
		else if(chunk_id==CHUNK_RIFF || chunk_id==CHUNK_RIFX || chunk_id==CHUNK_LIST)
		{
			de_read(list_id_buf, pos, 4);
			de_make_printable_ascii(list_id_buf, 4, list_id_printable, sizeof(list_id_printable), 0);
			de_dbg(c, "%s type: '%s'\n", chunk_id_printable, list_id_printable);

			process_riff_sequence(c, d, pos+4, chunk_data_len-4);
		}
		de_dbg_indent(c, -1);

		pos += chunk_data_len;
		if(chunk_data_len%2) pos++; // Padding byte
	}
}

static void de_run_riff(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_byte buf[4];

	d = de_malloc(c, sizeof(lctx));

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "RIFF", 4)) {
		d->is_le = 1;
		d->char_codes_are_reversed = 0;
	}
	else if(!de_memcmp(buf, "RIFX", 4)) {
		d->is_le = 0;
		d->char_codes_are_reversed = 0;
	}
	else if(!de_memcmp(buf, "XFIR", 4)) {
		d->is_le = 1;
		d->char_codes_are_reversed = 1;
	}
	else {
		de_warn(c, "This is probably not a RIFF file.\n");
		d->is_le = 1;
		d->char_codes_are_reversed = 0;
	}

	process_riff_sequence(c, d, 0, c->infile->len);

	de_free(c, d);
}

static int de_identify_ani(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "RIFF", 4) && !de_memcmp(&buf[8], "ACON", 4))
		return 100;
	return 0;
}

void de_module_ani(deark *c, struct deark_module_info *mi)
{
	mi->id = "ani";
	mi->desc = "Windows animated cursor";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_ani;
}

static int de_identify_riff(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "RIFF", 4))
		return 50;
	if(!dbuf_memcmp(c->infile, 0, "XFIR", 4))
		return 50;
	if(!dbuf_memcmp(c->infile, 0, "RIFX", 4))
		return 50;
	return 0;
}

void de_module_riff(deark *c, struct deark_module_info *mi)
{
	mi->id = "riff";
	mi->desc = "RIFF metaformat";
	mi->run_fn = de_run_riff;
	mi->identify_fn = de_identify_riff;
}
