// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Generic RIFF format
// Windows animated cursor format

#include <deark-config.h>
#include <deark-modules.h>

#define CODE_ACON  0x41434f4eU
#define CHUNK_LIST 0x4c495354U
#define CHUNK_RIFF 0x52494646U
#define CHUNK_RIFX 0x52494658U
#define CHUNK_icon 0x69636f6eU

typedef struct localctx_struct {
	de_uint32 riff_type;
	int level;
	int is_le;
	int char_codes_are_reversed;
} lctx;

static void extract_ani_frame(deark *c, lctx *d, de_int64 pos, de_int64 len)
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

static void reverse_fourcc(de_byte *buf)
{
	de_byte tmpc;
	tmpc=buf[0]; buf[0]=buf[3]; buf[3]=tmpc;
	tmpc=buf[1]; buf[1]=buf[2]; buf[2]=tmpc;
}

static void read_riff_fourcc(deark *c, lctx *d, de_int64 pos, de_byte *buf)
{
	de_read(buf, pos, 4);
	if(d->char_codes_are_reversed) {
		reverse_fourcc(buf);
	}
}

static void process_riff_sequence(deark *c, lctx *d, de_int64 pos, de_int64 len1)
{
	de_int64 chunk_pos;
	de_int64 chunk_data_pos;
	de_int64 chunk_data_len;
	de_int64 endpos;
	de_byte chunk_id_buf[4];
	de_uint32 chunk_id;
	char chunk_id_printable[16];
	de_byte list_id_buf[4];
	de_uint32 list_id;
	char list_id_printable[16];

	if(d->level >= 16) { // An arbitrary recursion limit
		return;
	}

	endpos = pos+len1;

	while(pos < endpos) {
		chunk_pos = pos;
		read_riff_fourcc(c, d, pos, chunk_id_buf);
		pos+=4;
		chunk_id = (de_uint32)de_getui32be_direct(chunk_id_buf);
		chunk_data_len = dbuf_getui32x(c->infile, pos, d->is_le);
		pos+=4;
		chunk_data_pos = pos;

		de_make_printable_ascii(chunk_id_buf, 4, chunk_id_printable, sizeof(chunk_id_printable), 0);
		de_dbg(c, "chunk '%s' at %d, dlen=%d\n", chunk_id_printable, (int)chunk_pos, (int)chunk_data_len);

		if(chunk_data_pos + chunk_data_len > endpos) {
			if(chunk_id==CHUNK_RIFF && chunk_pos==0 && chunk_data_len==endpos) {
				// This apparent error, in which the RIFF chunk's length field gives the
				// length of the entire file, is too common (particularly in .ani files)
				// to warn about.
				;
			}
			else if(chunk_data_pos+chunk_data_len > c->infile->len) {
				de_warn(c, "Chunk '%s' at offset %d goes beyond end of file.\n", chunk_id_printable,
					(int)chunk_pos);
			}
			else {
				de_warn(c, "Chunk '%s' at offset %d exceeds its bounds.\n", chunk_id_printable,
					(int)chunk_pos);
			}

			chunk_data_len = endpos - chunk_data_pos; // Fixup bad chunk length
			de_dbg(c, "adjusting chunk data len to %d\n", (int)chunk_data_len);
		}

		de_dbg_indent(c, 1);
		if(d->riff_type==CODE_ACON && chunk_id==CHUNK_icon) {
			extract_ani_frame(c, d, pos, chunk_data_len);
		}
		else if(chunk_id==CHUNK_RIFF || chunk_id==CHUNK_RIFX || chunk_id==CHUNK_LIST)
		{
			read_riff_fourcc(c, d, pos, list_id_buf);
			list_id = (de_uint32)de_getui32be_direct(list_id_buf);
			if(d->level==0) {
				d->riff_type = list_id; // Remember the file type for later
			}
			de_make_printable_ascii(list_id_buf, 4, list_id_printable, sizeof(list_id_printable), 0);
			de_dbg(c, "%s type: '%s'\n", chunk_id_printable, list_id_printable);

			d->level++;
			process_riff_sequence(c, d, pos+4, chunk_data_len-4);
			d->level--;
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
