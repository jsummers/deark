// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

// Decode IFF/ILBM and related image formats

typedef struct localctx_struct {
	int level;

	de_uint32 formtype;
} lctx;

#define CODE_FORM  0x464f524d
#define CODE_BODY  0x424f4459
#define CODE_CMAP  0x434d4150
#define CODE_BMHD  0x424d4844

#define CODE_ILBM  0x494c424d
#define CODE_PBM   0x50424d20 

// Caller supplies buf[]
static void make_printable_code(de_uint32 code, char *buf, size_t buf_size)
{
	de_byte s1[4];
	s1[0] = (de_byte)((code & 0xff000000U)>>24);
	s1[1] = (de_byte)((code & 0x00ff0000U)>>16);
	s1[2] = (de_byte)((code & 0x0000ff00U)>>8);
	s1[3] = (de_byte)(code & 0x000000ffU);
	de_make_printable_ascii(s1, 4, buf, buf_size, 0);
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len);

static int do_chunk(deark *c, lctx *d, de_int64 pos, de_int64 bytes_avail,
	de_int64 *bytes_consumed)
{
	de_uint32 ct;
	char printable_code[8];
	int errflag = 0;
	int doneflag = 0;
	int ret;

	de_int64 chunk_len;

	if(bytes_avail<8) {
		de_err(c, "Invalid chunk size (at %d, size=%d)\n", (int)pos, (int)bytes_avail);
		errflag = 1;
		goto done;
	}
	ct = (de_uint32)de_getui32be(pos);
	chunk_len = de_getui32be(pos+4);
	make_printable_code(ct, printable_code, sizeof(printable_code));
	de_dbg(c, "Chunk '%s' at %d, size %d\n", printable_code, (int)pos, (int)chunk_len);

	if(chunk_len > bytes_avail-8) {
		de_err(c, "Invalid chunk size ('%s' at %d, size=%d)\n",
			printable_code, (int)pos, (int)chunk_len);
		errflag = 1;
		goto done;
	}

	if(ct==CODE_BODY) {
		// A lot of ILBM files have padding or garbage data at the end of the file
		// (apparently included in the file size given by the FORM chunk).
		// To avoid it, don't read past the BODY chunk.
		doneflag = 1;
	}
	else if(ct==CODE_FORM) {
		de_dbg_indent(c, 1);
		d->level++;

		// First 4 bytes of payload are the FORM type ID (usually "ILBM").
		d->formtype = (de_uint32)de_getui32be(pos+8);
		make_printable_code(d->formtype, printable_code, sizeof(printable_code));
		de_dbg(c, "FORM type: '%s'\n", printable_code);

		// The rest is a sequence of chunks.
		ret = do_chunk_sequence(c, d, pos+12, bytes_avail-12);
		d->level--;
		de_dbg_indent(c, -1);
		if(!ret) {
			errflag = 1;
			goto done;
		}
	}

	*bytes_consumed = 8 + chunk_len;

done:
	return (errflag || doneflag) ? 0 : 1;
}

static int do_chunk_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	de_int64 pos;
	de_int64 endpos;
	de_int64 chunk_len;
	int ret;

	if(d->level >= 10) { // An arbitrary recursion limit.
		return 0;
	}

	endpos = pos1+len;
	
	pos = pos1;
	while(pos < endpos) {
		ret = do_chunk(c, d, pos, endpos-pos, &chunk_len);
		if(!ret) return 0;
		pos += chunk_len;
	}

	return 1;
}

static void de_run_ilbm(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In ilbm module\n");

	d = de_malloc(c, sizeof(lctx));
	do_chunk_sequence(c, d, 0, c->infile->len);
	de_free(c, d);

	de_err(c, "IFF/ILBM support is not implemented\n");
}
 
static int de_identify_ilbm(deark *c)
{
	de_byte buf[12];
	de_read(buf, 0, 12);

	if(!de_memcmp(buf, "FORM", 4)) {
		if(!de_memcmp(&buf[8], "ILBM", 4)) return 100;
		if(!de_memcmp(&buf[8], "PBM ", 4)) return 100;
	}
	return 0;
}

void de_module_ilbm(deark *c, struct deark_module_info *mi)
{
	mi->id = "ilbm";
	mi->run_fn = de_run_ilbm;
	mi->identify_fn = de_identify_ilbm;
}
