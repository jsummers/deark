// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 end_of_central_dir_pos;
	de_int64 central_dir_num_entries;
	de_int64 central_dir_byte_size;
	de_int64 central_dir_offset;
} lctx;

static void write_uchar_as_utf8(dbuf *outf, int u)
{
	de_byte utf8buf[4];
	de_int64 utf8len;

	de_uchar_to_utf8(u, utf8buf, &utf8len);
	dbuf_write(outf, utf8buf, utf8len);
}

static void copy_cp437_to_utf8(deark *c, dbuf *inf, de_int64 pos, de_int64 len, dbuf *outf)
{
	de_byte b;
	int u;
	de_int64 i;

	// Write a BOM.
	write_uchar_as_utf8(outf, 0xfeff);

	for(i=0; i<len; i++) {
		b = de_getbyte(pos+i);
		u = de_cp437c_to_unicode(c, b);
		write_uchar_as_utf8(outf, u);
	}
}

static void read_comment(deark *c, lctx *d, de_int64 pos, de_int64 len)
{
	dbuf *f = NULL;
	if(len<1) return;

	// TODO: Detect if the comment contains non-ASCII characters,
	// and use a different codepath if it does not.

	f = dbuf_create_output_file(c, "comment.txt", NULL);

	// TODO: Not all ZIP file comments use cp437.
	// There is a way to use UTF-8, I think.

	copy_cp437_to_utf8(c, c->infile, pos, len, f);
	dbuf_close(f);
}

static int read_end_of_central_dir(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 this_disk_num;
	de_int64 num_entries_this_disk;
	de_int64 disk_num_with_central_dir_start;
	de_int64 comment_length;

	pos = d->end_of_central_dir_pos;

	this_disk_num = de_getui16le(pos+4);
	disk_num_with_central_dir_start = de_getui16le(pos+6);
	num_entries_this_disk = de_getui16le(pos+8);
	d->central_dir_num_entries = de_getui16le(pos+10);
	d->central_dir_byte_size  = de_getui32le(pos+12);
	d->central_dir_offset = de_getui32le(pos+16);

	de_dbg(c, "central dir: num_entries=%d, offset=%d, size=%d\n",
		(int)d->central_dir_num_entries,
		(int)d->central_dir_offset,
		(int)d->central_dir_byte_size);

	comment_length = de_getui16le(pos+20);
	if(comment_length>0) {
		de_dbg(c, "comment length: %d\n", (int)comment_length);
		read_comment(c, d, pos+22, comment_length);
	}

	if(this_disk_num!=0 || disk_num_with_central_dir_start!=0 ||
		num_entries_this_disk!=d->central_dir_num_entries)
	{
		de_err(c, "Disk spanning not supported\n");
		return 0;
	}

	return 1;
}

static int find_end_of_central_dir(deark *c, lctx *d)
{
	de_int64 x;
	de_byte *buf = NULL;
	int retval = 0;
	de_int64 buf_size;
	de_int64 i;

	if(c->infile->len < 22) goto done;

	// End-of-central-dir record usually starts 22 bytes from EOF. Try that first.
	x = de_getui32le(c->infile->len - 22);
	if(x == 0x06054b50) {
		d->end_of_central_dir_pos = c->infile->len - 22;
		retval = 1;
		goto done;
	}

	// Search for the signature.
	buf_size = c->infile->len;
	if(buf_size > 65536) buf_size = 65536;

	buf = de_malloc(c, buf_size);
	de_read(buf, c->infile->len - buf_size, buf_size);

	for(i=buf_size-22; i>=0; i--) {
		if(buf[i]=='P' && buf[i+1]=='K' && buf[i+2]==5 && buf[i+3]==6) {
			d->end_of_central_dir_pos = i;
			retval = 1;
			goto done;
		}
	}

done:
	de_free(c, buf);
	return retval;
}

static void de_run_zip(deark *c, const char *params)
{
	lctx *d = NULL;

	de_dbg(c, "In zip module\n");

	d = de_malloc(c, sizeof(lctx));

	if(!find_end_of_central_dir(c, d)) {
		de_err(c, "Not a ZIP file\n");
		goto done;
	}

	de_dbg(c, "End of central dir record at %d\n", (int)d->end_of_central_dir_pos);

	if(!read_end_of_central_dir(c, d)) {
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_zip(deark *c)
{
	return 0;
}

void de_module_zip(deark *c, struct deark_module_info *mi)
{
	mi->id = "zip";
	mi->run_fn = de_run_zip;
	mi->identify_fn = de_identify_zip;
}
