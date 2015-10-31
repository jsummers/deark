// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// Extract comments from ZIP files.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 end_of_central_dir_pos;
	de_int64 central_dir_num_entries;
	de_int64 central_dir_byte_size;
	de_int64 central_dir_offset;
} lctx;

// Write a buffer to a file, converting the encoding.
static void copy_cp437c_to_utf8(deark *c, const de_byte *buf, de_int64 len, dbuf *outf)
{
	de_int32 u;
	de_int64 i;

	for(i=0; i<len; i++) {
		u = de_char_to_unicode(c, (de_int32)buf[i], DE_ENCODING_CP437_C);
		dbuf_write_uchar_as_utf8(outf, u);
	}
}

static int detect_bom(dbuf *f, de_int64 pos)
{
	de_byte buf[3];

	dbuf_read(f, buf, pos, 3);
	if(buf[0]==0xef && buf[1]==0xbb && buf[2]==0xbf) {
		return 1;
	}
	return 0;
}

static void do_comment(deark *c, lctx *d, de_int64 pos, de_int64 len, int utf8_flag,
	const char *ext)
{
	de_byte *comment = NULL;
	dbuf *f = NULL;

	if(len<1) return;

	comment = de_malloc(c, len);
	de_read(comment, pos, len);

	f = dbuf_create_output_file(c, ext, NULL);

	if(de_is_ascii(comment, len)) {
		// No non-ASCII characters, so write the comment as-is.
		dbuf_write(f, comment, len);
	}
	else if(utf8_flag) {

		// Comment is already UTF-8. Copy as-is, but maybe add a BOM.

		if(c->write_bom) {
			int already_has_bom = 0;

			// A UTF-8 comment is not expected to have a BOM, but just in case it does,
			// make sure we don't add a second one.
			if(len>=3) {
				already_has_bom = detect_bom(c->infile, pos);
			}

			if(!already_has_bom) {
				dbuf_write_uchar_as_utf8(f, 0xfeff);
			}
		}

		dbuf_write(f, comment, len);
	}
	else {
		// Convert the comment to UTF-8.

		if(c->write_bom) {
			// Write a BOM.
			dbuf_write_uchar_as_utf8(f, 0xfeff);
		}

		copy_cp437c_to_utf8(c, comment, len, f);
	}

	dbuf_close(f);
	de_free(c, comment);
}

static int do_central_dir_entry(deark *c, lctx *d, de_int64 index,
	de_int64 pos, de_int64 *p_entry_size)
{
	de_int64 x;
	unsigned int bit_flags;
	de_int64 fn_len, extra_len, comment_len;
	int utf8_flag;

	*p_entry_size = 46;
	de_dbg(c, "central dir entry #%d at %d\n", (int)index, (int)pos);

	x = de_getui32le(pos);
	if(x!=0x02014b50) {
		de_err(c, "Invalid central file header at %d\n", (int)pos);
		return 0;
	}

	bit_flags = (unsigned int)de_getui16le(pos+8);
	de_dbg(c, " flags: 0x%04x\n", bit_flags);

	utf8_flag = (bit_flags & 0x800)?1:0;

	fn_len = de_getui16le(pos+28);
	extra_len = de_getui16le(pos+30);
	comment_len = de_getui16le(pos+32);

	de_dbg(c, " filename_len=%d, extra_len=%d, comment_len=%d\n", (int)fn_len,
		(int)extra_len, (int)comment_len);

	*p_entry_size += fn_len + extra_len + comment_len;

	if(comment_len>0) {
		do_comment(c, d, pos+46+fn_len+extra_len, comment_len, utf8_flag, "fcomment.txt");
	}
	return 1;
}

static int do_central_dir(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 pos;
	de_int64 entry_size;
	int retval = 0;

	pos = d->central_dir_offset;
	for(i=0; i<d->central_dir_num_entries; i++) {
		if(pos >= d->central_dir_offset+d->central_dir_byte_size) {
			goto done;
		}

		if(!do_central_dir_entry(c, d, i, pos, &entry_size)) {
			goto done;
		}

		pos += entry_size;
	}
	retval = 1;

done:
	return retval;
}

static int do_end_of_central_dir(deark *c, lctx *d)
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
		// The comment for the whole .ZIP file presumably has to use
		// cp437 encoding. There's no flag that could indicate otherwise.
		do_comment(c, d, pos+22, comment_length, 0, "comment.txt");
	}

	// TODO: Figure out exactly how to detect disk spanning.
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
	de_int64 buf_offset;
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
	// The end-of-central-directory record could theoretically appear anywhere
	// in the file. We'll follow Info-Zip/UnZip's lead and search the last 66000
	// bytes.
#define MAX_EOCD_SEARCH 66000
	buf_size = c->infile->len;
	if(buf_size > MAX_EOCD_SEARCH) buf_size = MAX_EOCD_SEARCH;

	buf = de_malloc(c, buf_size);
	buf_offset = c->infile->len - buf_size;
	de_read(buf, buf_offset, buf_size);

	for(i=buf_size-22; i>=0; i--) {
		if(buf[i]=='P' && buf[i+1]=='K' && buf[i+2]==5 && buf[i+3]==6) {
			d->end_of_central_dir_pos = buf_offset + i;
			retval = 1;
			goto done;
		}
	}

done:
	de_free(c, buf);
	return retval;
}

static void de_run_zip(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	de_declare_fmt(c, "ZIP (extract comments only)");

	if(!find_end_of_central_dir(c, d)) {
		de_err(c, "Not a ZIP file\n");
		goto done;
	}

	de_dbg(c, "End of central dir record at %d\n", (int)d->end_of_central_dir_pos);

	if(!do_end_of_central_dir(c, d)) {
		goto done;
	}

	if(!do_central_dir(c, d)) {
		goto done;
	}

done:
	de_free(c, d);
}

static int de_identify_zip(deark *c)
{
	de_byte b[4];

	// This will not detect every ZIP file, but there is no cheap way to do that.

	de_read(b, 0, 4);
	if(!de_memcmp(b, "PK\x03\x04", 4)) {
		return 90;
	}

	if(c->infile->len >= 22) {
		de_read(b, c->infile->len - 22, 4);
		if(!de_memcmp(b, "PK\x05\x06", 4)) {
			return 90;
		}
	}

	return 0;
}

void de_module_zip(deark *c, struct deark_module_info *mi)
{
	mi->id = "zip";
	mi->desc = "ZIP archive (extract comments only)";
	mi->run_fn = de_run_zip;
	mi->identify_fn = de_identify_zip;
}
