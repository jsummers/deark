// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ar);

typedef struct localctx_struct {
	de_int64 extended_name_table_pos; // 0=none
	de_int64 extended_name_table_size;
} lctx;

static int do_ar_item(deark *c, lctx *d, de_int64 pos1, de_int64 *p_item_len)
{
	char name_orig[17];
	size_t name_orig_len;
	de_ucstring *rawname_ucstring = NULL;
	de_ucstring *filename_ucstring = NULL;
	char timestamp_buf[64];
	de_int64 mod_time;
	de_int64 file_mode;
	de_int64 file_offset;
	de_int64 file_size = 0;
	de_int64 name_offset;
	de_finfo *fi = NULL;
	de_int64 k;
	int retval = 0;
	int ret;
	de_int64 foundpos;
	de_int64 ext_name_len;

	de_dbg(c, "archive member at %d", (int)pos1);
	de_dbg_indent(c, 1);

	fi = de_finfo_create(c);

	de_read((de_byte*)name_orig, pos1, 16);
	// Strip trailing spaces
	name_orig[16] = '\0';
	for(k=15; k>=0; k--) {
		if(name_orig[k]!=' ') break;
		name_orig[k]='\0';
	}
	name_orig_len = de_strlen(name_orig);

	rawname_ucstring = ucstring_create(c);
	ucstring_append_bytes(rawname_ucstring, (const de_byte*)name_orig, name_orig_len, 0, DE_ENCODING_UTF8);

	de_dbg(c, "member raw name: \"%s\"", ucstring_getpsz(rawname_ucstring));

	(void)dbuf_read_ascii_number(c->infile, pos1+16, 12, 10, &mod_time);
	de_unix_time_to_timestamp(mod_time, &fi->mod_time);
	de_timestamp_to_string(&fi->mod_time, timestamp_buf, sizeof(timestamp_buf), 1);
	de_dbg(c, "mod time: %" INT64_FMT " (%s)", mod_time, timestamp_buf);

	(void)dbuf_read_ascii_number(c->infile, pos1+40, 8, 8, &file_mode);
	de_dbg(c, "file mode: octal(%06o)", (int)file_mode);
	if((file_mode & 0111)!=0) {
		fi->mode_flags |= DE_MODEFLAG_EXE;
	}
	else {
		fi->mode_flags |= DE_MODEFLAG_NONEXE;
	}

	file_offset = pos1 + 60;
	(void)dbuf_read_ascii_number(c->infile, pos1+48, 10, 10, &file_size);
	de_dbg(c, "member data at %d, size: %d",
		(int)file_offset, (int)file_size);

	if(name_orig_len<1) {
		de_warn(c, "Missing filename");
		retval = 1;
		goto done;
	}
	else if(!de_strcmp(name_orig, "/")) {
		de_dbg(c, "symbol table (ignoring)");
		retval = 1;
		goto done;
	}
	else if(!de_strcmp(name_orig, "//")) {
		de_dbg(c, "extended name table");
		d->extended_name_table_pos = file_offset;
		d->extended_name_table_size = file_size;
		retval = 1;
		goto done;
	}
	else if(name_orig[0]=='/' && name_orig[1]>='0' && name_orig[1]<='9') {
		if(d->extended_name_table_pos==0) {
			de_err(c, "Missing extended name table");
			goto done;
		}

		(void)dbuf_read_ascii_number(c->infile, pos1+1, 15, 10, &name_offset);
		if(name_offset >= d->extended_name_table_size) {
			goto done;
		}

		ret = dbuf_search_byte(c->infile, '\x0a', d->extended_name_table_pos+name_offset,
			d->extended_name_table_size-name_offset, &foundpos);
		if(!ret) goto done;
		ext_name_len = foundpos - (d->extended_name_table_pos+name_offset);

		// TODO: Consolidate the filename extraction code.
		if(ext_name_len>0 && de_getbyte(d->extended_name_table_pos+name_offset+ext_name_len-1)=='/') {
			// Strip trailing slash.
			ext_name_len--;
		}

		filename_ucstring = ucstring_create(c);
		dbuf_read_to_ucstring(c->infile, d->extended_name_table_pos+name_offset,
			ext_name_len, filename_ucstring, 0, DE_ENCODING_UTF8);

		de_dbg(c, "extended filename: \"%s\"", ucstring_getpsz(filename_ucstring));

		de_finfo_set_name_from_ucstring(c, fi, filename_ucstring);
		fi->original_filename_flag = 1;
	}
	else if(name_orig[0]=='/') {
		de_warn(c, "Unsupported extension: \"%s\"", ucstring_getpsz(rawname_ucstring));
		retval = 1;
		goto done;
	}
	else {
		de_int64 adjusted_len;

		filename_ucstring = ucstring_create(c);

		adjusted_len = name_orig_len;
		if(name_orig[name_orig_len-1]=='/') {
			// Filenames are often terminated with a '/', to allow for
			// trailing spaces. Strip off the '/'.
			adjusted_len--;
		}
		ucstring_append_bytes(filename_ucstring, (de_byte*)name_orig, adjusted_len,
			0, DE_ENCODING_UTF8);

		de_dbg(c, "filename: \"%s\"", ucstring_getpsz(filename_ucstring));
		de_finfo_set_name_from_ucstring(c, fi, filename_ucstring);
		fi->original_filename_flag = 1;
	}

	dbuf_create_file_from_slice(c->infile, file_offset, file_size, NULL, fi, 0);

	retval = 1;
done:
	*p_item_len = 60 + file_size;
	if(*p_item_len % 2) (*p_item_len)++; // padding byte
	de_dbg_indent(c, -1);
	de_finfo_destroy(c, fi);
	ucstring_destroy(rawname_ucstring);
	ucstring_destroy(filename_ucstring);
	return retval;
}

static void de_run_ar(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 item_len;
	int ret;

	d = de_malloc(c, sizeof(lctx));

	pos = 8;
	while(1) {
		if(pos >= c->infile->len) break;
		ret = do_ar_item(c, d, pos, &item_len);
		if(!ret || item_len<1) break;
		pos += item_len;
	}

	de_free(c, d);
}

static int de_identify_ar(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "!<arch>\x0a", 8))
		return 100;
	return 0;
}

void de_module_ar(deark *c, struct deark_module_info *mi)
{
	mi->id = "ar";
	mi->desc = "ar archive";
	mi->run_fn = de_run_ar;
	mi->identify_fn = de_identify_ar;
}
