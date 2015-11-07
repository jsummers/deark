// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 extended_name_table_pos; // 0=none
	de_int64 extended_name_table_size;
} lctx;

static de_int64 read_decimal(deark *c, de_int64 pos, de_int64 len)
{
	de_byte b;
	de_int64 k;
	de_int64 val = 0;

	for(k=0; k<len; k++) {
		b = de_getbyte(pos+k);
		if(b<'0' || b>'9') break;
		val = 10*val + (b-'0');
	}
	return val;
}

static int do_ar_item(deark *c, lctx *d, de_int64 pos1, de_int64 *p_item_len)
{
	char name_orig[17];
	size_t name_orig_len;
	char name_printable[32];
	de_int64 mod_time;
	de_int64 file_offset;
	de_int64 file_size = 0;
	de_int64 name_offset;
	de_finfo *fi = NULL;
	de_int64 k;
	int retval = 0;
	int ret;
	de_int64 foundpos;
	de_int64 ext_name_len;

	de_dbg(c, "archive member at %d\n", (int)pos1);
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

	de_make_printable_ascii((de_byte*)name_orig, 16,
		name_printable, sizeof(name_printable), DE_CONVFLAG_STOP_AT_NUL);
	de_dbg(c, "member raw name: \"%s\"\n", name_printable);

	mod_time = read_decimal(c, pos1+16, 12);
	de_dbg(c, "mod time: %" INT64_FMT "\n", mod_time);
	fi->mod_time_valid = 1;
	fi->mod_time = mod_time;

	file_offset = pos1 + 60;
	file_size = read_decimal(c, pos1+48, 10);
	de_dbg(c, "member data at %d, size: %d\n",
		(int)file_offset, (int)file_size);

	if(name_orig_len<1) {
		de_warn(c, "Missing filename\n");
		retval = 1;
		goto done;
	}
	else if(!de_strcmp(name_orig, "/")) {
		de_dbg(c, "symbol table (ignoring)\n");
		retval = 1;
		goto done;
	}
	else if(!de_strcmp(name_orig, "//")) {
		de_dbg(c, "extended name table\n");
		d->extended_name_table_pos = file_offset;
		d->extended_name_table_size = file_size;
		retval = 1;
		goto done;
	}
	else if(name_orig[0]=='/' && name_orig[1]>='0' && name_orig[1]<='9') {
		de_dbg(c, "extended filename\n");
		if(d->extended_name_table_pos==0) {
			de_err(c, "Missing extended name table\n");
			goto done;
		}

		name_offset = read_decimal(c, pos1+1, 15);
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

		de_finfo_set_name_from_slice(c, fi, c->infile, d->extended_name_table_pos+name_offset,
			ext_name_len, 0);
		fi->original_filename_flag = 1;
	}
	else if(name_orig[0]=='/') {
		de_warn(c, "Unsupported extension: \"%s\"\n", name_printable);
		retval = 1;
		goto done;
	}
	else {
		if(name_orig[name_orig_len-1]=='/') {
			// Filenames are often terminated with a '/', to allow for
			// trailing spaces.
			name_orig_len--;
		}

		de_finfo_set_name_from_bytes(c, fi, (de_byte*)name_orig, name_orig_len, 0,
			DE_ENCODING_ASCII);
		// TODO: Support UTF-8?
		fi->original_filename_flag = 1;
	}

	dbuf_create_file_from_slice(c->infile, file_offset, file_size, NULL, fi);

	retval = 1;
done:
	*p_item_len = 60 + file_size;
	if(*p_item_len % 2) (*p_item_len)++; // padding byte
	de_dbg_indent(c, -1);
	de_finfo_destroy(c, fi);
	return retval;
}

static void de_run_ar(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;
	de_int64 item_len;
	int ret;

	de_warn(c, "AR support is incomplete\n");

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
