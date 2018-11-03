// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// SIS - Symbian/EPOC installation archive

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_sis);

struct lang_info {
	char sz[4];
};

struct file_fork_info {
	de_int64 ptr;
	de_int64 len;
	de_int64 orig_len;
};

// A "file rec" is a kind of record, which may or may not actually represent
// a file.
struct file_rec {
	de_int64 rec_pos; // points to the "File record type" field
	de_int64 rec_len;
	unsigned int rectype;
	unsigned int file_type;

	de_int64 num_forks;
	struct file_fork_info *ffi; // has [num_forks] elements
	de_ucstring *name_src;
	de_ucstring *name_dest;
	de_ucstring *name_to_use;
};

typedef struct localctx_struct {
	de_int64 installer_ver;
	unsigned int options;
	de_byte is_rel6;
	de_byte files_are_compressed;
	de_int64 nfiles;
	de_int64 languages_ptr;
	de_int64 files_ptr;
	de_int64 requisites_ptr;
	de_int64 certificates_ptr;
	de_int64 component_name_ptr;
	de_int64 signature_ptr;
	de_int64 capabilities_ptr;
	de_int64 nlangs;
	struct lang_info *langi;
} lctx;

static int do_file_header(deark *c, lctx *d, de_int64 pos1)
{
	de_int64 pos = pos1;
	de_int64 k;
	de_int64 n;
	int retval = 0;

	de_dbg(c, "file header at %d", (int)pos);
	de_dbg_indent(c, 1);
	for(k=1; k<=4; k++) {
		n = de_getui32le_p(&pos);
		de_dbg(c, "UID %d: 0x%08x", (int)k, (unsigned int)n);
		if(k==2) {
			if(n==0x10003a12) {
				d->is_rel6 = 1;
			}
		}
	}

	pos += 2; // checksum

	d->nlangs = de_getui16le_p(&pos);
	de_dbg(c, "num languages: %d", (int)d->nlangs);

	d->nfiles = de_getui16le_p(&pos);
	de_dbg(c, "num files: %d", (int)d->nfiles);

	pos += 2; // num requisites
	pos += 2; // installation language
	pos += 2; // installation files
	pos += 2; // installation drive
	pos += 2; // num capabilities

	d->installer_ver = de_getui32le_p(&pos);
	de_dbg(c, "installer ver: %d", (int)d->installer_ver);
	if(d->installer_ver<68) {
		de_warn(c, "Unknown version: %d", (int)d->installer_ver);
	}

	d->options = (unsigned int)de_getui16le_p(&pos);
	de_dbg(c, "options: 0x%04x", d->options);
	if(d->is_rel6 && !(d->options&0x0008)) {
		d->files_are_compressed = 1;
		de_err(c, "Compression is not supported");
	}

	pos += 2; // type (TODO)
	pos += 2; // major version (of application)
	pos += 2; // minor version (of application)
	pos += 4; // variant

	d->languages_ptr = de_getui32le_p(&pos);
	de_dbg(c, "languages ptr: %"INT64_FMT, d->languages_ptr);
	d->files_ptr = de_getui32le_p(&pos);
	de_dbg(c, "files ptr: %"INT64_FMT, d->files_ptr);

	// TODO: More fields here

	retval = 1;
	de_dbg_indent(c, -1);
	return retval;
}

static const char *get_file_type_name(unsigned int t)
{
	const char *s = NULL;
	switch(t) {
	case 0: s="standard file"; break;
	case 1: s="text file displayed during install"; break;
	case 2: s="SIS component file"; break;
	case 3: s="file run during install"; break;
	case 4: s="file to be created during install"; break;
	case 5: s="open file"; break;
	}
	return s?s:"?";
}

static void do_extract_file(deark *c, lctx *d, struct file_rec *fr,
	de_int64 fork_num)
{
	de_finfo *fi = NULL;
	de_ucstring *fn = NULL;

	if(fr->ffi[fork_num].ptr<0 ||
		fr->ffi[fork_num].ptr + fr->ffi[fork_num].len > c->infile->len)
	{
		goto done;
	}

	if(d->files_are_compressed) {
		goto done;
	}

	fi = de_finfo_create(c);

	fn = ucstring_create(c);

	if(fr->rectype==0x1 && fork_num<d->nlangs && d->langi &&
		d->langi[fork_num].sz[0])
	{
		// Prepend a code for the language
		ucstring_append_sz(fn, d->langi[fork_num].sz, DE_ENCODING_LATIN1);
		ucstring_append_sz(fn, ".", DE_ENCODING_LATIN1);
	}
	ucstring_append_ucstring(fn, fr->name_to_use);
	de_finfo_set_name_from_ucstring(c, fi, fn);

	dbuf_create_file_from_slice(c->infile, fr->ffi[fork_num].ptr,
		fr->ffi[fork_num].len, NULL, fi, 0);

done:
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn);
}

static void read_sis_string(deark *c, lctx *d, de_ucstring *s,
	de_int64 pos, de_int64 len)
{
	if(d->options & 0x0001) {
		dbuf_read_to_ucstring_n(c->infile, pos, len, 512*2, s, 0, DE_ENCODING_UTF16LE);
	}
	else {
		dbuf_read_to_ucstring_n(c->infile, pos, len, 512, s, 0, DE_ENCODING_ASCII);
	}
}

// Append a substring of s2 to s1
static void ucstring_append_substring(de_ucstring *s1, const de_ucstring *s2,
	de_int64 pos, de_int64 len)
{
	de_int64 i;

	if(!s2) return;
	if(pos<0) return;
	for(i=0; i<len; i++) {
		if(pos+i >= s2->len) break;
		ucstring_append_char(s1, s2->str[pos+i]);
	}
}

// Sets fr->name_to_use
static void make_output_filename(deark *c, lctx *d, struct file_rec *fr)
{
	de_int64 k;
	de_int64 pathlen = 0;
	de_int64 basenamelen;
	de_ucstring *s;

	if(fr->name_to_use) return;
	if(!fr->name_dest || !fr->name_src) return;
	fr->name_to_use = ucstring_create(c);

	// s will point to either fr->name_dest or fr->name_src, whichever
	// one looks better.
	if(fr->name_src->len>0) {
		s = fr->name_src;
	}
	else {
		s = fr->name_dest;
	}

	if((fr->file_type==0 || fr->file_type==3) && fr->name_dest->len>0) {
		s = fr->name_dest;
	}

	for(k=s->len-1; k>=0; k--) {
		if(s->str[k]=='\\' ||
			s->str[k]=='/')
		{
			pathlen = k+1;
			break;
		}
	}
	basenamelen = s->len - pathlen;

	if(basenamelen>1) {
		ucstring_append_substring(fr->name_to_use, s, pathlen, basenamelen);
	}
	else {
		ucstring_append_ucstring(fr->name_to_use, s);
	}
}

// Returns 0 if fr->rec_len was not set
static int do_file_record_file(deark *c, lctx *d, struct file_rec *fr)
{
	de_int64 pos = fr->rec_pos;
	de_int64 k;
	de_int64 nlen, nptr;
	int should_extract;

	pos += 4; // File record type, already read
	fr->file_type = (unsigned int)de_getui32le_p(&pos);
	de_dbg(c, "file type: %u (%s)", fr->file_type, get_file_type_name(fr->file_type));

	pos += 4; // file details

	nlen = de_getui32le_p(&pos);
	nptr = de_getui32le_p(&pos);
	fr->name_src = ucstring_create(c);
	read_sis_string(c, d, fr->name_src, nptr, nlen);
	de_dbg(c, "src name: \"%s\"", ucstring_getpsz_d(fr->name_src));

	nlen = de_getui32le_p(&pos);
	nptr = de_getui32le_p(&pos);
	fr->name_dest = ucstring_create(c);
	read_sis_string(c, d, fr->name_dest, nptr, nlen);
	de_dbg(c, "dest name: \"%s\"", ucstring_getpsz_d(fr->name_dest));

	make_output_filename(c, d, fr);

	if(fr->rectype==0x1) fr->num_forks = d->nlangs;
	else fr->num_forks = 1;

	fr->ffi = de_malloc(c, fr->num_forks * sizeof(struct file_fork_info));

	for(k=0; k<fr->num_forks; k++) {
		fr->ffi[k].len = de_getui32le_p(&pos);
		de_dbg(c, "len[%d]: %"INT64_FMT, (int)k, fr->ffi[k].len);
	}
	for(k=0; k<fr->num_forks; k++) {
		fr->ffi[k].ptr = de_getui32le_p(&pos);
		de_dbg(c, "ptr[%d]: %"INT64_FMT, (int)k, fr->ffi[k].ptr);
	}

	if(d->is_rel6) {
		for(k=0; k<fr->num_forks; k++) {
			fr->ffi[k].orig_len = de_getui32le_p(&pos);
		}
		pos += 4; // MIME type len
		pos += 4; // MIME type ptr
	}

	should_extract = 0;
	if(fr->file_type==0 || fr->file_type==1 || fr->file_type==2 ||
		fr->file_type==3 || fr->file_type==5)
	{
		should_extract = 1;
	}

	if(should_extract) {
		for(k=0; k<fr->num_forks; k++) {
			do_extract_file(c, d, fr, k);
		}
	}

	fr->rec_len = pos - fr->rec_pos;
	de_dbg2(c, "record len: %d", (int)fr->rec_len);
	return 1;
}

static const char *get_file_rec_type_name(unsigned int t)
{
	const char *s = NULL;
	switch(t) {
	case 0: s="simple file"; break;
	case 1: s="multi-language file set"; break;
	case 2: s="options"; break;
	case 3: s="*if*"; break;
	case 4: s="*elseif*"; break;
	case 5: s="*else*"; break;
	case 6: s="*endif*"; break;
	}
	return s?s:"?";
}

static int do_file_record(deark *c, lctx *d, de_int64 idx,
	de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	int retval = 0;
	struct file_rec *fr = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	fr = de_malloc(c, sizeof(struct file_rec));
	fr->rec_pos = pos1;
	de_dbg(c, "file record[%d] at %"INT64_FMT, (int)idx, fr->rec_pos);
	de_dbg_indent(c, 1);

	fr->rectype = (unsigned int)de_getui32le_p(&pos);
	de_dbg(c, "record type: 0x%08x (%s)", fr->rectype, get_file_rec_type_name(fr->rectype));

	if(fr->rectype==0x0 || fr->rectype==0x1) {
		if(!do_file_record_file(c, d, fr)) goto done;
	}
	else {
		// TODO: more record types
		de_err(c, "Unsupported record type (0x%08x), can't continue", fr->rectype);
		goto done;
	}

	*bytes_consumed = fr->rec_len;
	retval = 1;
done:
	if(fr) {
		de_free(c, fr->ffi);
		ucstring_destroy(fr->name_src);
		ucstring_destroy(fr->name_dest);
		ucstring_destroy(fr->name_to_use);
		de_free(c, fr);
	}
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void do_file_records(deark *c, lctx *d)
{
	de_int64 k;
	de_int64 pos1 = d->files_ptr;
	de_int64 pos = pos1;

	de_dbg(c, "file records at %"INT64_FMT, pos1);
	de_dbg_indent(c, 1);
	for(k=0; k<d->nfiles; k++) {
		de_int64 bytes_consumed = 0;

		if(pos >= c->infile->len) break;
		if(!do_file_record(c, d, k, pos, &bytes_consumed)) break;
		pos += bytes_consumed;
	}
	de_dbg_indent(c, -1);
}

static void lookup_lang_namecode(unsigned int lc, char *nc, size_t nc_len)
{
	static const char codes[99*2+1] =
	 "XXENFRGESPITSWDANOFIAMSFSGPOTUICRUHUDUBLAUBGASNZIFCSSKPLSLTCHKZH"
	 "JATHAFSQAHARHYTLBEBNBGMYCAHRCEIESFETFACFGDKAELCGGUHEHIINGASZKNKK"
	 "KMKOLOLVLTMKMSMLMRMOMNNNBPPAROSRSISOOSLSSHFSXXTATEBOTICTTKUKURXX"
	 "VICYZU";

	if(lc>=99) lc=0;
	nc[0] = codes[2*lc];
	nc[1] = codes[2*lc+1];
	nc[2] = '\0';
}

static void do_language_records(deark *c, lctx *d)
{
	de_int64 k;
	de_int64 pos1 = d->languages_ptr;
	de_int64 pos = pos1;

	if(d->nlangs<1) return;
	de_dbg(c, "language records at %"INT64_FMT, pos1);
	d->langi = de_malloc(c, d->nlangs*sizeof(struct lang_info));
	de_dbg_indent(c, 1);
	for(k=0; k<d->nlangs; k++) {
		unsigned int lc;
		lc = (unsigned int)de_getui16le_p(&pos);
		lookup_lang_namecode(lc, d->langi[k].sz, sizeof(d->langi[k].sz));
		de_dbg(c, "lang[%d] = %u (%s)", (int)k, lc, d->langi[k].sz);
	}
	de_dbg_indent(c, -1);
}

static void de_run_sis(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_file_header(c, d, pos)) goto done;

	do_language_records(c, d);

	do_file_records(c, d);

done:
	if(d) {
		de_free(c, d->langi);
	}
	de_free(c, d);
}

static int de_identify_sis(deark *c)
{
	if(!dbuf_memcmp(c->infile, 8, "\x19\x04\x00\x10", 4)) {
		if(!dbuf_memcmp(c->infile, 4, "\x6d\x00\x00\x10", 8))
			return 100;
		if(!dbuf_memcmp(c->infile, 4, "\x12\x3a\x00\x10", 8))
			return 100;
		return 10;
	}
	return 0;
}

void de_module_sis(deark *c, struct deark_module_info *mi)
{
	mi->id = "sis";
	mi->desc = "SIS (EPOC/Symbian installation archive)";
	mi->run_fn = de_run_sis;
	mi->identify_fn = de_identify_sis;
}
