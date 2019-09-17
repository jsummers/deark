// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// SIS - Symbian/EPOC installation archive

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_sis);

struct lang_info {
	char sz[4];
};

struct file_fork_info {
	i64 ptr;
	i64 len;
	i64 orig_len;
};

// A "file rec" is a kind of record, which may or may not actually represent
// a file.
struct file_rec {
	i64 rec_pos; // points to the "File record type" field
	i64 rec_len;
	unsigned int rectype;
	unsigned int file_type;

	i64 num_forks;
	struct file_fork_info *ffi; // has [num_forks] elements
	de_ucstring *name_src;
	de_ucstring *name_dest;
	de_ucstring *name_to_use;
};

typedef struct localctx_struct {
	i64 installer_ver;
	unsigned int options;
	u8 is_rel6;
	u8 files_are_compressed;
	i64 nlangs;
	i64 nfiles;
	i64 nrequisites;
	i64 languages_ptr;
	i64 files_ptr;
	i64 requisites_ptr;
	i64 certificates_ptr;
	i64 component_name_ptr;
	i64 signature_ptr;
	i64 capabilities_ptr;
	struct lang_info *langi;
} lctx;

static int do_file_header(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	i64 k;
	i64 n, n2;
	int retval = 0;
	u32 crc_even;
	u32 crc_odd;
	de_ucstring *options_descr = NULL;
	struct de_crcobj *crco = NULL;
	u8 tmpbuf[12];

	de_dbg(c, "file header at %d", (int)pos);

	de_dbg_indent(c, 1);

	// Pre-read the first 12 bytes, to calculate some CRCs for later.
	de_read(tmpbuf, pos, 12);

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
	for(k=0; k<12; k+=2) {
		de_crcobj_addbyte(crco, tmpbuf[k]);
	}
	crc_even = de_crcobj_getval(crco);
	de_crcobj_reset(crco);
	for(k=1; k<12; k+=2) {
		de_crcobj_addbyte(crco, tmpbuf[k]);
	}
	crc_odd = de_crcobj_getval(crco);
	de_crcobj_destroy(crco);
	crco = NULL;

	n = de_getu32le_p(&pos);
	de_dbg(c, "UID 1: 0x%08x", (unsigned int)n);

	n = de_getu32le_p(&pos);
	de_dbg(c, "UID 2: 0x%08x", (unsigned int)n);
	if(n==0x10003a12) {
		d->is_rel6 = 1;
	}

	n = de_getu32le_p(&pos);
	de_dbg(c, "UID 3: 0x%08x", (unsigned int)n);

	n = de_getu32le_p(&pos);
	de_dbg(c, "UID 4: 0x%08x", (unsigned int)n);
	// The way UID 4 is calculated is really silly.
	de_dbg(c, "expected value of UID 4: 0x%04x%04x",
		(unsigned int)crc_odd, (unsigned int)crc_even);

	if(d->is_rel6) {
		de_declare_fmt(c, "SIS, EPOC r6");
	}
	else {
		de_declare_fmt(c, "SIS, EPOC r3/4/5");
	}

	pos += 2; // checksum

	d->nlangs = de_getu16le_p(&pos);
	de_dbg(c, "num languages: %d", (int)d->nlangs);

	d->nfiles = de_getu16le_p(&pos);
	de_dbg(c, "num files: %d", (int)d->nfiles);

	d->nrequisites = de_getu16le_p(&pos);
	de_dbg(c, "num requisites: %d", (int)d->nrequisites);

	pos += 2; // installation language
	pos += 2; // installation files
	pos += 2; // installation drive

	n = de_getu16le_p(&pos);
	de_dbg(c, "num capabilities: %d", (int)n);

	d->installer_ver = de_getu32le_p(&pos);
	de_dbg(c, "installer ver: %d", (int)d->installer_ver);
	if(d->installer_ver<68) {
		de_warn(c, "Unknown version: %d", (int)d->installer_ver);
	}

	d->options = (unsigned int)de_getu16le_p(&pos);
	options_descr = ucstring_create(c);
	if(d->options&0x01) ucstring_append_flags_item(options_descr, "IsUnicode");
	if(d->options&0x02) ucstring_append_flags_item(options_descr, "IsDistributable");
	if(d->options&0x08) ucstring_append_flags_item(options_descr, "NoCompress");
	if(d->options&0x10) ucstring_append_flags_item(options_descr, "ShutdownApps");
	de_dbg(c, "options: 0x%04x (%s)", d->options, ucstring_getpsz(options_descr));
	if(d->is_rel6 && !(d->options&0x0008)) {
		d->files_are_compressed = 1;
	}

	pos += 2; // type (TODO)
	n = de_getu16le_p(&pos);
	n2 = de_getu16le_p(&pos);
	de_dbg(c, "app version: %d,%d", (int)n, (int)n2);
	pos += 4; // variant

	d->languages_ptr = de_getu32le_p(&pos);
	de_dbg(c, "languages ptr: %"I64_FMT, d->languages_ptr);
	d->files_ptr = de_getu32le_p(&pos);
	de_dbg(c, "files ptr: %"I64_FMT, d->files_ptr);

	d->requisites_ptr = de_getu32le_p(&pos);
	de_dbg(c, "requisites ptr: %"I64_FMT, d->requisites_ptr);
	d->certificates_ptr = de_getu32le_p(&pos);
	de_dbg(c, "certificates ptr: %"I64_FMT, d->certificates_ptr);
	d->component_name_ptr = de_getu32le_p(&pos);
	de_dbg(c, "component name ptr: %"I64_FMT, d->component_name_ptr);

	if(d->is_rel6) {
		n = de_getu32le_p(&pos);
		de_dbg(c, "signature ptr: %"I64_FMT, n);
		n = de_getu32le_p(&pos);
		de_dbg(c, "capabilities ptr: %"I64_FMT, n);
	}

	retval = 1;
	de_dbg_indent(c, -1);
	ucstring_destroy(options_descr);
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
	i64 fork_num)
{
	de_finfo *fi = NULL;
	de_ucstring *fn = NULL;
	dbuf *outf = NULL;

	if(fr->ffi[fork_num].ptr<0 ||
		fr->ffi[fork_num].ptr + fr->ffi[fork_num].len > c->infile->len)
	{
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
	de_finfo_set_name_from_ucstring(c, fi, fn, 0);

	outf = dbuf_create_output_file(c, NULL, fi, 0);
	if(d->files_are_compressed) {
		if(!fmtutil_decompress_deflate(c->infile, fr->ffi[fork_num].ptr, fr->ffi[fork_num].len,
			outf, fr->ffi[fork_num].orig_len, NULL,
			DE_DEFLATEFLAG_ISZLIB|DE_DEFLATEFLAG_USEMAXUNCMPRSIZE))
		{
			goto done;
		}
		if(outf->len != fr->ffi[fork_num].orig_len) {
			de_warn(c, "expected %"I64_FMT" bytes, got %"I64_FMT,
				fr->ffi[fork_num].orig_len, outf->len);
		}
	}
	else {
		dbuf_copy(c->infile, fr->ffi[fork_num].ptr, fr->ffi[fork_num].len, outf);
	}

done:
	dbuf_close(outf);
	de_finfo_destroy(c, fi);
	ucstring_destroy(fn);
}

static void read_sis_string(deark *c, lctx *d, de_ucstring *s,
	i64 pos, i64 len)
{
	if(d->options & 0x0001) {
		dbuf_read_to_ucstring_n(c->infile, pos, len, 512*2, s, 0, DE_ENCODING_UTF16LE);
	}
	else {
		dbuf_read_to_ucstring_n(c->infile, pos, len, 512, s, 0, DE_ENCODING_WINDOWS1252);
	}
}

// Append a substring of s2 to s1
static void ucstring_append_substring(de_ucstring *s1, const de_ucstring *s2,
	i64 pos, i64 len)
{
	i64 i;

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
	i64 k;
	i64 pathlen = 0;
	i64 basenamelen;
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
	i64 pos = fr->rec_pos;
	i64 k;
	i64 nlen, nptr;
	int should_extract;

	pos += 4; // File record type, already read
	fr->file_type = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "file type: %u (%s)", fr->file_type, get_file_type_name(fr->file_type));

	pos += 4; // file details

	nlen = de_getu32le_p(&pos);
	nptr = de_getu32le_p(&pos);
	fr->name_src = ucstring_create(c);
	read_sis_string(c, d, fr->name_src, nptr, nlen);
	de_dbg(c, "src name: \"%s\"", ucstring_getpsz_d(fr->name_src));

	nlen = de_getu32le_p(&pos);
	nptr = de_getu32le_p(&pos);
	fr->name_dest = ucstring_create(c);
	read_sis_string(c, d, fr->name_dest, nptr, nlen);
	de_dbg(c, "dest name: \"%s\"", ucstring_getpsz_d(fr->name_dest));

	make_output_filename(c, d, fr);

	if(fr->rectype==0x1) fr->num_forks = d->nlangs;
	else fr->num_forks = 1;

	fr->ffi = de_mallocarray(c, fr->num_forks, sizeof(struct file_fork_info));

	for(k=0; k<fr->num_forks; k++) {
		fr->ffi[k].len = de_getu32le_p(&pos);
		de_dbg(c, "len[%d]: %"I64_FMT, (int)k, fr->ffi[k].len);
	}
	for(k=0; k<fr->num_forks; k++) {
		fr->ffi[k].ptr = de_getu32le_p(&pos);
		de_dbg(c, "ptr[%d]: %"I64_FMT, (int)k, fr->ffi[k].ptr);
	}

	if(d->is_rel6) {
		for(k=0; k<fr->num_forks; k++) {
			fr->ffi[k].orig_len = de_getu32le_p(&pos);
			de_dbg(c, "orig_len[%d]: %"I64_FMT, (int)k, fr->ffi[k].orig_len);
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

static int do_file_record(deark *c, lctx *d, i64 idx,
	i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	int retval = 0;
	struct file_rec *fr = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	fr = de_malloc(c, sizeof(struct file_rec));
	fr->rec_pos = pos1;
	de_dbg(c, "file record[%d] at %"I64_FMT, (int)idx, fr->rec_pos);
	de_dbg_indent(c, 1);

	fr->rectype = (unsigned int)de_getu32le_p(&pos);
	de_dbg(c, "record type: 0x%08x (%s)", fr->rectype, get_file_rec_type_name(fr->rectype));

	if(fr->rectype==0x0 || fr->rectype==0x1) {
		if(!do_file_record_file(c, d, fr)) goto done;
	}
	else if(fr->rectype==0x3 || fr->rectype==0x4) { // *if*, *elseif*
		i64 n;
		n = de_getu32le_p(&pos);
		de_dbg(c, "size of conditional expression: %d", (int)n);
		pos += n;
		fr->rec_len = pos - pos1;
	}
	else if(fr->rectype==0x5 || fr->rectype==0x6) { // *else*, *endif*
		fr->rec_len = 4;
	}
	else {
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
	i64 k;
	i64 pos1 = d->files_ptr;
	i64 pos = pos1;

	de_dbg(c, "file records at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	for(k=0; k<d->nfiles; k++) {
		i64 bytes_consumed = 0;

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
	i64 k;
	i64 pos1 = d->languages_ptr;
	i64 pos = pos1;

	if(d->nlangs<1) return;
	de_dbg(c, "language records at %"I64_FMT, pos1);
	d->langi = de_mallocarray(c, d->nlangs, sizeof(struct lang_info));
	de_dbg_indent(c, 1);
	for(k=0; k<d->nlangs; k++) {
		unsigned int lc;
		lc = (unsigned int)de_getu16le_p(&pos);
		lookup_lang_namecode(lc, d->langi[k].sz, sizeof(d->langi[k].sz));
		de_dbg(c, "lang[%d] = %u (%s)", (int)k, lc, d->langi[k].sz);
	}
	de_dbg_indent(c, -1);
}

static void do_component_name_record(deark *c, lctx *d)
{
	i64 pos1 = d->component_name_ptr;
	de_ucstring *s = NULL;
	i64 k;

	if(pos1<1 || pos1>=c->infile->len) return;
	if(d->nlangs<1) return;

	de_dbg(c, "component name record at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	s = ucstring_create(c);
	for(k=0; k<d->nlangs; k++) {
		i64 npos, nlen;
		nlen = de_getu32le(pos1+4*k);
		npos = de_getu32le(pos1+4*d->nlangs+4*k);
		ucstring_empty(s);
		read_sis_string(c, d, s, npos, nlen);
		de_dbg(c, "name[%d]: \"%s\"", (int)k, ucstring_getpsz_d(s));
	}
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}

static void do_requisite_records(deark *c, lctx *d)
{
	i64 pos1 = d->requisites_ptr;
	i64 pos = pos1;
	i64 k, i;
	de_ucstring *s = NULL;

	if(d->nrequisites<1) return;
	if(pos1<1 || pos1>=c->infile->len) return;
	de_dbg(c, "requisite records at %"I64_FMT, pos1);
	s = ucstring_create(c);
	de_dbg_indent(c, 1);
	for(k=0; k<d->nrequisites; k++) {
		i64 n, n2;

		de_dbg(c, "requisite record[%d] at %"I64_FMT, (int)k, pos);
		de_dbg_indent(c, 1);
		n = de_getu32le_p(&pos);
		de_dbg(c, "UID: 0x%08x", (unsigned int)n);
		n = de_getu16le_p(&pos);
		n2 = de_getu16le_p(&pos);
		de_dbg(c, "version required: %d,%d", (int)n, (int)n2);
		n = de_getu32le_p(&pos);
		de_dbg(c, "variant: 0x%08x", (unsigned int)n);

		for(i=0; i<d->nlangs; i++) {
			i64 npos, nlen;
			nlen = de_getu32le(pos+4*i);
			npos = de_getu32le(pos+4*d->nlangs+4*i);
			ucstring_empty(s);
			read_sis_string(c, d, s, npos, nlen);
			de_dbg(c, "name[%d]: \"%s\"", (int)i, ucstring_getpsz_d(s));
		}
		pos += 4*d->nlangs; // name lengths
		pos += 4*d->nlangs; // name pointers

		de_dbg_indent(c, -1);
	}
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
}
static void do_certificate_records(deark *c, lctx *d)
{
	i64 pos1 = d->certificates_ptr;
	i64 pos = pos1;
	i64 k;
	i64 ncerts;
	int z[6];

	if(pos1<1 || pos1>=c->infile->len) return;
	de_dbg(c, "certificate records at %"I64_FMT, pos1);
	de_dbg_indent(c, 1);
	for(k=0; k<6; k++) {
		z[k] = (int)de_getu16le_p(&pos);
	}

	// The documentation I have does not explain how the month is encoded.
	// I.e., is January month #0, or month #1?
	// I found a file that has the month set to 0, so I assume that must be
	// January.
	de_dbg(c, "timestamp: %04d-%02d-%02d %02d:%02d:%02d",
		z[0], z[1]+1, z[2],
		z[3], z[4], z[5]);
	ncerts = de_getu32le_p(&pos);
	de_dbg(c, "number of certs: %d", (int)ncerts);
	de_dbg_indent(c, -1);
}

static void de_run_sis(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_file_header(c, d, pos)) goto done;

	do_language_records(c, d);
	do_component_name_record(c, d);
	do_requisite_records(c, d);
	do_file_records(c, d);
	do_certificate_records(c, d);

done:
	if(d) {
		de_free(c, d->langi);
	}
	de_free(c, d);
}

static int de_identify_sis(deark *c)
{
	if(!dbuf_memcmp(c->infile, 8, "\x19\x04\x00\x10", 4)) {
		if(!dbuf_memcmp(c->infile, 4, "\x6d\x00\x00\x10", 4))
			return 100;
		if(!dbuf_memcmp(c->infile, 4, "\x12\x3a\x00\x10", 4))
			return 100;
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
