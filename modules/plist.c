// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Binary PLIST (property list format used mainly by Apple)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_plist);

#define MAX_PLIST_NESTING_LEVEL 10
#define MAX_PLIST_OBJECTS       1000000

struct objref_struct {
	u32 offs;
};

typedef struct localctx_struct {
	int nesting_level;
	int exceeded_max_objects;
	i64 object_count; // Number of objects we've decoded so far

	unsigned int nbytes_per_objref_table_entry;
	unsigned int nbytes_per_object_refnum;
	i64 top_object_refnum;
	i64 objref_table_start;

	// objref_table maps object refnums to file offsets.
	// It has .num_objrefs elements.
	i64 num_objrefs;
	struct objref_struct *objref_table;
} lctx;

static int do_header(deark *c, lctx *d, i64 pos)
{
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);

	if(dbuf_memcmp(c->infile, pos, "bplist", 6)) {
		de_err(c, "Not in binary PLIST format");
		goto done;
	}
	if(dbuf_memcmp(c->infile, pos+6, "00", 2)) {
		// TODO: Support other versions?
		de_err(c, "Unsupported binary PLIST version");
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static int do_trailer(deark *c, lctx *d, i64 pos1)
{
	int retval = 0;
	i64 pos = pos1;

	de_dbg(c, "trailer at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 5; // unused
	pos++; // sort version

	d->nbytes_per_objref_table_entry = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "bytes per objref table entry: %u", d->nbytes_per_objref_table_entry);

	d->nbytes_per_object_refnum = (unsigned int)de_getbyte_p(&pos);
	de_dbg(c, "bytes per object refnum: %u", d->nbytes_per_object_refnum);

	d->num_objrefs = de_geti64be(pos);
	de_dbg(c, "num objrefs: %d", (int)d->num_objrefs);
	pos += 8;

	d->top_object_refnum = de_geti64be(pos);
	de_dbg(c, "root object refnum: %"I64_FMT, d->top_object_refnum);
	pos += 8;

	d->objref_table_start = de_geti64be(pos);
	de_dbg(c, "objref table start: %"I64_FMT, d->objref_table_start);
	pos += 8;

	if(d->nbytes_per_objref_table_entry<1 || d->nbytes_per_objref_table_entry>8 ||
		d->nbytes_per_object_refnum<1 || d->nbytes_per_object_refnum>8)
	{
		de_err(c, "Bad or unsupported PLIST format");
		goto done;
	}

	if(d->num_objrefs<0 || d->num_objrefs>MAX_PLIST_OBJECTS) {
		de_err(c, "Too many PLIST objects (%"I64_FMT")", d->num_objrefs);
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	return retval;
}

static int do_one_object_by_refnum(deark *c, lctx *d, i64 refnum);

static void report_nesting_level_exceeded(deark *c, lctx *d)
{
	de_err(c, "Maximum nesting level exceeded");
}

static void do_object_array_or_set(deark *c, lctx *d, const char *tn,
	i64 objpos, i64 pos1, i64 numitems)
{
	i64 k;
	i64 pos = pos1;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d->nesting_level++;
	if(d->nesting_level>MAX_PLIST_NESTING_LEVEL) {
		report_nesting_level_exceeded(c, d);
		goto done;
	}

	for(k=0; k<numitems; k++) {
		i64 refnum;

		if(d->exceeded_max_objects) goto done;
		de_dbg(c, "item[%d] (for %s@%"I64_FMT")", (int)k, tn, objpos);
		de_dbg_indent(c, 1);

		refnum = dbuf_getint_ext(c->infile, pos, d->nbytes_per_object_refnum, 0, 0);
		pos += (i64)d->nbytes_per_object_refnum;

		de_dbg(c, "refnum: %u", (unsigned int)refnum);
		if(!do_one_object_by_refnum(c, d, refnum)) goto done;

		de_dbg_indent(c, -1);
	}

done:
	d->nesting_level--;
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_object_dict(deark *c, lctx *d, i64 objpos, i64 pos1,
	i64 dictsize)
{
	i64 k;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d->nesting_level++;
	if(d->nesting_level>MAX_PLIST_NESTING_LEVEL) {
		report_nesting_level_exceeded(c, d);
		goto done;
	}

	for(k=0; k<dictsize; k++) {
		i64 keyrefnum;
		i64 valrefnum;

		if(d->exceeded_max_objects) goto done;
		de_dbg(c, "entry[%d] (for dict@%"I64_FMT")", (int)k, objpos);
		de_dbg_indent(c, 1);

		keyrefnum = dbuf_getint_ext(c->infile, pos1+k*(i64)d->nbytes_per_object_refnum,
			d->nbytes_per_object_refnum, 0, 0);
		de_dbg(c, "key objrefnum: %u", (unsigned int)keyrefnum);
		de_dbg_indent(c, 1);
		if(!do_one_object_by_refnum(c, d, keyrefnum)) goto done;
		de_dbg_indent(c, -1);

		valrefnum = dbuf_getint_ext(c->infile, pos1+(dictsize+k)*(i64)d->nbytes_per_object_refnum,
			d->nbytes_per_object_refnum, 0, 0);
		de_dbg(c, "val objrefnum: %u", (unsigned int)valrefnum);
		de_dbg_indent(c, 1);
		if(!do_one_object_by_refnum(c, d, valrefnum)) goto done;
		de_dbg_indent(c, -1);

		de_dbg_indent(c, -1);
	}

done:
	d->nesting_level--;
	de_dbg_indent_restore(c, saved_indent_level);
}

// "ASCII" string
static void do_object_string(deark *c, lctx *d, i64 pos, i64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s, 0, DE_ENCODING_ASCII);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_object_utf16string(deark *c, lctx *d, i64 pos, i64 len)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len*2, DE_DBG_MAX_STRLEN*2, s, 0, DE_ENCODING_UTF16BE);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

static void do_object_real(deark *c, lctx *d, i64 pos, i64 dlen_raw)
{
	double val;

	if(dlen_raw==2) {
		val = dbuf_getfloat32x(c->infile, pos, 0);
	}
	else if(dlen_raw==3) {
		val = dbuf_getfloat64x(c->infile, pos, 0);
	}
	else {
		return;
	}

	de_dbg(c, "value: %f", val);
}

static void do_object_int(deark *c, lctx *d, i64 pos, i64 dlen_raw)
{
	unsigned int nbytes;
	i64 n;

	if(dlen_raw<0 || dlen_raw>3) return;
	nbytes = 1U<<(unsigned int)dlen_raw;
	n = dbuf_getint_ext(c->infile, pos, nbytes, 0, 1);
	de_dbg(c, "value: %"I64_FMT, n);
}

static void do_object_date(deark *c, lctx *d, i64 pos)
{
	double val_flt;
	i64 val_int;
	struct de_timestamp ts;
	char timestamp_buf[64];

	val_flt = dbuf_getfloat64x(c->infile, pos, 0);
	val_int = (i64)val_flt;
	// Epoch is Jan 1, 2001. There are 31 years, with 8 leap days, between
	// that and the Unix time epoch.
	de_unix_time_to_timestamp(val_int + ((365*31 + 8)*86400), &ts, 0x1);
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "value: %f (%s)", val_flt, timestamp_buf);
}

// Returns 0 if we should stop processing the file
static int do_one_object_by_offset(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	u8 marker;
	u8 m1, m2;
	int has_size;
	i64 dlen_raw;
	const char *tn;

	// In this format, it is easy for an aggregate object to contain itself, or an
	// ancestor, making the number of objects infinite. We could detect this if we
	// wanted, but doesn't really solve the problem. Even without recursion, the
	// number of objects can grow exponentially, and a small file could easily
	// contain trillions of objects. Instead, we'll enforce an arbitrary limit to
	// the number of objects we decode.
	// TODO: If we were to decode each aggregate object only once, would that be a
	// good solution, or would it make the output less useful?
	if(d->exceeded_max_objects) return 0;
	if(d->object_count>=MAX_PLIST_OBJECTS) {
		d->exceeded_max_objects = 1;
		de_err(c, "Too many objects encountered (max=%d)", MAX_PLIST_OBJECTS);
		return 0;
	}

	de_dbg(c, "object at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->object_count++;

	if(pos<8 || pos>=c->infile->len-32) goto done;

	marker = de_getbyte_p(&pos);
	de_dbg(c, "marker: 0x%02x", (unsigned int)marker);

	m1 = (marker&0xf0)>>4;
	m2 = marker&0x0f;

	tn = "?";
	has_size = 0;
	dlen_raw = 0;

	switch(m1) {
	case 0x0:
		if(m2==0x8 || m2==0x9) {
			tn = "bool";
		}
		break;
	case 0x1:
		tn = "int";
		has_size = 1;
		break;
	case 0x2:
		tn = "real";
		has_size = 1;
		break;
	case 0x3:
		if(m2==0x3) {
			tn = "date";
		}
		break;
	case 0x4:
		tn = "binary data";
		has_size = 1;
		break;
	case 0x5:
		tn = "string";
		has_size = 1;
		break;
	case 0x6:
		tn = "UTF-16 string";
		has_size = 1;
		break;
	case 0x8: // TODO
		tn = "uid";
		has_size = 1;
		break;
	case 0xa:
		tn = "array";
		has_size = 1;
		break;
	case 0xc:
		tn = "set";
		has_size = 1;
		break;
	case 0xd:
		tn = "dict";
		has_size = 1;
		break;
	}

	de_dbg(c, "data type: %s", tn);

	if(has_size) {
		if(m2==0xf) {
			u8 x;
			unsigned int nbytes_in_len;
			x = de_getbyte_p(&pos);
			// 0x10 = size is a 1-byte int
			// 0x11 = 2-byte int, 0x12 = 4-byte int, 0x13 = 8-byte int
			if(x<0x10 || x>0x13) goto done;
			nbytes_in_len = 1U<<(unsigned int)(x-0x10);
			dlen_raw = dbuf_getint_ext(c->infile, pos, nbytes_in_len, 0, 0);
			pos += (i64)nbytes_in_len;
		}
		else {
			dlen_raw = (i64)m2;
		}
		de_dbg(c, "size (logical): %"I64_FMT, dlen_raw);
	}

	if(m1==0x0 && (m2==0x8 || m2==0x9)) {
		de_dbg(c, "value: %s", (m2==0x8)?"false":"true");
	}
	else if(m1==0x1) {
		do_object_int(c, d, pos, dlen_raw);
	}
	else if(m1==0x2) {
		do_object_real(c, d, pos, dlen_raw);
	}
	else if(m1==0x3 && m2==0x3) {
		do_object_date(c, d, pos);
	}
	else if(m1==0x4) {
		de_dbg(c, "binary data at %"I64_FMT", len=%"I64_FMT, pos, dlen_raw);
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, c->infile, pos, dlen_raw, 256, NULL, 0x1);
		de_dbg_indent(c, -1);
	}
	else if(m1==0x5) {
		do_object_string(c, d, pos, dlen_raw);
	}
	else if(m1==0x6) {
		do_object_utf16string(c, d, pos, dlen_raw);
	}
	else if(m1==0xa) {
		do_object_array_or_set(c, d, tn, pos1, pos, dlen_raw);
	}
	else if(m1==0xc) {
		do_object_array_or_set(c, d, tn, pos1, pos, dlen_raw);
	}
	else if(m1==0xd) {
		do_object_dict(c, d, pos1, pos, dlen_raw);
	}
	else {
		de_dbg(c, "[don't know how to decode this data type]");
	}

done:
	de_dbg_indent(c, -1);
	return 1;
}

// Returns 0 if we should stop processing the file
static int do_one_object_by_refnum(deark *c, lctx *d, i64 refnum)
{
	if(refnum<0 || refnum>=d->num_objrefs) return 1;
	return do_one_object_by_offset(c, d, d->objref_table[refnum].offs);
}

static void read_offset_table(deark *c, lctx *d)
{
	i64 k;
	i64 pos = d->objref_table_start;

	de_dbg(c, "objref table at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	d->objref_table = de_mallocarray(c, d->num_objrefs, sizeof(struct objref_struct));

	for(k=0; k<d->num_objrefs; k++) {
		i64 offs;

		if(pos+(i64)d->nbytes_per_objref_table_entry > c->infile->len-32) break;
		offs = dbuf_getint_ext(c->infile, pos, d->nbytes_per_objref_table_entry, 0, 0);
		if(c->debug_level>=2)
			de_dbg(c, "objref[%"I64_FMT"] offset: %"I64_FMT, k, offs);
		d->objref_table[k].offs = (u32)offs;
		pos += (i64)d->nbytes_per_objref_table_entry;
	}

	de_dbg_indent(c, -1);
}

static void de_run_plist(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));

	if(c->infile->len>0xffffffffU) {
		// We *could* support huge PLIST files, but until I learn that they
		// are valid, for efficiency I'll make sure an offset can fit in
		// 4 bytes.
		de_err(c, "PLIST too large (%"I64_FMT")", c->infile->len);
		goto done;
	}

	if(!do_header(c, d, 0)) goto done;

	if(!do_trailer(c, d, c->infile->len-32)) goto done;
	read_offset_table(c, d);

	do_one_object_by_refnum(c, d, d->top_object_refnum);

done:
	if(d) {
		de_free(c, d->objref_table);
		de_free(c, d);
	}
}

static int de_identify_plist(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "bplist00", 8))
		return 100;
	return 0;
}

void de_module_plist(deark *c, struct deark_module_info *mi)
{
	mi->id = "plist";
	mi->desc = ".plist property list, binary format";
	mi->run_fn = de_run_plist;
	mi->identify_fn = de_identify_plist;
}
