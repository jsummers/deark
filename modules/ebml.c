// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// EBML, Matroska, MKV

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ebml);

typedef struct localctx_struct {
	int level;
} lctx;

struct handler_params {
	de_int64 dpos;
	de_int64 dlen;
};
typedef void (*handler_fn_type)(deark *c, lctx *d, struct handler_params *hp);

struct ele_id_info {
	// flags:
	// The low byte is a code for the data type:
#define TY_m 0x01 // Master
#define TY_u 0x02 // unsigned int
#define TY_i 0x03 // signed int
#define TY_s 0x04 // string
#define TY_8 0x05 // UTF-8 string
#define TY_b 0x06 // binary
#define TY_f 0x07 // float
#define TY_d 0x08 // date
	// 0x0100 = Don't decode this element by default
	unsigned int flags;

	de_int64 ele_id;
	const char *name;
	handler_fn_type hfn;
};

// Read a "Variable Size Integer".
// Updates *pos.
// Returns:
//  0 on failure
//  1 on success
//  2 for a special "reserved" value
static int get_var_size_int(dbuf *f, de_int64 *val, de_int64 *pos)
{
	de_byte b;
	de_byte mask;
	unsigned int k;
	int retval = 0;
	de_byte test_bit;
	unsigned int initial_zero_bits;

	// This is an unsigned int. In a de_int64, we can support up to 63
	// bits.
	// For now we'll hope that 8 octets is the most we'll have to support,
	// but it's possible we'll have to support 9 or even more, which will
	// require additional logic.
	//
	//  1xxxxxxx width_nbits=0, octets=1, data_bits=7
	//  01xxxxxx width_nbits=1, octets=2, data_bits=14
	//  ...
	//  00000001 width_nbits=7, octets=8, data_bits=56
	//  00000000 1xxxxxxx width_nbits=8, octets=9, data_bits=63

	b = dbuf_getbyte(f, *pos);
	(*pos)++;

	test_bit = 0x80;
	initial_zero_bits = 0;
	while(1) {
		if(b>=test_bit) {
			break;
		}

		// "Not it". Try the next-larger number of initial 0 bits.
		initial_zero_bits++;
		test_bit >>= 1;
		if(test_bit==0) {
			goto done;
		}
	}

	mask = 0x7f >> initial_zero_bits;

	*val = (de_int64)(b & mask);

	// Read remaining bytes, if any.
	for(k=0; k<initial_zero_bits; k++) {
		b = dbuf_getbyte(f, *pos);
		(*pos)++;
		if(*val > 0x07ffffffffffffffLL) {
			goto done;
		}
		*val = ((*val)<<8) | ((de_int64)b);
	}

	if(initial_zero_bits==0 && (*val)==0x7f) {
		// TODO: Fully handle "reserved" element value of all 1 bits.
		retval = 2;
		goto done;
	}

	retval = 1;

done:
	if(retval!=1) {
		*val = 0;
	}
	return retval;
}

static void handler_hexdumpa(deark *c, lctx *d, struct handler_params *hp)
{
	de_dbg_hexdump(c, c->infile, hp->dpos, hp->dlen, 256, NULL, 0x1);
}

static void handler_hexdumpb(deark *c, lctx *d, struct handler_params *hp)
{
	de_dbg_hexdump(c, c->infile, hp->dpos, hp->dlen, 256, NULL, 0x0);
}

static const struct ele_id_info ele_id_info_arr[] = {
	// Note that the Matroska spec may conflate encoded IDs with decoded IDs.
	// This table lists decoded IDs. Encoded IDs have an extra 1 bit in a
	// position that makes it more significant than any of the other 1 bits.
	{TY_u, 0x3, "TrackType", NULL},
	{TY_s, 0x6, "CodecID", NULL},
	{TY_u, 0x8, "FlagDefault", NULL},
	{TY_u, 0x1a, "FlagInterlaced", NULL},
	{TY_u, 0x1b, "BlockDuration", NULL},
	{TY_u, 0x1c, "FlagLacing", NULL},
	{TY_u, 0x1f, "Channels", NULL},
	{TY_m, 0x20, "BlockGroup", NULL},
	{TY_b, 0x21, "Block", NULL},
	{TY_b, 0x23, "SimpleBlock", NULL},
	{TY_u, 0x27, "Position", NULL},
	{TY_u, 0x2a, "CodecDecodeAll", NULL},
	{TY_u, 0x2b, "PrevSize", NULL},
	{TY_m, 0x2e, "TrackEntry", NULL},
	{TY_u, 0x30, "PixelWidth", NULL},
	{TY_u, 0x33, "CueTime", NULL},
	{TY_f, 0x35, "SamplingFrequency", NULL},
	{TY_m, 0x37, "CueTrackPositions", NULL},
	{TY_u, 0x39, "FlagEnabled", NULL},
	{TY_u, 0x3a, "PixelHeight", NULL},
	{TY_m, 0x3b, "CuePoint", NULL},
	{TY_b, 0x3f, "CRC-32", handler_hexdumpb},
	{TY_u, 0x57, "TrackNumber", NULL},
	{TY_m, 0x60, "Video", NULL},
	{TY_m, 0x61, "Audio", NULL},
	{TY_u, 0x67, "Timecode", NULL},
	{TY_b|0x0100, 0x6c, "Void", handler_hexdumpb},
	{TY_u, 0x71, "CueClusterPosition", NULL},
	{TY_u, 0x77, "CueTrack", NULL},
	{TY_i, 0x7b, "ReferenceBlock", NULL},
	{TY_u, 0x254, "ContentCompAlgo", NULL},
	{TY_b, 0x255, "ContentCompSettings", handler_hexdumpb},
	{TY_s, 0x282, "DocType", NULL},
	{TY_u, 0x285, "DocTypeReadVersion", NULL},
	{TY_u, 0x286, "EBMLVersion", NULL},
	{TY_u, 0x287, "DocTypeVersion", NULL},
	{TY_u, 0x2f2, "EBMLMaxIDLength", NULL},
	{TY_u, 0x2f3, "EBMLMaxSizeLength", NULL},
	{TY_u, 0x2f7, "EBMLReadVersion", NULL},
	{TY_d, 0x461, "DateUTC", NULL},
	{TY_s, 0x47a, "TagLanguage", NULL},
	{TY_u, 0x484, "TagDefault", NULL},
	{TY_8, 0x487, "TagString", NULL},
	{TY_f, 0x489, "Duration", NULL},
	{TY_8, 0x5a3, "TagName", NULL},
	{TY_8, 0xd80, "MuxingApp", NULL},
	{TY_m, 0xdbb, "Seek", NULL},
	{TY_m, 0x1034, "ContentCompression", NULL},
	{TY_8, 0x136e, "Name", NULL},
	{TY_b, 0x13ab, "SeekID", handler_hexdumpb},
	{TY_u, 0x13ac, "SeekPosition", NULL},
	{TY_u, 0x14b0, "DisplayWidth", NULL},
	{TY_u, 0x14b2, "DisplayUnit", NULL},
	{TY_u, 0x14ba, "DisplayHeight", NULL},
	{TY_u, 0x15aa, "FlagForced", NULL},
	{TY_u, 0x15ee, "MaxBlockAdditionID", NULL},
	{TY_8, 0x1741, "WritingApp", NULL},
	{TY_m, 0x2240, "ContentEncoding", NULL},
	{TY_u, 0x2264, "BitDepth", NULL},
	{TY_b, 0x23a2, "CodecPrivate", handler_hexdumpa},
	{TY_m, 0x23c0, "Targets", NULL},
	{TY_m, 0x27c8, "SimpleTag", NULL},
	{TY_u, 0x28ca, "TargetTypeValue", NULL},
	{TY_m, 0x2d80, "ContentEncodings", NULL},
	{TY_u, 0x2de7, "MinCache", NULL},
	{TY_m, 0x3373, "Tag", NULL},
	{TY_b, 0x33a4, "SegmentUID", handler_hexdumpb},
	{TY_u, 0x33c5, "TrackUID", NULL},
	{TY_f, 0x38b5, "OutputSamplingFrequency", NULL},
	{TY_s, 0x2b59c, "Language", NULL},
	{TY_f, 0x3314f, "TrackTimecodeScale (deprecated)", NULL},
	{TY_u, 0x3e383, "DefaultDuration", NULL},
	{TY_u, 0xad7b1, "TimecodeScale", NULL},
	{TY_m|0x0100, 0x14d9b74, "SeekHead", NULL},
	{TY_m, 0x254c367, "Tags", NULL},
	{TY_m, 0x549a966, "Info", NULL},
	{TY_m, 0x654ae6b, "Tracks", NULL},
	{TY_m, 0x8538067, "Segment", NULL},
	{TY_m, 0xa45dfa3, "EBML", NULL},
	{TY_m, 0xc53bb6b, "Cues", NULL},
	{TY_m|0x0100, 0xf43b675, "Cluster", NULL}
};

static const struct ele_id_info *find_ele_id_info(de_int64 ele_id)
{
	size_t k;
	for(k=0; k<DE_ITEMS_IN_ARRAY(ele_id_info_arr); k++) {
		if(ele_id_info_arr[k].ele_id == ele_id) {
			return &ele_id_info_arr[k];
		}
	}
	return NULL;
}

// This is a variable size integer, but it's different from the one named
// "Variable Size Integer".
static void decode_int(deark *c, lctx *d, const struct ele_id_info *ele_id,
	  de_int64 pos, de_int64 len1)
{
	unsigned int k;
	unsigned int len;
	de_uint64 v;

	if(len1<1 || len1>8) return;
	len = (unsigned int)len1;

	v = 0;
	for(k=0; k<len; k++) {
		de_uint64 x;
		x = (de_uint64)de_getbyte(pos+(de_int64)k);
		v |= x<<((len-1-k)*8);
	}

	de_dbg(c, "value: %"INT64_FMT, (de_int64)v);
}

static void decode_float(deark *c, lctx *d, const struct ele_id_info *ele_id,
	  de_int64 pos, de_int64 len)
{
	double v;

	if(len==4) {
		v = dbuf_getfloat32x(c->infile, pos, 0);
	}
	else if(len==8) {
		v = dbuf_getfloat64x(c->infile, pos, 0);
	}
	else {
		return;
	}
	de_dbg(c, "value: %f", v);
}

static void EBMLdate_to_timestamp(de_int64 ed, struct de_timestamp *ts)
{
	de_int64 t;

	// ed is the number of nanoseconds since the beginning of 2001.
	t = ed/1000000000;
	// Now t is seconds since the beginning of 2001.
	// (We assume leap seconds are not included. The EBML spec says nothing
	// about this issue, and there's no reasonable way to deal with it anyway.)
	// We want seconds since the beginning of 1970.
	// So, add the number of seconds in the years from 1970 through 2000. This
	// is 31 years.
	// There are 86400 seconds in a day.
	// There are 8 leap days in this range ('72, 76, 80, 84, 88, 92, 96, 00).
	t += 86400LL * (31*365 + 8);
	de_unix_time_to_timestamp(t, ts);
}

static void decode_date(deark *c, lctx *d, const struct ele_id_info *ele_id,
	  de_int64 pos, de_int64 len)
{
	de_int64 dt_int;
	struct de_timestamp ts;
	char buf[64];

	if(len!=8) return;
	dt_int = de_geti64be(pos);
	EBMLdate_to_timestamp(dt_int, &ts);
	de_timestamp_to_string(&ts, buf, sizeof(buf), 1);
	de_dbg(c, "value: %"INT64_FMT" (%s)", dt_int, buf);
}

static void decode_string(deark *c, lctx *d, const struct ele_id_info *ele_id,
	  de_int64 pos, de_int64 len, int encoding)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, len, DE_DBG_MAX_STRLEN, s,
		DE_CONVFLAG_STOP_AT_NUL, encoding);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));

	ucstring_destroy(s);
}

static int do_element_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len);

static int do_element(deark *c, lctx *d, de_int64 pos1,
	de_int64 nbytes_avail, de_int64 *bytes_used)
{
	de_int64 ele_id;
	de_int64 ele_dlen;
	de_int64 pos = pos1;
	int retval = 0;
	const struct ele_id_info *einfo;
	const char *ele_name;
	int saved_indent_level;
	unsigned int dtype = 0;
	int should_decode;
	int len_ret;
	char tmpbuf[80];

	de_dbg_indent_save(c, &saved_indent_level);

	de_dbg(c, "element at %"INT64_FMT", max_len=%"INT64_FMT, pos1, nbytes_avail);
	de_dbg_indent(c, 1);

	if(1!=get_var_size_int(c->infile, &ele_id, &pos)) {
		de_err(c, "Failed to read ID of element at %"INT64_FMT, pos1);
		goto done;
	}

	einfo = find_ele_id_info(ele_id);
	if(einfo && einfo->name)
		ele_name = einfo->name;
	else
		ele_name = "?";

	de_dbg(c, "element id: 0x%"INT64_FMTx" (%s)", ele_id, ele_name);

	len_ret = get_var_size_int(c->infile, &ele_dlen, &pos);
	if(len_ret==1) {
		de_snprintf(tmpbuf, sizeof(tmpbuf), "%"INT64_FMT, ele_dlen);
	}
	else if(len_ret==2) {
		ele_dlen = c->infile->len - pos;
		de_strlcpy(tmpbuf, "unknown", sizeof(tmpbuf));
	}
	else {
		de_err(c, "Failed to read length of element at %"INT64_FMT, pos1);
		goto done;
	}
	de_dbg(c, "element data at %"INT64_FMT", dlen=%s", pos, tmpbuf);

	if(len_ret==2) {
		// EBML does not have any sort of end-of-master-element marker, which
		// presents a problem when a master element has an unknown length.
		//
		// EBML's "solution" is this:
		// "The end of an Unknown-Sized Element is determined by whichever
		// comes first: the end of the file or the beginning of the next EBML
		// Element, defined by this document or the corresponding EBML Schema,
		// that is not independently valid as Descendant Element of the
		// Unknown-Sized Element."
		//
		// This would appear to require a sophisticated, high-level algorithm
		// with 100% complete knowledge of the latest version of the specific
		// application format. We do not have such an algorithm.

		de_err(c, "EBML files with unknown-length elements are not supported");
		goto done;
	}

	if(pos + ele_dlen > c->infile->len) {
		de_err(c, "Element at %"INT64_FMT" goes beyond end of file", pos1);
		goto done;
	}

	should_decode = 1;
	if(einfo) {
		dtype = einfo->flags & 0xff;
		if((einfo->flags & 0x0100) && c->debug_level<2) {
			should_decode = 0;
		}
	}

	if(should_decode && einfo && einfo->hfn) {
		struct handler_params hp;
		hp.dpos = pos;
		hp.dlen = ele_dlen;
		einfo->hfn(c, d, &hp);
	}
	else if(should_decode) {
		switch(dtype) {
		case TY_m:
			do_element_sequence(c, d, pos, ele_dlen);
			break;
		case TY_u:
			decode_int(c, d, einfo, pos, ele_dlen);
			break;
		case TY_f:
			decode_float(c, d, einfo, pos, ele_dlen);
			break;
		case TY_8:
			decode_string(c, d, einfo, pos, ele_dlen, DE_ENCODING_UTF8);
			break;
		case TY_s:
			decode_string(c, d, einfo, pos, ele_dlen, DE_ENCODING_PRINTABLEASCII);
			break;
		case TY_d:
			decode_date(c, d, einfo, pos, ele_dlen);
			break;
		}
	}
	else {
		de_dbg(c, "[not decoding this element]");
	}

	pos += ele_dlen;

	*bytes_used = pos - pos1;
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_element_sequence(deark *c, lctx *d, de_int64 pos1, de_int64 len)
{
	int ret;
	int retval = 0;
	de_int64 pos = pos1;
	int saved_indent_level;

	// TODO:
	// From the EBML spec:
	// "data that is not part of an EBML Element is permitted to be present
	// within a Master Element if unknownsizeallowed is enabled within the
	// definition for that Master Element. In this case, the EBML Reader
	// should skip data until a valid Element ID of the same EBMLParentPath or
	// the next upper level Element Path of the Master Element is found."
	//
	// We do not support this. We can't even detect it, so our parser will go
	// off the rails. How do you even support it efficiently? What kind of
	// psychopath designs a format like this? It's incredibly fragile (a new
	// format version that defines a new optional element will completely
	// break backward compatibility), and its abstractions are leaking all
	// over the place.

	d->level++;
	de_dbg_indent_save(c, &saved_indent_level);
	if(d->level > 16) goto done;
	if(len==0) { retval = 1; goto done; }

	de_dbg(c, "element sequence at %"INT64_FMT", max_len=%"INT64_FMT, pos1, len);
	de_dbg_indent(c, 1);

	while(1) {
		de_int64 ele_len = 0;
		if(pos >= pos1+len) {
			break;
		}
		ret = do_element(c, d, pos, pos1+len-pos, &ele_len);
		if(!ret) goto done;
		if(ele_len<1) goto done;

		pos += ele_len;
	}
	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	d->level--;
	return retval;
}

static void de_run_ebml(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));
	de_msg(c, "Note: EBML files can be parsed, but no files can be extracted from them.");

	pos = 0;
	do_element_sequence(c, d, pos, c->infile->len);

	de_free(c, d);
}

static int de_identify_ebml(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1a\x45\xdf\xa3", 4))
		return 100;
	return 0;
}

void de_module_ebml(deark *c, struct deark_module_info *mi)
{
	mi->id = "ebml";
	mi->desc = "EBML";
	mi->run_fn = de_run_ebml;
	mi->identify_fn = de_identify_ebml;
}
