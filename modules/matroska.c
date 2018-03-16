// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// EBML, Matroska, MKV

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_ebml);

typedef struct localctx_struct {
	int reserved;
} lctx;

struct ele_id_info {
	// flags:
	//  0x01 = contains other elements
	unsigned int flags;
	de_int64 ele_id;
	const char *name;
	void *hfn;
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

static const struct ele_id_info ele_id_info_arr[] = {
	// Note that the Matroska spec may conflate encoded IDs with decoded IDs.
	// This table lists decoded IDs. Encoded IDs have an extra 1 bit in a
	// position that makes it more significant than any of the other 1 bits.
	{0x00, 0x3, "TrackType", NULL},
	{0x00, 0x6, "CodecID", NULL},
	{0x00, 0x8, "FlagDefault", NULL},
	{0x00, 0x1b, "BlockDuration", NULL},
	{0x00, 0x1c, "FlagLacing", NULL},
	{0x01, 0x20, "BlockGroup", NULL},
	{0x00, 0x21, "Block", NULL},
	{0x00, 0x2a, "CodecDecodeAll", NULL},
	{0x01, 0x2e, "TrackEntry", NULL},
	{0x00, 0x33, "CueTime", NULL},
	{0x01, 0x37, "CueTrackPositions", NULL},
	{0x00, 0x39, "FlagEnabled", NULL},
	{0x01, 0x3b, "CuePoint", NULL},
	{0x00, 0x57, "TrackNumber", NULL},
	{0x00, 0x60, "Video", NULL},
	{0x00, 0x61, "Audio", NULL},
	{0x00, 0x67, "Timecode", NULL},
	{0x00, 0x6c, "Void", NULL},
	{0x00, 0x71, "CueClusterPosition", NULL},
	{0x00, 0x77, "CueTrack", NULL},
	{0x00, 0x7b, "ReferenceBlock", NULL},
	{0x00, 0x282, "DocType", NULL},
	{0x00, 0x285, "DocTypeReadVersion", NULL},
	{0x00, 0x286, "EBMLVersion", NULL},
	{0x00, 0x287, "DocTypeVersion", NULL},
	{0x00, 0x2f2, "EBMLMaxIDLength", NULL},
	{0x00, 0x2f3, "EBMLMaxSizeLength", NULL},
	{0x00, 0x2f7, "EBMLReadVersion", NULL},
	{0x00, 0x461, "DateUTC", NULL},
	{0x00, 0x489, "Duration", NULL},
	{0x00, 0xd80, "MuxingApp", NULL},
	{0x00, 0x136e, "Name", NULL},
	{0x00, 0x15aa, "FlagForced", NULL},
	{0x00, 0x15ee, "MaxBlockAdditionID", NULL},
	{0x00, 0x1741, "WritingApp", NULL},
	{0x00, 0x23a2, "CodecPrivate", NULL},
	{0x00, 0x2de7, "MinCache", NULL},
	{0x00, 0x33a4, "SegmentUID", NULL},
	{0x00, 0x33c5, "TrackUID", NULL},
	{0x00, 0x2b59c, "Language", NULL},
	{0x00, 0x3314f, "TrackTimecodeScale (deprecated)", NULL},
	{0x00, 0x3e383, "DefaultDuration", NULL},
	{0x00, 0xad7b1, "TimecodeScale", NULL},
	{0x00, 0x14d9b74, "SeekHead", NULL},
	{0x01, 0x549a966, "Info", NULL},
	{0x01, 0x654ae6b, "Tracks", NULL},
	{0x01, 0x8538067, "Segment", NULL},
	{0x01, 0xa45dfa3, "Header", NULL},
	{0x01, 0xc53bb6b, "Cues", NULL},
	{0x01, 0xf43b675, "Cluster", NULL}
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

	if(1!=get_var_size_int(c->infile, &ele_dlen, &pos)) {
		de_err(c, "Failed to read length of element at %"INT64_FMT, pos1);
		goto done;
	}
	de_dbg(c, "element data at %"INT64_FMT", dlen=%"INT64_FMT, pos, ele_dlen);
	// TODO: Validate ele_len

	if(einfo && (einfo->flags&0x01)) {
		int ret;
		ret = do_element_sequence(c, d, pos, ele_dlen);
		if(!ret) goto done;
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

	de_dbg_indent_save(c, &saved_indent_level);
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
	return retval;
}

static void de_run_ebml(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

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
	mi->flags |= DE_MODFLAG_NONWORKING;
}
