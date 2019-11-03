// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Windows Write (.wri) format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wri);

#define WRI_STG_METAFILE  0x88
#define WRI_STG_BITMAP    0xe3
#define WRI_STG_OLE       0xe4

struct picctx_struct {
	unsigned int mm; // WRI_STG_*
	i64 cbHeader;
	i64 cbSize;
	unsigned int ole_objectType;
	i64 ole_dwDataSize;
};

struct text_styles_struct {
	u8 tab_style;
};

struct para_info {
	i64 thisparapos, thisparalen;
	i64 bfprop_offset; // file-level offset
	u8 papflags;
	u8 justification;

	int in_para;
	int xpos; // Current length of this line in the source code
	int has_content; // Have we emitted a non-space char in this paragraph?
	int space_count;

	int in_span;
	struct text_styles_struct text_styles_wanted; // Styles for the next char to be emitted
	struct text_styles_struct text_styles_current; // Effective current styles
};

typedef struct localctx_struct {
	int extract_text;
	int extract_ole;
	int input_encoding;
	i64 fcMac;
	i64 pnChar;
	i64 pnChar_offs;
	i64 pnPara;
	i64 pnPara_offs;
	i64 pnPara_npages;
	i64 pnFntb, pnSep, pnSetb, pnPgtb, pnFfntb;
	i64 pnMac;
	dbuf *html_outf;
	de_ucstring *tmpstr;
} lctx;

static void do_emit_raw_sz(deark *c, lctx *d, struct para_info *pinfo, const char *sz);
static void do_emit_ucstring(deark *c, lctx *d, struct para_info *pinfo,
	de_ucstring *s);
static void end_para(deark *c, lctx *d, struct para_info *pinfo);

static void default_text_styles(struct text_styles_struct *ts)
{
	de_zeromem(ts, sizeof(struct text_styles_struct));
}

static int text_styles_differ(const struct text_styles_struct *ts1,
	const struct text_styles_struct *ts2)
{
	if(ts1->tab_style != ts2->tab_style) return 1;
	return 0;
}

static int do_header(deark *c, lctx *d, i64 pos)
{
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->fcMac = de_getu32le(pos+7*2);
	de_dbg(c, "fcMac: %d", (int)d->fcMac);
	d->pnChar = (d->fcMac + 127) / 128;
	d->pnChar_offs = d->pnChar * 128;
	de_dbg(c, "pnChar: page %d (offset %d)", (int)d->pnChar, (int)d->pnChar_offs);

	d->pnPara = de_getu16le(pos+9*2);
	d->pnPara_offs = d->pnPara * 128;
	de_dbg(c, "pnPara: page %d (offset %d)", (int)d->pnPara, (int)d->pnPara_offs);

	d->pnFntb = de_getu16le(pos+10*2);
	de_dbg(c, "pnFntb: page %d", (int)d->pnFntb);

	d->pnSep = de_getu16le(pos+11*2);
	de_dbg(c, "pnSep: page %d", (int)d->pnSep);

	d->pnSetb = de_getu16le(pos+12*2);
	de_dbg(c, "pnSetb: page %d", (int)d->pnSetb);

	d->pnPgtb = de_getu16le(pos+13*2);
	de_dbg(c, "pnPgtb: page %d", (int)d->pnPgtb);

	d->pnFfntb = de_getu16le(pos+14*2);
	de_dbg(c, "pnFfntb: page %d", (int)d->pnFfntb);

	d->pnMac = de_getu16le(pos+48*2);
	de_dbg(c, "pnMac: %d pages", (int)d->pnMac);

	d->pnPara_npages = d->pnFntb - d->pnPara;

	de_dbg_indent(c, -1);
	return 1;
}

static const char *get_objecttype1_name(unsigned int t)
{
	const char *name;
	switch(t) {
	case 1: name="static"; break;
	case 2: name="embedded"; break;
	case 3: name="link"; break;
	default: name="?"; break;
	}
	return name;
}

// Read the usually-40-byte picture header.
// The header has 3 variants (metafile, bitmap, OLE), which have some common
// fields, and some different fields. So, this function is kind of ugly.
static void do_picture_header(deark *c, lctx *d, struct para_info *pinfo,
	struct picctx_struct *picctx)
{
	i64 pos1 = pinfo->thisparapos;
	i64 pos = pos1;
	i64 n1, n2;

	// (The initial "mm" / "storage type" field has already been read.)

	if(picctx->mm==WRI_STG_METAFILE) {
		pos = pos1+2;
		n1 = de_getu16le_p(&pos);
		n2 = de_getu16le_p(&pos);
		de_dbg(c, "xExt,yExt: %d"DE_CHAR_TIMES"%d twips", (int)n1, (int)n2);
	}

	if(picctx->mm==WRI_STG_OLE) {
		// This field seems important, but we don't use it, because the OLE
		// FormatID field is sufficient.
		picctx->ole_objectType = (unsigned int)de_getu16le(pos1+6);
		de_dbg(c, "objectType: %u (%s)", picctx->ole_objectType,
			get_objecttype1_name(picctx->ole_objectType));
	}

	pos = pos1+8;
	n1 = de_getu16le_p(&pos);
	de_dbg(c, "dxaOffset: %d twips", (int)n1);
	n1 = de_getu16le_p(&pos);
	n2 = de_getu16le_p(&pos);
	de_dbg(c, "dxaSize,dyaSize: %d"DE_CHAR_TIMES"%d twips", (int)n1, (int)n2);

	if(picctx->mm==WRI_STG_BITMAP) {
		de_dbg(c, "[DDB header at %"I64_FMT"]", pos1+16);
	}

	if(picctx->mm==WRI_STG_OLE) {
		picctx->ole_dwDataSize = de_getu32le(pos1+16);
		de_dbg(c, "dwDataSize: %d", (int)picctx->ole_dwDataSize);
		n1 = de_getu32le(pos1+24);
		de_dbg(c, "dwObjNum: 0x%08x", (unsigned int)n1);
	}

	picctx->cbHeader = de_getu16le(pos1+30);
	de_dbg(c, "header size: %d", (int)picctx->cbHeader);

	if(picctx->mm==WRI_STG_METAFILE || picctx->mm==WRI_STG_BITMAP) {
		picctx->cbSize = de_getu32le(pos1+32);
		de_dbg(c, "data size: %d", (int)picctx->cbSize);
	}

	pos = pos1+36;
	n1 = de_getu16le_p(&pos);
	n2 = de_getu16le_p(&pos);
	de_dbg(c, "scaling factor x,y: %d,%d", (int)n1, (int)n2);
}

static void do_picture_metafile(deark *c, lctx *d, struct para_info *pinfo,
	struct picctx_struct *picctx)
{
	i64 pos = pinfo->thisparapos;

	if(picctx->cbHeader+picctx->cbSize > pinfo->thisparalen) goto done;
	de_dbg(c, "metafile data at %"I64_FMT, pos+picctx->cbHeader);
	dbuf_create_file_from_slice(c->infile, pos+picctx->cbHeader, picctx->cbSize,
		"wmf", NULL, 0);
done:
	;
}

static void do_picture_bitmap(deark *c, lctx *d, struct para_info *pinfo,
	struct picctx_struct *picctx)
{
	i64 hdrpos, bitspos;
	i64 bitssize;
	dbuf *tmpf = NULL;

	if(picctx->cbHeader + picctx->cbSize > pinfo->thisparalen) goto done;
	hdrpos = pinfo->thisparapos + 16;
	bitspos = pinfo->thisparapos + picctx->cbHeader;
	bitssize = picctx->cbSize;
	de_dbg(c, "processing DDB, header at %"I64_FMT", pixels at %"I64_FMT,
		hdrpos, bitspos);

	// Most commonly, the DDB bits immediately follow the header. But in this
	// format, they are separated, with some non-DDB data in between.
	// We'll construct a temporary DDB, in which they are contiguous, to pass
	// to the ddb module.
	tmpf = dbuf_create_membuf(c, 14+bitssize, 0);
	dbuf_copy(c->infile, hdrpos, 14, tmpf);
	dbuf_copy(c->infile, bitspos, bitssize, tmpf);

	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice2(c, "ddb", "N", tmpf, 0, tmpf->len);
	de_dbg_indent(c, -1);

done:
	dbuf_close(tmpf);
}

static const char *get_picture_storage_type_name(unsigned int t)
{
	const char *name;
	switch(t) {
	case WRI_STG_METAFILE: name="metafile"; break;
	case WRI_STG_BITMAP: name="bitmap"; break;
	case WRI_STG_OLE: name="OLE object"; break;
	default: name="?"; break;
	}
	return name;
}

static void do_picture_ole(deark *c, lctx *d, struct para_info *pinfo,
	struct picctx_struct *picctx)
{
	i64 pos = pinfo->thisparapos;
	i64 ole_len;
	de_module_params *mparams = NULL;

	pos += picctx->cbHeader;

	mparams = de_malloc(c, sizeof(de_module_params));
	mparams->in_params.input_encoding = d->input_encoding;

	ole_len = de_min_int(picctx->ole_dwDataSize, pinfo->thisparapos+pinfo->thisparalen-pos);
	de_dbg(c, "OLE1 data at %"I64_FMT", len=%"I64_FMT, pos, ole_len);
	de_dbg_indent(c, 1);
	de_run_module_by_id_on_slice(c, "ole1", mparams, c->infile, pos, ole_len);
	de_dbg_indent(c, -1);

	de_free(c, mparams);
}

static int get_next_output_file_id(deark *c)
{
	return c->file_count;
}

static void do_picture(deark *c, lctx *d, struct para_info *pinfo)
{
	int orig_file_count, curr_file_count;
	struct picctx_struct *picctx = NULL;
	i64 pos = pinfo->thisparapos;

	picctx = de_malloc(c, sizeof(struct picctx_struct));
	if(pinfo->thisparalen<2) goto done;
	picctx->mm = (unsigned int)de_getu16le(pos);
	de_dbg(c, "picture storage type: 0x%04x (%s)", picctx->mm,
		get_picture_storage_type_name(picctx->mm));

	orig_file_count = get_next_output_file_id(c);

	do_picture_header(c, d, pinfo, picctx);

	switch(picctx->mm) {
	case WRI_STG_METAFILE:
		do_picture_metafile(c, d, pinfo, picctx);
		break;
	case WRI_STG_BITMAP:
		do_picture_bitmap(c, d, pinfo, picctx);
		break;
	case WRI_STG_OLE:
		do_picture_ole(c, d, pinfo, picctx);
		break;
	default:
		de_err(c, "Picture storage type 0x%04x not supported", picctx->mm);
	}

	if(d->html_outf) {
		// We want to include the image file ID numbers in the HTML document,
		// so that the user can figure out which image goes where.
		// To deduce the ID number, we watch the global file ID counter.
		// It's totally a hack, but unfortunately our high level functions that
		// create an output file (e.g. de_convert_and_write_image_bilevel) do
		// not have a way return the ID number of the file they created. It
		// would be a lot of trouble to create such a mechanism.

		do_emit_raw_sz(c, d, pinfo, "<p class=r>");
		pinfo->in_para = 1;
		ucstring_empty(d->tmpstr);
		ucstring_append_sz(d->tmpstr, "object", DE_ENCODING_LATIN1);

		curr_file_count = get_next_output_file_id(c);
		if(curr_file_count == orig_file_count+1) {
			ucstring_printf(d->tmpstr, DE_ENCODING_LATIN1, " %d", orig_file_count);
		}
		else if(curr_file_count == orig_file_count) {
			ucstring_append_sz(d->tmpstr, " (not extracted)", DE_ENCODING_LATIN1);
		}
		else {
			ucstring_printf(d->tmpstr, DE_ENCODING_UTF8, "s %d" "\xe2\x80\x93" "%d",
				orig_file_count, curr_file_count-1);
		}
		do_emit_ucstring(c, d, pinfo, d->tmpstr);
		end_para(c, d, pinfo);
	}

done:
	de_free(c, picctx);
}

static void ensure_in_para(deark *c, lctx *d, struct para_info *pinfo)
{
	if(pinfo->in_para) return;
	do_emit_raw_sz(c, d, pinfo, "<p");
	switch(pinfo->justification) {
	case 1: do_emit_raw_sz(c, d, pinfo, " class=tc"); break;
	case 2: do_emit_raw_sz(c, d, pinfo, " class=tr"); break;
	case 3: do_emit_raw_sz(c, d, pinfo, " class=tj"); break;
	}
	do_emit_raw_sz(c, d, pinfo, ">");
	pinfo->in_para = 1;
}

// Emit a data codepoint, inside a paragraph.
static void do_emit_codepoint(deark *c, lctx *d, struct para_info *pinfo, i32 outcp)
{
	int styles_changed;

	if(!pinfo->in_para) {
		ensure_in_para(c, d, pinfo);
	}

	styles_changed = text_styles_differ(&pinfo->text_styles_current, &pinfo->text_styles_wanted);

	if(pinfo->in_span && styles_changed) {
		do_emit_raw_sz(c, d, pinfo, "</span>");
		pinfo->in_span = 0;
	}
	if(styles_changed) {
		if(pinfo->text_styles_wanted.tab_style) {
			do_emit_raw_sz(c, d, pinfo, "<span class=c>");
			pinfo->in_span = 1;
		}
		pinfo->text_styles_current = pinfo->text_styles_wanted; // struct copy
	}

	de_write_codepoint_to_html(c, d->html_outf, outcp);

	// FIXME: We'd like to know how many characters (not bytes) were written,
	// but we don't currently have a good way to do that in the case where the
	// codepoint was written as an HTML entity.
	pinfo->xpos++;

	if(outcp!=32) {
		pinfo->has_content = 1;
	}
}

// Same as calling do_emit_codepoint() on each character.
static void do_emit_ucstring(deark *c, lctx *d, struct para_info *pinfo,
	de_ucstring *s)
{
	i64 k;

	if(!s) return;
	for(k=0; k<s->len; k++) {
		do_emit_codepoint(c, d, pinfo, s->str[k]);
	}
}

// Emit a raw string. Does not force a paragraph to be open.
// Updates pinfo->xpos (assumes 1 byte per char).
// For xpos, handles the case where sz ends with a newline, but does not
// handle internal newlines.
static void do_emit_raw_sz(deark *c, lctx *d, struct para_info *pinfo, const char *sz)
{
	size_t sz_len = de_strlen(sz);
	if(sz_len<1) return;
	dbuf_write(d->html_outf, (const u8*)sz, (i64)sz_len);
	if(sz[sz_len-1]=='\n') {
		pinfo->xpos = 0;
	}
	else {
		pinfo->xpos += (int)sz_len;
	}
}

static void end_para(deark *c, lctx *d, struct para_info *pinfo)
{
	if(!pinfo->in_para) return;

	if(pinfo->in_span) {
		do_emit_raw_sz(c, d, pinfo, "</span>");
		pinfo->in_span = 0;
	}

	if(!pinfo->has_content) {
		// No empty paragraphs allowed. HTML will collapse them, but Write does not.
		do_emit_codepoint(c, d, pinfo, 0xa0);
	}
	do_emit_raw_sz(c, d, pinfo, "</p>\n");
	pinfo->in_para = 0;
	default_text_styles(&pinfo->text_styles_current);
}

static void do_text_paragraph(deark *c, lctx *d, struct para_info *pinfo)
{
	i64 i, k;

	if(!d->html_outf) return;

	if((pinfo->papflags & 0x06)!=0) {
		// TODO: Decode headers and footers somehow.
		do_emit_raw_sz(c, d, pinfo, "<p class=r>");
		do_emit_raw_sz(c, d, pinfo, (pinfo->papflags&0x01)?"footer":"header");
		do_emit_raw_sz(c, d, pinfo, " definition</p>\n");
		return;
	}

	pinfo->in_para = 0;
	pinfo->xpos = 0;
	pinfo->space_count = 0;
	pinfo->has_content = 0;
	pinfo->in_span = 0;
	default_text_styles(&pinfo->text_styles_wanted);
	default_text_styles(&pinfo->text_styles_current);

	for(i=0; i<pinfo->thisparalen; i++) {
		u8 incp;

		incp = de_getbyte(pinfo->thisparapos+i);
		if(incp==0x0d && i<pinfo->thisparalen-1) {
			if(de_getbyte(pinfo->thisparapos+i+1)==0x0a) {
				// Found CR-LF combo
				i++;
				ensure_in_para(c, d, pinfo);
				end_para(c, d, pinfo);
				continue;
			}
		}

		if(incp!=32 && pinfo->space_count>0) {
			int nonbreaking_count, breaking_count;

			if(!pinfo->in_para && pinfo->space_count==1) {
				// If the paragraph starts with a single space, make it nonbreaking.
				nonbreaking_count = 1;
				breaking_count = 0;
			}
			else {
				// Else make all spaces but the last one nonbreaking
				nonbreaking_count = pinfo->space_count-1;
				breaking_count = 1;
			}

			ensure_in_para(c, d, pinfo);

			for(k=0; k<nonbreaking_count; k++) {
				do_emit_codepoint(c, d, pinfo, 0xa0);
			}

			if(breaking_count>0) {
				if(pinfo->xpos>70) {
					// We don't do proper word wrapping of the HTML source, but
					// maybe this is better than nothing.
					do_emit_raw_sz(c, d, pinfo, "\n");
				}
				else {
					do_emit_codepoint(c, d, pinfo, 32);
				}
			}

			pinfo->space_count=0;
		}

		if(incp>=33) {
			i32 outcp;
			outcp = de_char_to_unicode(c, (i32)incp, d->input_encoding);
			do_emit_codepoint(c, d, pinfo, outcp);
		}
		else {
			switch(incp) {
			case 9: // tab
				pinfo->text_styles_wanted.tab_style = 1;
				do_emit_codepoint(c, d, pinfo, 0x2192);
				pinfo->text_styles_wanted.tab_style = 0;
				break;
			case 10:
			case 11:
				ensure_in_para(c, d, pinfo);
				do_emit_raw_sz(c, d, pinfo, "<br>\n");
				pinfo->has_content = 1;
				break;
			case 12: // page break
				end_para(c, d, pinfo);
				do_emit_raw_sz(c, d, pinfo, "<hr>\n");
				break;
			case 31:
				break;
			case 32:
				pinfo->space_count++;
				break;
			default:
				do_emit_codepoint(c, d, pinfo, 0xfffd);
			}
		}
	}

	end_para(c, d, pinfo);
}

static void do_paragraph(deark *c, lctx *d, struct para_info *pinfo)
{
	if(pinfo->papflags&0x10) {
		de_dbg(c, "picture at %d, len=%d", (int)pinfo->thisparapos,
			(int)pinfo->thisparalen);
		de_dbg_indent(c, 1);
		do_picture(c, d, pinfo);
		de_dbg_indent(c, -1);
	}
	else {
		de_dbg(c, "text paragraph at %d, len=%d", (int)pinfo->thisparapos,
			(int)pinfo->thisparalen);
		do_text_paragraph(c, d, pinfo);
	}
}

static void do_para_fprop(deark *c, lctx *d, struct para_info *pinfo,
	i64 bfprop, u8 is_dup)
{
	i64 fprop_dlen = 0;

	// bfprop is a pointer into the 123 bytes of data starting
	// at pos+4. The maximum sensible value is at most 122.
	if(bfprop<=122) {
		// It appears that the length prefix does not include itself,
		// contrary to what one source says.
		fprop_dlen = (i64)de_getbyte(pinfo->bfprop_offset);
		if(!is_dup) de_dbg(c, "fprop dlen: %d", (int)fprop_dlen);
	}

	if(fprop_dlen>=2) {
		pinfo->justification = de_getbyte(pinfo->bfprop_offset + 1 + 1) & 0x03;
		if(!is_dup && pinfo->justification!=0) {
			de_dbg(c, "justification: %d", (int)pinfo->justification);
		}
	}

	if(fprop_dlen>=17) {
		pinfo->papflags = de_getbyte(pinfo->bfprop_offset + 1 + 16);
		if(!is_dup) {
			de_ucstring *flagstr = ucstring_create(c);
			if(pinfo->papflags&0x06) {
				ucstring_append_flags_item(flagstr, (pinfo->papflags&0x01)?"footer":"header");
				ucstring_append_flags_item(flagstr, (pinfo->papflags&0x08)?"print on first page":
					"do not print on first page");
			}
			if(pinfo->papflags&0x10) ucstring_append_flags_item(flagstr, "picture");
			de_dbg(c, "paragraph flags: 0x%02x (%s)", (unsigned int)pinfo->papflags,
				ucstring_getpsz(flagstr));
			ucstring_destroy(flagstr);
		}
	}
}

static void do_para_info_page(deark *c, lctx *d, i64 pos)
{
	i64 fcFirst;
	i64 cfod;
	i64 i;
	i64 fod_array_startpos;
	i64 prevtextpos;
	u8 fprop_seen[128];

	de_zeromem(fprop_seen, sizeof(fprop_seen));
	de_dbg(c, "paragraph info page at %d", (int)pos);
	de_dbg_indent(c, 1);

	cfod = (i64)de_getbyte(pos+127);
	de_dbg(c, "number of FODs on this page: %d", (int)cfod);

	// There are up to 123 bytes available for the FOD array, and each FOD is
	// 6 bytes. So I assume the maximum possible is 20.
	if(cfod>20) cfod=20;

	fcFirst = de_getu32le(pos);
	de_dbg(c, "fcFirst: %d", (int)fcFirst);

	fod_array_startpos = pos + 4;

	prevtextpos = fcFirst;

	for(i=0; i<cfod; i++) {
		struct para_info *pinfo = NULL;
		i64 fcLim_orig, fcLim_adj;
		i64 bfprop;
		i64 fodpos = fod_array_startpos + 6*i;

		pinfo = de_malloc(c, sizeof(struct para_info));

		de_dbg(c, "FOD[%d] at %d", (int)i, (int)fodpos);
		de_dbg_indent(c, 1);

		fcLim_orig = de_getu32le(fodpos);
		fcLim_adj = fcLim_orig;
		if(fcLim_adj > d->fcMac) fcLim_adj = d->fcMac;
		pinfo->thisparapos = prevtextpos;
		pinfo->thisparalen = fcLim_adj - prevtextpos;
		de_dbg(c, "fcLim: %d (paragraph from %d to %d)", (int)fcLim_orig,
			(int)pinfo->thisparapos, (int)(fcLim_adj-1));
		prevtextpos = fcLim_adj;

		bfprop = de_getu16le(fodpos+4);
		if(bfprop==0xffff) {
			de_dbg(c, "bfprop: %d (none)", (int)bfprop);
		}
		else {
			pinfo->bfprop_offset = fod_array_startpos + bfprop;

			de_dbg(c, "bfprop: %d (+ %d = %d)", (int)bfprop,
				(int)fod_array_startpos, (int)pinfo->bfprop_offset);

			de_dbg_indent(c, 1);
			if(bfprop<128) {
				if(fprop_seen[bfprop]) {
					// An FPROP can be referenced multiple times. Only print the
					// debug info for it once.
					de_dbg(c, "[already decoded FPROP at %d on this paragraph info page]", (int)bfprop);
				}
				do_para_fprop(c, d, pinfo, bfprop, fprop_seen[bfprop]);
				fprop_seen[bfprop] = 1;
			}
			de_dbg_indent(c, -1);
		}

		do_paragraph(c, d, pinfo);

		de_free(c, pinfo);
		pinfo = NULL;
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static void do_para_info(deark *c, lctx *d)
{
	i64 i;

	if(d->pnPara_npages<1) return;
	de_dbg(c, "paragraph info at %d, len=%d page(s)", (int)d->pnPara_offs, (int)d->pnPara_npages);

	de_dbg_indent(c, 1);
	for(i=0; i<d->pnPara_npages; i++) {
		do_para_info_page(c, d, d->pnPara_offs + 128*i);
	}
	de_dbg_indent(c, -1);
}

static void do_html_begin(deark *c, lctx *d)
{
	dbuf *f;
	if(d->html_outf) return;
	d->html_outf = dbuf_create_output_file(c, "html", NULL, 0);
	f = d->html_outf;
	if(c->write_bom && !c->ascii_html) dbuf_write_uchar_as_utf8(f, 0xfeff);
	dbuf_puts(f, "<!DOCTYPE html>\n");
	dbuf_puts(f, "<html>\n");
	dbuf_puts(f, "<head>\n");
	dbuf_printf(f, "<meta charset=\"%s\">\n", c->ascii_html?"US-ASCII":"UTF-8");
	dbuf_puts(f, "<title></title>\n");

	dbuf_puts(f, "<style type=\"text/css\">\n");
	dbuf_puts(f, " body { color: #000; background-color: #fff }\n");
	dbuf_puts(f, " p { margin-top: 0; margin-bottom: 0 }\n");
	dbuf_puts(f, " .c { color: #ccc }\n"); // Visible control characters

	// Replacement object
	dbuf_puts(f, " .r { padding: 0.5ex; color: #800; background-color: #eee;\n");
	dbuf_puts(f, "  font-style: italic; border: 0.34ex dotted #800 }\n");

	dbuf_puts(f, " .tc { text-align: center }\n");
	dbuf_puts(f, " .tr { text-align: right }\n");
	dbuf_puts(f, " .tj { text-align: justify }\n");
	dbuf_puts(f, "</style>\n");

	dbuf_puts(f, "</head>\n");
	dbuf_puts(f, "<body>\n");
}

static void do_html_end(deark *c, lctx *d)
{
	if(!d->html_outf) return;
	dbuf_puts(d->html_outf, "</body>\n</html>\n");
	dbuf_close(d->html_outf);
	d->html_outf = NULL;
}

static void de_run_wri(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_WINDOWS1252);
	d->extract_text = de_get_ext_option_bool(c, "wri:extracttext", 1);
	d->extract_ole = de_get_ext_option_bool(c, "wri:extractole",
		(c->extract_level>=2)?1:0);

	d->tmpstr = ucstring_create(c);

	pos = 0;
	if(!do_header(c, d, pos)) goto done;
	if(d->extract_text) {
		do_html_begin(c, d);
	}

	do_para_info(c, d);

done:
	if(d) {
		do_html_end(c, d);
		ucstring_destroy(d->tmpstr);
		de_free(c, d);
	}
}

static int de_identify_wri(deark *c)
{
	u8 buf[6];
	de_read(buf, 0, 6);

	if((buf[0]==0x31 || buf[0]==0x32) &&
		!de_memcmp(&buf[1], "\xbe\x00\x00\x00\xab", 5))
	{
		i64 pnMac;
		pnMac = de_getu16le(48*2);
		if(pnMac==0) return 0; // Apparently MSWord, not Write
		return 100;
	}
	return 0;
}

static void de_help_wri(deark *c)
{
	de_msg(c, "-opt wri:extracttext=0 : Do not extract text");
	de_msg(c, "-opt wri:extractole : Extract unidentified OLE objects");
}

void de_module_wri(deark *c, struct deark_module_info *mi)
{
	mi->id = "wri";
	mi->desc = "Microsoft Write";
	mi->run_fn = de_run_wri;
	mi->identify_fn = de_identify_wri;
	mi->help_fn = de_help_wri;
}
