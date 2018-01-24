// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Windows Write (.wri) format

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_wri);

struct para_info {
	de_int64 thisparapos, thisparalen;
	de_int64 bfprop_offset; // file-level offset
	de_byte papflags;
};

typedef struct localctx_struct {
	int extract_text;
	int input_encoding;
	de_int64 fcMac;
	de_int64 pnChar;
	de_int64 pnChar_offs;
	de_int64 pnPara;
	de_int64 pnPara_offs;
	de_int64 pnPara_npages;
	de_int64 pnFntb, pnSep, pnSetb, pnPgtb, pnFfntb;
	de_int64 pnMac;
	dbuf *html_outf;
} lctx;

static int do_header(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);

	d->fcMac = de_getui32le(pos+7*2);
	de_dbg(c, "fcMac: %d", (int)d->fcMac);
	d->pnChar = (d->fcMac + 127) / 128;
	d->pnChar_offs = d->pnChar * 128;
	de_dbg(c, "pnChar: page %d (offset %d)", (int)d->pnChar, (int)d->pnChar_offs);

	d->pnPara = de_getui16le(pos+9*2);
	d->pnPara_offs = d->pnPara * 128;
	de_dbg(c, "pnPara: page %d (offset %d)", (int)d->pnPara, (int)d->pnPara_offs);

	d->pnFntb = de_getui16le(pos+10*2);
	de_dbg(c, "pnFntb: page %d", (int)d->pnFntb);

	d->pnSep = de_getui16le(pos+11*2);
	de_dbg(c, "pnSep: page %d", (int)d->pnSep);

	d->pnSetb = de_getui16le(pos+12*2);
	de_dbg(c, "pnSetb: page %d", (int)d->pnSetb);

	d->pnPgtb = de_getui16le(pos+13*2);
	de_dbg(c, "pnPgtb: page %d", (int)d->pnPgtb);

	d->pnFfntb = de_getui16le(pos+14*2);
	de_dbg(c, "pnFfntb: page %d", (int)d->pnFfntb);

	d->pnMac = de_getui16le(pos+48*2);
	de_dbg(c, "pnMac: %d pages", (int)d->pnMac);

	d->pnPara_npages = d->pnFntb - d->pnPara;

	de_dbg_indent(c, -1);
	return 1;
}

static void do_picture_metafile(deark *c, lctx *d, struct para_info *pinfo)
{
	de_int64 pos = pinfo->thisparapos;
	de_int64 cbHeader, cbSize;

	cbHeader = de_getui16le(pos+30);
	de_dbg(c, "cbHeader: %d", (int)cbHeader);

	cbSize = de_getui32le(pos+32);
	de_dbg(c, "cbSize: %d", (int)cbSize);

	if(cbHeader+cbSize <= pinfo->thisparalen) {
		dbuf_create_file_from_slice(c->infile, pos+cbHeader, cbSize, "wmf", NULL, 0);
	}
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

static const char *get_picture_storage_type_name(unsigned int t)
{
	const char *name;
	switch(t) {
	case 0x88: name="metafile"; break;
	case 0xe3: name="bitmap"; break;
	case 0xe4: name="OLE object"; break;
	default: name="?"; break;
	}
	return name;
}

static int do_picture_ole_static_rendition(deark *c, lctx *d, struct para_info *pinfo,
	int rendition_idx, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_int64 stringlen;
	struct de_stringreaderdata *srd_typename = NULL;

	pos += 4; // 0x00000501
	pos += 4; // "type" (probably already read by caller)

	stringlen = de_getui32le(pos);
	pos += 4;
	srd_typename = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "typename: \"%s\"", ucstring_get_printable_sz(srd_typename->str));
	pos += stringlen;

	if(!de_strcmp((const char*)srd_typename->sz, "DIB")) {
		struct de_bmpinfo bi;
		dbuf *outf = NULL;

		pos += 12;
		if(!de_fmtutil_get_bmpinfo(c, c->infile, &bi, pos,
			pinfo->thisparapos+pinfo->thisparalen-pos, 0))
		{
			goto done;
		}

		outf = dbuf_create_output_file(c, "bmp", NULL, 0);
		de_fmtutil_generate_bmpfileheader(c, outf, &bi, 0);
		dbuf_copy(c->infile, pos, bi.total_size, outf);

		dbuf_close(outf);
	}
	else {
		// TODO: "BITMAP"
		// TODO: "METAFILEPICT"
		de_warn(c, "Static OLE picture type \"%s\" is not supported",
			ucstring_get_printable_sz(srd_typename->str));
	}

done:
	de_destroy_stringreaderdata(c, srd_typename);
	return 0;
}

// pos1 points to the ole_id field (should be 0x00000501).
// Caller must have looked ahead to check the type.
static int do_picture_ole_embedded_rendition(deark *c, lctx *d, struct para_info *pinfo,
	int rendition_idx, de_int64 pos1, de_int64 *bytes_consumed)
{
	de_int64 pos = pos1;
	de_int64 stringlen;
	de_int64 data_len;
	struct de_stringreaderdata *srd_typename = NULL;
	struct de_stringreaderdata *srd_filename = NULL;
	struct de_stringreaderdata *srd_params = NULL;

	pos += 4; // 0x00000501
	pos += 4; // "type" (probably already read by caller)

	stringlen = de_getui32le(pos);
	pos += 4;
	srd_typename = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "typename: \"%s\"", ucstring_get_printable_sz(srd_typename->str));
	pos += stringlen;

	stringlen = de_getui32le(pos);
	pos += 4;
	srd_filename = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "filename: \"%s\"", ucstring_get_printable_sz(srd_filename->str));
	pos += stringlen;

	stringlen = de_getui32le(pos);
	pos += 4;
	srd_params = dbuf_read_string(c->infile, pos, stringlen, 260, DE_CONVFLAG_STOP_AT_NUL,
		DE_ENCODING_ASCII);
	de_dbg(c, "params: \"%s\"", ucstring_get_printable_sz(srd_params->str));
	pos += stringlen;

	data_len = de_getui32le(pos);
	pos += 4;
	de_dbg(c, "embedded ole rendition data: pos=%d, len=%d", (int)pos, (int)data_len);

	// TODO: Detect type and true length of data
	dbuf_create_file_from_slice(c->infile, pos, data_len, "bmp", NULL, 0);

	pos += data_len;
	*bytes_consumed = pos - pos1;

	de_destroy_stringreaderdata(c, srd_typename);
	de_destroy_stringreaderdata(c, srd_filename);
	de_destroy_stringreaderdata(c, srd_params);
	return 1;
}

// pos1 points to the ole_id field (should be 0x00000501).
// Returns nonzero if there may be additional renditions.
static int do_picture_ole_rendition(deark *c, lctx *d, struct para_info *pinfo,
	unsigned int objectType,
	int rendition_idx, de_int64 pos1, de_int64 *bytes_consumed)
{
	unsigned int ole_id;
	unsigned int objectType2;
	int retval = 0;

	de_dbg(c, "OLE rendition[%d] at %d", rendition_idx, (int)pos1);
	de_dbg_indent(c, 1);

	ole_id = (unsigned int)de_getui32le(pos1);
	de_dbg(c, "ole id: 0x%08x", ole_id);
	if(ole_id!=0x00000501U) {
		de_err(c, "Unexpected ole_id: 0x%08x", ole_id);
		goto done;
	}

	objectType2 = (unsigned int)de_getui32le(pos1+4);
	de_dbg(c, "type: %u", objectType2);

	if(objectType==1) {
		if(objectType2==3) {
			do_picture_ole_static_rendition(c, d, pinfo, rendition_idx, pos1, bytes_consumed);
		}
	}
	else if(objectType==2) {
		if(objectType2==0) {
			goto done;
		}
		else if(objectType2==2) {
			do_picture_ole_embedded_rendition(c, d, pinfo, rendition_idx, pos1, bytes_consumed);
			retval = 1;
		}
		else if(objectType2==5) { // replacement
			do_picture_ole_static_rendition(c, d, pinfo, rendition_idx, pos1, bytes_consumed);
		}
	}

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_picture_ole(deark *c, lctx *d, struct para_info *pinfo)
{
	unsigned int objectType;
	de_int64 cbHeader, dwDataSize;
	de_int64 pos = pinfo->thisparapos;
	de_int64 nbytes_left;
	de_int64 bytes_consumed = 0;
	int rendition_idx = 0;

	objectType = (unsigned int)de_getui16le(pos+6);
	de_dbg(c, "objectType: %u (%s)", objectType, get_objecttype1_name(objectType));

	dwDataSize = de_getui32le(pos+16);
	de_dbg(c, "dwDataSize: %d", (int)dwDataSize);

	cbHeader = de_getui16le(pos+30);
	de_dbg(c, "cbHeader: %d", (int)cbHeader);

	pos += cbHeader;

	// An "embedded" OLE object contains a sequence of entities that I'll call
	// renditions. The last entity is just an end-of-sequence marker.
	// I'm not sure if there can be more than two renditions (one embedded, and
	// one static "replacement"), or if the order matters.

	while(1) {
		int ret;
		nbytes_left = pinfo->thisparapos + pinfo->thisparalen - pos;
		if(nbytes_left<8) break;

		bytes_consumed = 0;
		ret = do_picture_ole_rendition(c, d, pinfo, objectType, rendition_idx, pos,
			&bytes_consumed);
		if(!ret || bytes_consumed==0) break;
		pos += bytes_consumed;
		rendition_idx++;
	}
}

static void do_picture(deark *c, lctx *d, struct para_info *pinfo)
{
	unsigned int mm;
	de_int64 pos = pinfo->thisparapos;

	if(d->html_outf) {
		dbuf_puts(d->html_outf, "<p><i>[picture]</i></p>\n");
	}

	if(pinfo->thisparalen<2) goto done;
	mm = (unsigned int)de_getui16le(pos);
	de_dbg(c, "picture storage type: 0x%04x (%s)", mm,
		get_picture_storage_type_name(mm));

	switch(mm) {
	case 0x88:
		do_picture_metafile(c, d, pinfo);
		break;
		// todo: 0xe3
	case 0xe4:
		do_picture_ole(c, d, pinfo);
		break;
	default:
		de_err(c, "Picture storage type 0x%04x not supported", mm);
	}

done:
	;
}

static void do_text_paragraph(deark *c, lctx *d, struct para_info *pinfo)
{
	dbuf *f;
	de_int64 i, k;
	int space_count=0;
	int xpos;

	if(!d->html_outf) return;
	f = d->html_outf;

	if((pinfo->papflags & 0x06)!=0) {
		// TODO: Decode headers and footers somehow.
		dbuf_puts(f, "<p><i>[header/footer]</i></p>\n");
		return;
	}

	// The last 2 bytes should always be CR LF, so a length less than 2
	// should be impossible.
	if(pinfo->thisparalen<2) return;

	dbuf_puts(f, "<p>");
	xpos = 3;
	for(i=0; i<pinfo->thisparalen-2; i++) {
		de_byte incp;

		incp = de_getbyte(pinfo->thisparapos+i);

		if(incp!=32 && space_count>0) {
			// Make all spaces but the last one nonbreaking
			for(k=0; k<space_count-1; k++) {
				de_write_codepoint_to_html(c, f, 0xa0);
				xpos++;
			}

			if(xpos>70) {
				// We don't do proper word wrapping of the HTML source, but
				// maybe this is better than nothing.
				dbuf_writebyte(f, 0x0a);
				xpos = 0;
			}
			else {
				dbuf_writebyte(f, 32);
				xpos++;
			}

			space_count=0;
		}

		if(incp>=33) {
			de_int32 outcp;
			outcp = de_char_to_unicode(c, (de_int32)incp, d->input_encoding);
			de_write_codepoint_to_html(c, f, outcp);
			xpos++;
		}
		else {
			switch(incp) {
			case 9: // tab
				dbuf_puts(f, "<span class=c>");
				de_write_codepoint_to_html(c, f, 0x2192);
				dbuf_puts(f, "</span>");
				xpos += 22;
				break;
			case 10:
			case 11:
				dbuf_puts(f, "<br>\n");
				xpos = 0;
				break;
			case 12: // page break
				dbuf_puts(f, "</p>\n<hr>\n<p>");
				xpos = 3;
				break;
			case 31:
				break;
			case 32:
				space_count++;
				break;
			default:
				de_write_codepoint_to_html(c, f, 0xfffd);
				xpos++;
			}
		}
	}
	dbuf_puts(f, "</p>\n");
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

static void do_para_info_page(deark *c, lctx *d, de_int64 pos)
{
	de_int64 fcFirst;
	de_int64 cfod;
	de_int64 i;
	de_int64 fod_array_startpos;
	de_int64 prevtextpos;

	de_dbg(c, "paragraph info page at %d", (int)pos);
	de_dbg_indent(c, 1);

	cfod = (de_int64)de_getbyte(pos+127);
	de_dbg(c, "number of FODs on this page: %d", (int)cfod);

	// There are up to 123 bytes available for the FOD array, and each FOD is
	// 6 bytes. So I assume the maximum possible is 20.
	if(cfod>20) cfod=20;

	fcFirst = de_getui32le(pos);
	de_dbg(c, "fcFirst: %d", (int)fcFirst);

	fod_array_startpos = pos + 4;

	prevtextpos = fcFirst;

	for(i=0; i<cfod; i++) {
		struct para_info *pinfo = NULL;
		de_int64 fcLim;
		de_int64 bfprop;
		de_int64 fodpos = fod_array_startpos + 6*i;

		pinfo = de_malloc(c, sizeof(struct para_info));

		de_dbg(c, "FOD[%d] at %d", (int)i, (int)fodpos);
		de_dbg_indent(c, 1);

		fcLim = de_getui32le(fodpos);
		pinfo->thisparapos = prevtextpos;
		pinfo->thisparalen = fcLim - prevtextpos;
		de_dbg(c, "fcLim: %d (paragraph from %d to %d)", (int)fcLim,
			(int)pinfo->thisparapos, (int)(fcLim-1));
		prevtextpos = fcLim;

		bfprop = de_getui16le(fodpos+4);
		if(bfprop==0xffff) {
			de_dbg(c, "bfprop: %d (none)", (int)bfprop);
		}
		else {
			de_int64 fprop_dlen = 0;

			pinfo->bfprop_offset = fod_array_startpos + bfprop;

			de_dbg(c, "bfprop: %d (+ %d = %d)", (int)bfprop,
				(int)fod_array_startpos, (int)pinfo->bfprop_offset);

			de_dbg_indent(c, 1);
			// bfprop is a pointer into the 123 bytes of data starting
			// at pos+4. The maximum sensible value is at most 122.
			if(bfprop<=122) {
				// It appears that the length prefix does not include itself,
				// contrary to what one source says.
				fprop_dlen = (de_int64)de_getbyte(pinfo->bfprop_offset);
				de_dbg(c, "fprop dlen: %d", (int)fprop_dlen);
			}
			if(fprop_dlen>=17) {
				pinfo->papflags = de_getbyte(pinfo->bfprop_offset + 1 + 16);
				de_dbg(c, "paragraph flags: 0x%02x", (unsigned int)pinfo->papflags);
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
	de_int64 i;

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
	dbuf_puts(f, " .c { color: #ccc }\n"); // Visible control characters
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
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	d->extract_text = 1;
	d->input_encoding = DE_ENCODING_WINDOWS1252;

	pos = 0;
	if(!do_header(c, d, pos)) goto done;
	if(d->extract_text) {
		do_html_begin(c, d);
	}

	do_para_info(c, d);

done:
	do_html_end(c, d);
	de_free(c, d);
}

static int de_identify_wri(deark *c)
{
	de_byte buf[6];
	de_read(buf, 0, 6);

	if((buf[0]==0x31 || buf[0]==0x32) &&
		!de_memcmp(&buf[1], "\xbe\x00\x00\x00\xab", 5))
	{
		de_int64 pnMac;
		pnMac = de_getui16le(48*2);
		if(pnMac==0) return 0; // Apparently MSWord, not Write
		return 100;
	}
	return 0;
}

void de_module_wri(deark *c, struct deark_module_info *mi)
{
	mi->id = "wri";
	mi->desc = "Microsoft Write";
	mi->run_fn = de_run_wri;
	mi->identify_fn = de_identify_wri;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
