// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Windows Write (.wri) format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_wri);

struct para_info {
	de_int64 thisparapos, thisparalen;
	de_int64 bfprop_offset; // file-level offset
	de_byte papflags;
};

typedef struct localctx_struct {
	de_int64 fcMac;
	de_int64 pnChar;
	de_int64 pnChar_offs;
	de_int64 pnPara;
	de_int64 pnPara_offs;
	de_int64 pnPara_npages;
	de_int64 pnFntb, pnSep, pnSetb, pnPgtb, pnFfntb;
	de_int64 pnMac;
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

static void do_paragraph(deark *c, lctx *d, struct para_info *pinfo)
{
	if(pinfo->papflags&0x10) {
		de_dbg(c, "[image at %d, len=%d]", (int)pinfo->thisparapos,
			(int)pinfo->thisparalen);
	}
	else {
		de_dbg(c, "[text paragraph at %d, len=%d]", (int)pinfo->thisparapos,
			(int)pinfo->thisparalen);
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

static void de_run_wri(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	de_int64 pos;

	d = de_malloc(c, sizeof(lctx));

	pos = 0;
	if(!do_header(c, d, pos)) goto done;
	do_para_info(c, d);

done:
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
