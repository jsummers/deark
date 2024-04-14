// This file is part of Deark.
// Copyright (C) 2024 Jason Summers
// See the file COPYING for terms of use.

// RIFF Multimedia Movie / RMMP / .MMM

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_mmm);

#define CODE_RIFF  0x52494646U
#define CODE_RMMP  0x524d4d50U
#define CODE_DIB   0x44494220U
#define CODE_dib   0x64696220U
#define CODE_CLUT  0x434c5554U
#define CODE_clut  0x636c7574U
#define CODE_Ver_  0x5665722eU // "Ver."
#define CODE_ver   0x76657220U // "ver "

struct mmm_ctx {
	u8 errflag;
	u8 opt_allowbad;
	int clut_count;
	int dib_count;
	int pass;
	u8 have_pal;
	u8 force_pal;
	UI pal_id_to_use;
	de_ucstring *tmpstr;
	de_color pal1[2];
	de_color pal[256];
};

static void mmm_default_pal256(deark *c, struct mmm_ctx *d)
{
	UI i, j, k;
	static const u8 v[6] = {0, 48, 100, 152, 204, 252};

	de_warn(c, "Using a default palette. Colors might be wrong.");

	// Note: This sets pal[40] incorrectly, but it will be fixed later.
	for(i=0; i<6; i++) {
		for(j=0; j<6; j++) {
			for(k=0; k<6; k++) {
				d->pal[40 + i*36 + j*6 + k] = DE_MAKE_RGB(v[i], v[j], v[k]);
			}
		}
	}

	for(i=0; i<=10; i++) {
		d->pal[i] = DE_MAKE_GRAY(i*24);
	}

	for(i=0; i<10; i++) {
		UI t;

		t = 16+24*i;
		if(t>=128) t += 4;
		d->pal[11+i] = DE_MAKE_RGB(0, 0, t);
		d->pal[21+i] = DE_MAKE_RGB(0, t, 0);
		d->pal[31+i] = DE_MAKE_RGB(t, 0, 0);
	}

	d->have_pal = 1;
}

static void mmm_allowbad_note(deark *c)
{
	de_info(c, "Note: Use \"-opt mmm:allowbad\" to extract anyway.");
}

static void mmm_default_pal16(deark *c, struct mmm_ctx *d)
{
	de_make_grayscale_palette(d->pal, 16, 0);
	d->have_pal = 1;

	// TODO: Figure out if there is a default 16-color palette.
	if(d->opt_allowbad) {
		de_warn(c, "No palette found. Colors will be wrong.");
	}
	else {
		de_err(c, "No palette found");
		mmm_allowbad_note(c);
		d->errflag = 1;
	}
}

static void mmm_read_name_p(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 *ppos)
{
	i64 pos = *ppos;
	i64 namelen;

	namelen = (i64)dbuf_getbyte(ictx->f, pos);
	if(namelen) {
		ucstring_empty(d->tmpstr);
		dbuf_read_to_ucstring(ictx->f, pos+1, namelen, d->tmpstr, 0, DE_ENCODING_ASCII);
		de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(d->tmpstr));
	}
	*ppos += de_pad_to_2(1+namelen);
}

static void hexdump_chunk(deark *c, struct de_iffctx *ictx, const char *name, UI flags)
{
	de_dbg_hexdump(c, ictx->f, ictx->chunkctx->dpos, ictx->chunkctx->dlen,
		256, name, flags);
}

static void do_mmm_dib(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx, i64 pos1, i64 len)
{
	i64 pos;
	i64 i_infohdr_pos;
	i64 i_bits_pos;
	i64 infosize;
	i64 i_bits_size;
	i64 o_bits_size;
	i64 i_rowspan;
	i64 k;
	i64 j;
	UI seqnum;
	u8 special_1bpp = 0;
	int ret;
	dbuf *outf = NULL;
	struct de_bmpinfo bi;

	pos = pos1;
	seqnum = (UI)dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "dib id: %u", seqnum);
	pos += 2;
	mmm_read_name_p(c, d, ictx, &pos);
	i_infohdr_pos = pos;

	infosize = dbuf_getu32le(ictx->f, i_infohdr_pos);
	if(infosize<40 || infosize>124) goto done;
	i_bits_pos = i_infohdr_pos + infosize;
	i_bits_size = pos+len-i_bits_pos;

	ret = fmtutil_get_bmpinfo(c, ictx->f, &bi, i_infohdr_pos, infosize, 0);
	if(!ret) goto done;
	if(bi.num_colors > 256) goto done;

	if(bi.bitcount==1) {
		special_1bpp = 1;
	}

	if(special_1bpp) {
		i_rowspan = de_pad_to_n(bi.bitcount*bi.width, 16) / 8;
	}
	else {
		i_rowspan = bi.rowspan;
	}

	if(bi.compression_field==0) {
		o_bits_size = bi.foreground_size;
	}
	else {
		o_bits_size = i_bits_size;
	}

	// color table
	if(bi.bitcount==4 && !d->have_pal) {
		mmm_default_pal16(c, d);
	}
	if(bi.bitcount==8 && !d->have_pal) {
		mmm_default_pal256(c, d);
	}
	if(d->errflag) goto done;

	outf = dbuf_create_output_file(c, "bmp", NULL, 0);

	// file header
	fmtutil_generate_bmpfileheader(c, outf, &bi,
		14 + infosize + bi.num_colors*4 + o_bits_size);

	// info header
	dbuf_copy(ictx->f, i_infohdr_pos, 20, outf);
	if(special_1bpp) {
		// She biSizeImage field may be wrong, so zero it out.
		dbuf_write_zeroes(outf, 4);
	}
	else {
		dbuf_copy(ictx->f, i_infohdr_pos+20, 4, outf);
	}
	dbuf_copy(ictx->f, i_infohdr_pos+24, infosize-24, outf);

	// color table

	if(bi.bitcount==1) {
		for(k=0; k<2; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal1[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal1[k]));
			dbuf_writebyte(outf, 0);
		}
	}
	else if(bi.bitcount<=8) {
		if(bi.num_colors>256) goto done;
		for(k=0; k<bi.num_colors; k++) {
			dbuf_writebyte(outf, DE_COLOR_B(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_G(d->pal[k]));
			dbuf_writebyte(outf, DE_COLOR_R(d->pal[k]));
			dbuf_writebyte(outf, 0);
		}
	}

	// bits
	if(special_1bpp) {
		for(j=0; j<bi.height; j++) {
			dbuf_copy(ictx->f, i_bits_pos+(bi.height-1-j)*i_rowspan, bi.rowspan, outf);
		}
	}
	else {
		dbuf_copy(ictx->f, i_bits_pos, i_bits_size, outf);
	}

done:
	dbuf_close(outf);
}

static void do_mmm_clut(deark *c, struct mmm_ctx *d, struct de_iffctx *ictx,
	i64 pos1, i64 len)
{
	i64 pos;
	i64 num_entries;
	i64 i;
	UI seqnum;
	u8 keep_this_pal = 0;

	pos = pos1;
	seqnum = (UI)dbuf_getu16le_p(ictx->f, &pos);
	de_dbg(c, "pal id: %u", seqnum);
	pos += 2;
	mmm_read_name_p(c, d, ictx, &pos);

	num_entries = (pos1+len-pos)/6;

	de_dbg(c, "palette at %"I64_FMT", %u entries", pos, (UI)num_entries);

	if(num_entries!=16 && num_entries!=256) {
		de_warn(c, "Unsupported type of palette");
		goto done;
	}

	if(!d->have_pal) {
		if(d->force_pal) {
			if(seqnum == d->pal_id_to_use) {
				keep_this_pal = 1;
			}
		}
		else {
			keep_this_pal = 1;
		}
	}

	// TODO: This probably won't work. We should index the clut chunks, and read
	// them later.
	de_dbg_indent(c, 1);
	for(i=0; i<num_entries; i++) {
		UI samp[3];
		de_color clr;
		i64 idx;
		UI k;

		idx = num_entries-1-i;

		for(k=0; k<3; k++) {
			samp[k] = (UI)dbuf_getu16be_p(ictx->f, &pos);
			samp[k] = (UI)de_sample_nbit_to_8bit(16, samp[k]);
		}
		clr = DE_MAKE_RGB(samp[0], samp[1], samp[2]);
		de_dbg_pal_entry(c, idx, clr);

		if(keep_this_pal) {
			d->pal[idx] = clr;
		}
	}
	de_dbg_indent(c, -1);
	if(keep_this_pal) {
		d->have_pal = 1;
	}

done:
	d->clut_count++;
}

static int my_mmm_chunk_handler(struct de_iffctx *ictx)
{
	deark *c = ictx->c;
	struct mmm_ctx *d = (struct mmm_ctx*)ictx->userdata;
	i64 dpos, dlen;

	dpos = ictx->chunkctx->dpos;
	dlen = ictx->chunkctx->dlen;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_RIFF:
		ictx->is_std_container = 1;
		goto done;
	}

	if(ictx->level != 1) goto done;

	ictx->handled = 1;

	switch(ictx->chunkctx->chunk4cc.id) {
	case CODE_Ver_:
	case CODE_ver:
		if(d->pass==1) {
			hexdump_chunk(c, ictx, "verdata", 0);
		}
		break;
	case CODE_CLUT:
	case CODE_clut:
		if(d->pass==1) {
			do_mmm_clut(c, d, ictx, dpos, dlen);
		}
		break;
	case CODE_DIB:
	case CODE_dib:
		if(d->pass==1) {
			d->dib_count++;
		}
		else {
			do_mmm_dib(c, d, ictx, dpos, dlen);
		}
		break;
	default:
		if(d->pass==1) {
			ictx->handled = 0;
		}
	}

done:
	if(d->errflag) return 0;
	return 1;
}

static int my_mmm_handle_nonchunk_data_fn(struct de_iffctx *ictx,
	i64 pos, i64 *plen)
{
	u8 x;

	x = dbuf_getbyte(ictx->f, pos);
	if(x==0) {
		*plen = 2;
		de_dbg(ictx->c, "[%"I64_FMT" non-RIFF bytes at %"I64_FMT"]", *plen, pos);
		return 1;
	}

	return 0;
}

static void de_run_mmm(deark *c, de_module_params *mparams)
{
	struct mmm_ctx *d = NULL;
	struct de_iffctx *ictx = NULL;
	const char *s;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	d = de_malloc(c, sizeof(struct mmm_ctx));
	d->opt_allowbad = (u8)de_get_ext_option_bool(c, "mmm:allowbad", 0);
	s = de_get_ext_option(c, "mmm:palid");
	if(s) {
		d->pal_id_to_use = (UI)de_atoi(s);
		d->force_pal = 1;
	}

	d->tmpstr = ucstring_create(c);

	ictx = fmtutil_create_iff_decoder(c);
	ictx->userdata = (void*)d;
	ictx->is_le = 1;
	ictx->handle_chunk_fn = my_mmm_chunk_handler;
	ictx->handle_nonchunk_data_fn = my_mmm_handle_nonchunk_data_fn;
	ictx->f = c->infile;

	d->pal1[0] = DE_STOCKCOLOR_BLACK;
	d->pal1[1] = DE_STOCKCOLOR_WHITE;

	d->pass = 1;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);
	if(d->errflag) goto done;

	if(d->force_pal && !d->have_pal && !d->opt_allowbad) {
		de_err(c, "Palette %u not found", d->pal_id_to_use);
		goto done;
	}

	if(d->clut_count>1 && d->dib_count>0 && !d->opt_allowbad && !d->force_pal) {
		de_err(c, "Multiple palettes found (not supported, "
			"or try \"-opt mmm:palid=...\").");
		mmm_allowbad_note(c);
		goto done;
	}

	d->pass = 2;
	de_dbg(c, "pass %d", d->pass);
	de_dbg_indent(c, 1);
	fmtutil_read_iff_format(ictx, 0, c->infile->len);
	de_dbg_indent(c, -1);

done:
	fmtutil_destroy_iff_decoder(ictx);
	if(d) {
		de_dbg(c, "dib count: %d", d->dib_count);
		de_dbg(c, "clut count: %d", d->clut_count);
		ucstring_destroy(d->tmpstr);
		de_free(c, d);
	}
	de_dbg_indent_restore(c, saved_indent_level);
}

static int de_identify_mmm(deark *c)
{
	if((u32)de_getu32be(0)!=CODE_RIFF) return 0;
	if((u32)de_getu32be(8)!=CODE_RMMP) return 0;
	return 100;
}

static void de_help_mmm(deark *c)
{
	de_msg(c, "-opt mmm:palid=<id> : Use this palette");
}

void de_module_mmm(deark *c, struct deark_module_info *mi)
{
	mi->id = "mmm";
	mi->desc = "RIFF Multimedia Movie";
	mi->run_fn = de_run_mmm;
	mi->identify_fn = de_identify_mmm;
	mi->help_fn = de_help_mmm;
	// Status: Many images work correctly. Others have the wrong colors.
	// Improvements are probably possible, but only up to a point. This
	// is just a resource format; the correct color table might, for
	// example, be in a different file.
	mi->flags |= DE_MODFLAG_NONWORKING;
}
