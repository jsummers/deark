// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// STOS Memory Bank (MBK)

#include <deark-config.h>
#include <deark-modules.h>

typedef struct localctx_struct {
	de_int64 banknum;
	de_byte banktype;
	de_int64 banksize;
	de_uint32 data_bank_id;
} lctx;

#define SPRITERES_L 0
#define SPRITERES_M 1
#define SPRITERES_H 2
static const char* sprite_res_name[3] = { "low", "med", "high" };

static void do_sprite_param_block(deark *c, lctx *d, de_int64 res,
	de_int64 sprite_index, de_int64 pos)
{
	de_int64 sprite_data_offs;
	de_int64 width_raw;
	de_int64 height;

	de_dbg(c, "%s-res sprite #%d param block at %d\n", sprite_res_name[res],
		(int)sprite_index, (int)pos);
	de_dbg_indent(c, 1);
	sprite_data_offs = de_getui32be(pos);
	de_dbg(c, "sprite data offset: %d\n", (int)sprite_data_offs);
	width_raw = (de_int64)de_getbyte(pos+4);
	de_dbg(c, "width: %d unit(s) of 16\n", (int)width_raw);
	height = (de_int64)de_getbyte(pos+5);
	de_dbg(c, "height: %d pixels\n", (int)height);
	de_dbg_indent(c, -1);
}

static void do_sprite_param_blocks(deark *c, lctx *d, de_int64 res,
	de_int64 nsprites, de_int64 pos)
{
	de_int64 k;
	de_dbg(c, "%s-res sprite param blocks at %d\n", sprite_res_name[res],
		(int)pos);

	de_dbg_indent(c, 1);
	for(k=0; k<nsprites; k++) {
		do_sprite_param_block(c, d, res, k, pos + 8*k);
	}
	de_dbg_indent(c, -1);
}

static void do_sprite_bank(deark *c, lctx *d, de_int64 pos)
{
	de_int64 res;
	de_int64 paramoffs[3]; // indexed by SPRITERES_*
	de_int64 nsprites[3]; // indexed by SPRITERES_*

	de_dbg(c, "sprite bank\n");
	for(res=0; res<3; res++) {
		paramoffs[res] = de_getui32be(pos+4+4*res);
		nsprites[res] = de_getui16be(pos+16+2*res);
		de_dbg(c, "%s-res sprites: %d, param blk offset: %d\n", sprite_res_name[res],
			(int)nsprites[res], (int)paramoffs[res]);
	}

	for(res=0; res<3; res++) {
		de_int64 abs_offset;
		if(nsprites[res]<1) continue;

		// paramoffs is relative to the first position after the ID.
		abs_offset = pos + 4 + paramoffs[res];

		if(abs_offset>(c->infile->len-8)) continue;
		do_sprite_param_blocks(c, d, res, nsprites[res], abs_offset);
	}
}

static void do_mbk_data_bank(deark *c, lctx *d, de_int64 pos)
{
	de_dbg(c, "STOS data bank at %d\n", (int)pos);
	de_dbg_indent(c, 1);
	d->data_bank_id = (de_uint32)de_getui32be(pos);
	de_dbg(c, "data bank id: 0x%08x\n", (unsigned int)d->data_bank_id);

	switch(d->data_bank_id) {
	case 0x19861987U:
		do_sprite_bank(c, d, pos);
		break;
	}
	de_dbg_indent(c, -1);
}

static void do_mbk(deark *c, lctx *d)
{
	de_int64 pos = 0;

	de_dbg(c, "MBK header at %d\n", (int)pos);
	de_dbg_indent(c, 1);

	de_dbg(c, "bank number: %d\n", (int)d->banknum);

	d->banksize = de_getui32be(14);
	d->banktype = (de_byte)(d->banksize>>24);
	d->banksize &= (de_int64)0x00ffffff;
	de_dbg(c, "bank type: 0x%02x\n", (unsigned int)d->banktype);
	de_dbg(c, "bank size: %d\n", (int)d->banksize);

	de_dbg_indent(c, -1);

	pos += 18;

	if(d->banktype==0x81) {
		do_mbk_data_bank(c, d, pos);
	}
}

static void do_mbs(deark *c, lctx *d)
{
	de_int64 pos = 0;
	de_dbg(c, "MBS header at %d\n", (int)pos);
}

static void de_run_mbk_mbs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->banknum = de_getui32be(10);
	if(d->banknum==0) {
		do_mbs(c, d);
	}
	else {
		do_mbk(c, d);
	}

	de_free(c, d);
}

static int de_identify_mbk(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "Lionpoubnk", 10))
		return 100;
	return 0;
}

void de_module_mbk(deark *c, struct deark_module_info *mi)
{
	mi->id = "mbk";
	mi->desc = "STOS Memory Bank";
	mi->run_fn = de_run_mbk_mbs;
	mi->identify_fn = de_identify_mbk;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
