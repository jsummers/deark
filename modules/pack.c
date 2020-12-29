// This file is part of Deark.
// Copyright (C) 2020 Jason Summers
// See the file COPYING for terms of use.

// Unix "pack" (.z) compressed format

#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_pack);

#define PCK_EOF_CODE (-1)

typedef struct localctx_struct {
	i64 unc_size;
	i64 tree_def_size;
	struct fmtutil_huffman_tree *ht;
	struct de_bitreader bitrd;

	UI depth;
#define PCK_MAX_LEVELS 48 // Traditional unpack maxes out at ~24
	UI leaves_per_level[PCK_MAX_LEVELS];
} lctx;

static int read_tree(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	UI lv;
	int retval = 0;

	d->depth = (UI)de_getbyte_p(&pos);
	de_dbg(c, "depth: %u", d->depth);
	if(d->depth>=PCK_MAX_LEVELS) goto done;
	if(d->depth<1) goto done;

	for(lv=0; lv<d->depth; lv++) {
		d->leaves_per_level[lv] = (UI)de_getbyte_p(&pos);
		if(lv==d->depth-1) {
			// The count of leaves in the last level is biased, and the last leaf
			// (for EOF) is virtual (not stored in the following table).
			// The bias is 2 if you think it includes the virtual leaf, otherwise 1.
			d->leaves_per_level[lv] += 2;
		}
		de_dbg2(c, "num length %u codes: %u", (UI)(lv+1), d->leaves_per_level[lv]);
	}

	for(lv=0; lv<d->depth; lv++) {
		UI n_stored_leaves_this_level;
		UI k;

		if(lv==d->depth-1) {
			n_stored_leaves_this_level = d->leaves_per_level[lv] - 1;
		}
		else {
			n_stored_leaves_this_level = d->leaves_per_level[lv];
		}

		for(k=0; k<n_stored_leaves_this_level; k++) {
			u8 ch;

			ch = de_getbyte_p(&pos);
			de_dbg3(c, "lv=%u ch=%u", lv, (UI)ch);
			fmtutil_huffman_record_a_code_length(c, d->ht, (fmtutil_huffman_valtype)ch, lv+1);
		}

		if(lv==d->depth-1) {
			de_dbg3(c, "lv=%u EOF", lv);
			fmtutil_huffman_record_a_code_length(c, d->ht, (fmtutil_huffman_valtype)PCK_EOF_CODE, lv+1);
		}
	}

	if(!fmtutil_huffman_make_canonical_tree(c, d->ht, FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES)) {
		de_err(c, "Failed to decode Huffman tree");
	}

	retval = 1;
done:
	d->tree_def_size = pos - pos1;
	return retval;
}

static void decode_file_data(deark *c, lctx *d, i64 pos1, dbuf *outf)
{
	i64 ncodes_expected;
	i64 i;

	de_dbg(c, "compressed data at %"I64_FMT, pos1);

	d->bitrd.f = c->infile;
	d->bitrd.curpos = pos1;
	d->bitrd.endpos = c->infile->len;
	d->bitrd.bbll.is_lsb = 0;
	de_bitbuf_lowelevel_empty(&d->bitrd.bbll);

	ncodes_expected = d->unc_size + 1;

	for(i=0; i<ncodes_expected; i++) {
		int ret;
		fmtutil_huffman_valtype val = 0;

		ret = fmtutil_huffman_read_next_value(d->ht, &d->bitrd, &val, NULL);
		if(ret && c->debug_level>=3) {
			de_dbg3(c, "val: %d", (int)val);
		}

		if(i==ncodes_expected-1) { // Expecting the EOF code at this position
			if(!ret || val!=PCK_EOF_CODE) {
				de_warn(c, "EOF code not found. Decompression might have failed.");
			}
			goto done;
		}

		if(!ret) {
			if(d->bitrd.eof_flag) {
				de_err(c, "Unexpected end of file");
			}
			else {
				de_err(c, "Huffman decode error");
			}
			goto done;
		}

		if(val==PCK_EOF_CODE) {
			de_err(c, "Unexpected EOF code");
			goto done;
		}

		dbuf_writebyte(outf, (u8)val);
	}

done:
	;
}

static void de_run_pack(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 pos = 0;
	dbuf *outf = NULL;

	d = de_malloc(c, sizeof(lctx));

	pos += 2;
	d->unc_size = de_getu32be_p(&pos);
	de_dbg(c, "uncompressed size: %"I64_FMT, d->unc_size);

	if(d->unc_size!=0) {
		d->ht = fmtutil_huffman_create_tree(c, 257, 257);
		if(!read_tree(c, d, pos)) goto done;
		pos += d->tree_def_size;
	}

	outf = dbuf_create_output_file(c, "bin", NULL, 0);

	if(d->unc_size!=0) {
		decode_file_data(c, d, pos, outf);
	}

done:
	dbuf_close(outf);
	if(d) {
		if(d->ht) {
			fmtutil_huffman_destroy_tree(c, d->ht);
		}
		de_free(c, d);
	}
}

static int de_identify_pack(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "\x1f\x1e", 2)) {
		if(de_input_file_has_ext(c, ".z")) {
			return 100;
		}
		return 65;
	}
	return 0;
}

void de_module_pack(deark *c, struct deark_module_info *mi)
{
	mi->id = "pack";
	mi->desc = "Unix pack (.z)";
	mi->run_fn = de_run_pack;
	mi->identify_fn = de_identify_pack;
}
