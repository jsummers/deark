// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// HFS (Mac filesystem)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_hfs);

struct dirid_item_struct {
	u32 ParID;
	de_ucstring *name;
};

struct nodedata {
	int expecting_header;
	i64 nodenum;

	i64 dpos;
	i64 f_link, b_link;
	unsigned int nrecs;
	int node_type;
	int node_level;

	i64 bthFNode; // Used if this is a header node

	i64 num_offsets;
	unsigned int *offsets;
};

typedef struct localctx_struct {
	int input_encoding;
	int nesting_level;
	i64 blocksize;
	i64 num_files_in_root_dir;
	i64 drNmAlBlks;
	i64 drAlBlkSiz;
	i64 drClpSiz;
	i64 drAlBlSt;
	i64 drCTExtRec_first_blk;
	struct de_inthashtable *nodes_seen;
	struct de_inthashtable *dirid_hash;
} lctx;

static i64 block_dpos(lctx *d, i64 blknum)
{
	return blknum * d->blocksize;
}

static i64 allocation_blk_dpos(lctx *d, i64 ablknum)
{
	return (d->blocksize * d->drAlBlSt) + (d->drAlBlkSiz * ablknum);
}

static i64 node_dpos(lctx *d, i64 nodenum)
{
	return allocation_blk_dpos(d, d->drCTExtRec_first_blk) + 512 * nodenum;
}

static int do_master_directory_blocks(deark *c, lctx *d, i64 blknum)
{
	i64 pos;
	i64 nlen;
	de_ucstring *s = NULL;

	pos = block_dpos(d, blknum);
	de_dbg(c, "master directory blocks at %"I64_FMT" (block %"I64_FMT")", pos, blknum);
	de_dbg_indent(c, 1);

	pos += 2; // signature
	pos += 4; // creation time
	pos += 4; // last mod time
	pos += 2; // attribs

	d->num_files_in_root_dir = de_getu16be_p(&pos); // drNmFls
	de_dbg(c, "num. files in root dir: %d", (int)d->num_files_in_root_dir);

	pos += 2; // first block of volume bitmap
	pos += 2; // start of next allocation search

	d->drNmAlBlks = de_getu16be_p(&pos);
	de_dbg(c, "drNmAlBlks: %d", (int)d->drNmAlBlks);
	d->drAlBlkSiz = de_getu32be_p(&pos);
	de_dbg(c, "drAlBlkSiz: %u", (unsigned int)d->drAlBlkSiz);
	d->drClpSiz = de_getu32be_p(&pos);
	de_dbg(c, "drClpSiz: %u", (unsigned int)d->drClpSiz);
	d->drAlBlSt = de_getu16be_p(&pos);
	de_dbg(c, "drAlBlSt: %d", (int)d->drAlBlSt);
	pos += 4; // drNxtCNID
	pos += 2; // drFreeBks

	nlen = de_getbyte_p(&pos);
	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, pos, nlen, 27, s, 0, d->input_encoding);
	de_dbg(c, "volume name: \"%s\"", ucstring_getpsz_d(s));
	pos += 27;

	pos += 4; // drVolBkUp
	pos += 2; // drVSeqNum
	pos += 4; // drWrCnt
	pos += 4; // drXTClpSiz
	pos += 4; // drCTClpSiz
	pos += 2; // drNmRtDirs
	pos += 4; // drFilCnt
	pos += 4; // drDirCnt
	pos += 4*8; // drFndrInfo
	pos += 2; // drVCSize
	pos += 2; // drVBMCSize
	pos += 2; // drCtlCSize
	pos += 4; // drXTFlSize
	pos += 12; // drXTExtRec
	pos += 4; // drCTFlSize

	d->drCTExtRec_first_blk = de_getu16be(pos);
	de_dbg(c, "drCTExtRec[1].first_allocation_blk: %"I64_FMT, d->drCTExtRec_first_blk);
	pos += 12; // drCTExtRec

	de_dbg_indent(c, -1);
	ucstring_destroy(s);
	return 1;
}

static const char *get_node_type_name(int t)
{
	const char *name = NULL;
	switch(t) {
	case 0: name="index"; break;
	case 1: name="header"; break;
	case 2: name="map"; break;
	case -1: name="leaf"; break;
	}
	return name?name:"?";
}

static void do_header_node(deark *c, lctx *d, struct nodedata *nd)
{
	i64 pos;
	i64 bthRoot;
	i64 n;

	if(nd->nrecs<3) goto done;
	// offset[0] = B* tree header record
	// offset[1] = not important
	// offset[2] = B* tree map record, not important
	pos = nd->dpos + nd->offsets[0];
	if(pos+512 > c->infile->len) goto done;

	de_dbg(c, "header node B*-tree header record at %"I64_FMT, pos);
	de_dbg_indent(c, 1);

	n = de_getu16be_p(&pos);
	de_dbg(c, "bthDepth: %"I64_FMT, n);
	bthRoot = de_getu32be_p(&pos);
	de_dbg(c, "bthRoot: %"I64_FMT, bthRoot);
	n = de_getu32be_p(&pos);
	de_dbg(c, "bthNRecs: %"I64_FMT, n);
	nd->bthFNode = de_getu32be_p(&pos);
	de_dbg(c, "bthFNode: %"I64_FMT, nd->bthFNode);
	n = de_getu32be_p(&pos);
	de_dbg(c, "bthLNode: %"I64_FMT, n);
	n = de_getu16be_p(&pos);
	de_dbg(c, "bthNodeSize: %"I64_FMT, n);
	n = de_getu16be_p(&pos);
	de_dbg(c, "bthKeyLen: %"I64_FMT, n);
	n = de_getu32be_p(&pos);
	de_dbg(c, "bthNNodes: %"I64_FMT, n);
	n = de_getu32be_p(&pos);
	de_dbg(c, "bthFree: %"I64_FMT, n);

	de_dbg_indent(c, 1);
done:
	;
}

static const char *get_cdrType_name(int n)
{
	const char *name = NULL;
	switch(n) {
	case 1: name="directory"; break;
	case 2: name="file"; break;
	case 3: name="directory thread"; break;
	case 4: name="file thread"; break;
	}
	return name?name:"?";
}

static void do_leaf_node_record_directory(deark *c, lctx *d, struct nodedata *nd,
	i64 pos1, de_ucstring *name, u32 ParID)
{
	i64 pos = pos1;
	unsigned int dirFlags;
	u32 dirID;
	struct dirid_item_struct *dirid_item = NULL;

	dirid_item = de_malloc(c, sizeof(struct dirid_item_struct));

	pos += 2; // common fields, already read
	dirFlags = (unsigned int)de_getu16be_p(&pos);
	de_dbg(c, "dirFlags: 0x%04x", dirFlags);
	pos += 2; // valence
	dirID = (u32)de_getu32be_p(&pos);
	de_dbg(c, "dirDirID: %u", (unsigned int)dirID);

	dirid_item->name = ucstring_clone(name);
	dirid_item->ParID = ParID;

	de_inthashtable_add_item(c, d->dirid_hash, (i64)dirID, (void*)dirid_item);
	dirid_item = NULL;
}

static void get_full_path_from_dirid(deark *c, lctx *d, u32 dirid, de_ucstring *s)
{
	void *item;
	int ret;
	struct dirid_item_struct *dirid_item;

	if(dirid==0) goto done;
	ret = de_inthashtable_get_item(c, d->dirid_hash, (i64)dirid, &item);
	if(!ret) goto done;
	dirid_item = (struct dirid_item_struct*)item;

	if(dirid_item->ParID!=0 && dirid_item->ParID!=dirid) {
		// TODO: Prevent infinite recursion
		get_full_path_from_dirid(c, d, dirid_item->ParID, s);
	}

	if(!ucstring_isnonempty(dirid_item->name)) goto done;
	ucstring_append_ucstring(s, dirid_item->name);
	ucstring_append_sz(s, "/", DE_ENCODING_LATIN1);
done:
	;
}

static void do_leaf_node_record_file(deark *c, lctx *d, struct nodedata *nd,
	i64 pos1, de_ucstring *name, u32 ParID)
{
	de_ucstring *fullpath = NULL;

	fullpath = ucstring_create(c);
	get_full_path_from_dirid(c, d, ParID, fullpath);
	de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(fullpath));

	ucstring_destroy(fullpath);
}

static void do_leaf_node_record(deark *c, lctx *d, struct nodedata *nd, i64 idx, int pass)
{
	i64 pos1, pos1_rel, pos;
	i64 len;
	u32 ckrParID;
	i64 ckrKeyLen;
	i64 nlen;
	i64 datapos;
	int cdrType;
	de_ucstring *name = NULL;

	pos1_rel = nd->offsets[idx];
	pos1 = nd->dpos + pos1_rel;
	len = nd->offsets[idx+1] - nd->offsets[idx];
	de_dbg(c, "leaf node record[%d] at %"I64_FMT"+%"I64_FMT", len=%"I64_FMT,
		(int)idx, nd->dpos, pos1_rel, len);
	de_dbg_indent(c, 1);

	// == Catalog File Key
	pos = pos1;
	ckrKeyLen = (i64)de_getbyte_p(&pos);
	de_dbg(c, "ckrKeyLen: %d", (int)ckrKeyLen);
	if(ckrKeyLen==0) {
		de_dbg(c, "[deleted record]");
		goto done;
	}

	datapos = pos1 + 1 + ckrKeyLen;
	if((ckrKeyLen%2)==0) datapos++; // padding

	// Look ahead to get the cdrType
	cdrType = (int)dbuf_geti8(c->infile, datapos);
	de_dbg(c, "cdrType: %d (%s)", cdrType, get_cdrType_name(cdrType));

	if(cdrType!=1 && cdrType!=2) goto done;
	if(cdrType==1 && pass!=1) goto done; // read directories in pass 1
	if(cdrType==2 && pass!=2) goto done; // read files in pass 2

	pos++; // ckrResrv1
	ckrParID = (u32)de_getu32be_p(&pos);
	de_dbg(c, "ckrParID: %u", (unsigned int)ckrParID);

	nlen = (i64)de_getbyte_p(&pos);
	de_dbg(c, "name len: %d", (int)nlen);
	name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, nlen, name, 0, d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(name));

	// == Catalog File Data Record

	switch(cdrType) {
	case 1:
		do_leaf_node_record_directory(c, d, nd, datapos, name, ckrParID);
		break;
	case 2:
		do_leaf_node_record_file(c, d, nd, datapos, name, ckrParID);
		break;
	}

done:
	de_dbg_indent(c, -1);
	ucstring_destroy(name);
}

static void do_leaf_node(deark *c, lctx *d, struct nodedata *nd, int pass)
{
	i64 i;

	for(i=0; i<nd->nrecs; i++) {
		do_leaf_node_record(c, d, nd, i, pass);
	}
}

static void destroy_nodedata(deark *c, struct nodedata *nd)
{
	if(!nd) return;
	de_free(c, nd->offsets);
	de_free(c, nd);
}

// Caller must allocate nd, set some fields in it, call this function,
// and is responsible for destroying nd.
// pass is relevant only for leaf nodes.
static int do_node(deark *c, lctx *d, struct nodedata *nd, int pass)
{
	i64 pos;
	i64 i;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	d->nesting_level++;
	if(d->nesting_level>20) goto done;
	if(nd->nodenum==0 && !nd->expecting_header) goto done;

	if(pass==1 && !de_inthashtable_add_item(c, d->nodes_seen, nd->nodenum, NULL)) {
		goto done;
	}
	retval = 1;

	nd->dpos = node_dpos(d, nd->nodenum);
	pos = nd->dpos;

	de_dbg(c, "node #%"I64_FMT" at %"I64_FMT, nd->nodenum, nd->dpos);
	de_dbg_indent(c, 1);

	// == 14-byte NodeDescriptor ==
	nd->f_link = de_getu32be_p(&pos);
	de_dbg(c, "fwd link: %"I64_FMT, nd->f_link);
	nd->b_link = de_getu32be_p(&pos);
	de_dbg(c, "bwd link: %"I64_FMT, nd->b_link);

	nd->node_type = (int)dbuf_geti8(c->infile, pos++);
	de_dbg(c, "node type: %d (%s)", nd->node_type, get_node_type_name(nd->node_type));
	nd->node_level = (int)dbuf_geti8(c->infile, pos++);
	de_dbg(c, "node level: %d", nd->node_level);
	nd->nrecs = (unsigned int)de_getu16be_p(&pos);
	de_dbg(c, "number of records: %u", nd->nrecs);
	if(nd->nrecs>250) goto done;
	pos += 2; // ndResv2

	// == The offset table at the end of the node ==
	nd->num_offsets = (i64)nd->nrecs+1;
	nd->offsets = de_mallocarray(c, nd->num_offsets, sizeof(unsigned int));

	pos = nd->dpos+512 - 2*nd->num_offsets;
	for(i=0; i<nd->num_offsets; i++) {
		char nbuf[32];
		i64 idx = nd->num_offsets - 1 - i;
		nd->offsets[idx] = (unsigned int)de_getu16be_p(&pos);
		if(i==0) de_strlcpy(nbuf, "free space", sizeof(nbuf));
		else de_snprintf(nbuf, sizeof(nbuf), "rec %u", (unsigned int)idx);
		de_dbg(c, "offset to %s: %u", nbuf, (unsigned int)nd->offsets[idx]);
	}

	if(nd->node_type == -1) {
		do_leaf_node(c, d, nd, pass);
	}
	else if(nd->node_type==1) {
		do_header_node(c, d, nd);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	d->nesting_level--;
	return retval;
}

static int do_all_leaf_nodes(deark *c, lctx *d, struct nodedata *hdr_node, int pass)
{
	i64 curr_nodenum;
	struct nodedata *nd = NULL;
	int retval = 1;

	de_dbg(c, "reading leaf nodes, pass %d", pass);
	de_dbg_indent(c, 1);

	// Read all leaf nodes, using the leaf-to-leaf links
	curr_nodenum = hdr_node->bthFNode;

	while(curr_nodenum!=0) {
		nd = de_malloc(c, sizeof(struct nodedata));
		nd->nodenum = curr_nodenum;

		if(!do_node(c, d, nd, pass)) goto done;

		curr_nodenum = nd->f_link;
		destroy_nodedata(c, nd);
		nd = NULL;
	}
	retval = 1;

done:
	destroy_nodedata(c, nd);
	de_dbg_indent(c, -1);
	return retval;
}

static int do_catalog(deark *c, lctx *d)
{
	i64 pos;
	struct nodedata *hdr_node = NULL;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	pos = allocation_blk_dpos(d, d->drCTExtRec_first_blk);
	de_dbg(c, "catalog at %"I64_FMT, pos);

	hdr_node = de_malloc(c, sizeof(struct nodedata));
	hdr_node->expecting_header = 1;
	hdr_node->nodenum = 0;
	de_dbg_indent(c, 1);
	if(!do_node(c, d, hdr_node, 0)) goto done;
	de_dbg_indent(c, -1);

	if(hdr_node->node_type != 1) {
		de_err(c, "Expected header node not found");
		goto done;
	}

	if(!do_all_leaf_nodes(c, d, hdr_node, 1)) goto done;
	if(!do_all_leaf_nodes(c, d, hdr_node, 2)) goto done;

	retval = 1;
done:
	destroy_nodedata(c, hdr_node);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void destroy_dirid_hash(deark *c, lctx *d)
{
	if(!d->dirid_hash) return;

	while(1) {
		i64 key;
		void *removed_item = NULL;
		struct dirid_item_struct *dirid_item;

		if(!de_inthashtable_remove_any_item(c, d->dirid_hash, &key, &removed_item)) {
			break;
		}
		dirid_item = (struct dirid_item_struct *)removed_item;
		ucstring_destroy(dirid_item->name);
		de_free(c, dirid_item);
	}

	de_inthashtable_destroy(c, d->dirid_hash);
}

static void de_run_hfs(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	d->input_encoding = DE_ENCODING_MACROMAN;
	d->blocksize = 512;
	d->nodes_seen = de_inthashtable_create(c);
	d->dirid_hash = de_inthashtable_create(c);

	if(!do_master_directory_blocks(c, d, 2)) goto done;

	if(!do_catalog(c, d)) goto done;

done:
	if(d) {
		de_inthashtable_destroy(c, d->nodes_seen);
		destroy_dirid_hash(c, d);
		de_free(c, d);
	}
}

static int de_identify_hfs(deark *c)
{
	int has_ext;

	// TODO: Better detection.
	has_ext = de_input_file_has_ext(c, "hfs");
	if(!dbuf_memcmp(c->infile, 1024, "BD", 2)) {
		return has_ext?90:5;
	}
	return 0;
}

void de_module_hfs(deark *c, struct deark_module_info *mi)
{
	mi->id = "hfs";
	mi->desc = "HFS filesystem image";
	mi->run_fn = de_run_hfs;
	mi->identify_fn = de_identify_hfs;
	mi->flags |= DE_MODFLAG_NONWORKING;
}
