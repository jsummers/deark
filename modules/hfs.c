// This file is part of Deark.
// Copyright (C) 2019 Jason Summers
// See the file COPYING for terms of use.

// HFS (Mac filesystem)

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_hfs);

#define CDRTYPE_DIR   1
#define CDRTYPE_FILE  2

struct ExtDescriptor {
	i64 first_alloc_blk;
	i64 num_alloc_blks;
};

// Used by dirid_hash
struct dirid_item_struct {
	u32 ParID;
	de_ucstring *name;
};

// Represents one record in a leaf node (one file or directory)
struct recorddata {
	i64 pos1;
	i64 datapos;
	int cdrType;
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
	i64 drXTFlSize;
	i64 drCTFlSize;
	struct ExtDescriptor drXTExtRec[3];
	struct ExtDescriptor drCTExtRec[3];

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
	return allocation_blk_dpos(d, d->drCTExtRec[0].first_alloc_blk) + 512 * nodenum;
}

static void read_one_timestamp(deark *c, lctx *d, i64 pos, de_finfo *fi1,
	de_finfo *fi2, const char *name)
{
	i64 ts_raw;
	struct de_timestamp ts;
	char timestamp_buf[64];

	ts.is_valid = 0;
	ts_raw = de_getu32be(pos);
	if(ts_raw!=0) {
		de_mac_time_to_timestamp(ts_raw, &ts);
	}
	if(ts.is_valid) {
		de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);

		if(fi1) {
			fi1->mod_time = ts;
		}
		if(fi2) {
			fi2->mod_time = ts;
		}
	}
	else {
		de_strlcpy(timestamp_buf, "unknown", sizeof(timestamp_buf));
	}
	de_dbg(c, "%s: %"I64_FMT" (%s)", name, ts_raw, timestamp_buf);
}

static void read_ExtDataRecs(deark *c, lctx *d, i64 pos1,
	struct ExtDescriptor *eds, size_t num_eds, const char *name)
{
	size_t i;
	i64 pos = pos1;

	for(i=0; i<num_eds; i++) {
		eds[i].first_alloc_blk = de_getu16be_p(&pos);
		eds[i].num_alloc_blks = de_getu16be_p(&pos);
		de_dbg(c, "%s[%u]: first_blk=%u, num_blks=%u", name, (unsigned int)i,
			(unsigned int)eds[i].first_alloc_blk, (unsigned int)eds[i].num_alloc_blks);
	}
}

static int do_master_directory_blocks(deark *c, lctx *d, i64 blknum)
{
	i64 pos;
	i64 nlen;
	de_ucstring *s = NULL;
	int retval = 0;

	pos = block_dpos(d, blknum);
	de_dbg(c, "master directory blocks at %"I64_FMT" (block %"I64_FMT")", pos, blknum);
	de_dbg_indent(c, 1);

	pos += 2; // signature
	read_one_timestamp(c, d, pos, NULL, NULL, "vol. create date");
	pos += 4;
	read_one_timestamp(c, d, pos, NULL, NULL, "vol. last mod date");
	pos += 4;
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

	d->drXTFlSize = de_getu32be_p(&pos);
	de_dbg(c, "drXTFlSize: %"I64_FMT, d->drXTFlSize);
	read_ExtDataRecs(c, d, pos, d->drCTExtRec, 3, "drXTFlSize");
	pos += 12;

	d->drCTFlSize = de_getu32be_p(&pos);
	de_dbg(c, "drCTFlSize: %"I64_FMT, d->drCTFlSize);
	read_ExtDataRecs(c, d, pos, d->drCTExtRec, 3, "drCTExtRec");
	pos += 12;

	if(d->drCTFlSize > d->drCTExtRec[0].num_alloc_blks * d->drAlBlkSiz) {
		// TODO: Support this
		de_err(c, "Fragmented catalog, not supported");
		goto done;
	}

	retval = 1;
done:
	de_dbg_indent(c, -1);
	ucstring_destroy(s);
	return retval;
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

static void squash_slashes(de_ucstring *s, i64 pos1)
{
	i64 i;

	for(i=pos1; i<s->len; i++) {
		if(s->str[i]=='/') {
			s->str[i] = '_';
		}
	}
}

static void do_leaf_node_record_directory_pass1(deark *c, lctx *d, struct nodedata *nd,
	struct recorddata *rd)
{
	i64 pos = rd->datapos;
	u32 dirID;
	struct dirid_item_struct *dirid_item = NULL;

	dirid_item = de_malloc(c, sizeof(struct dirid_item_struct));

	pos += 2; // common fields, already read
	pos += 2; // dirFlags
	pos += 2; // valence
	dirID = (u32)de_getu32be_p(&pos);
	de_dbg(c, "dirDirID: %u", (unsigned int)dirID);

	dirid_item->name = ucstring_clone(rd->name);
	squash_slashes(dirid_item->name, 0);
	dirid_item->ParID = rd->ParID;

	de_inthashtable_add_item(c, d->dirid_hash, (i64)dirID, (void*)dirid_item);
	dirid_item = NULL;
}

static void get_full_path_from_dirid(deark *c, lctx *d, u32 dirid, de_ucstring *s,
	int depth)
{
	void *item;
	int ret;
	struct dirid_item_struct *dirid_item;

	if(depth>20) goto done;
	if(dirid==0) goto done;
	ret = de_inthashtable_get_item(c, d->dirid_hash, (i64)dirid, &item);
	if(!ret && dirid>1) {
		de_warn(c, "Unknown parent directory (ID %u)", (unsigned int)dirid);
	}
	if(!ret) goto done;
	dirid_item = (struct dirid_item_struct*)item;

	if(dirid_item->ParID!=0 && dirid_item->ParID!=dirid) {
		get_full_path_from_dirid(c, d, dirid_item->ParID, s, depth+1);
	}

	if(!ucstring_isnonempty(dirid_item->name)) goto done;
	ucstring_append_ucstring(s, dirid_item->name);
	ucstring_append_sz(s, "/", DE_ENCODING_LATIN1);
done:
	;
}
static void read_timestamp_fields(deark *c, lctx *d, i64 pos1,
	de_finfo *fi1, de_finfo *fi2)
{
	i64 pos = pos1;

	read_one_timestamp(c, d, pos, NULL, NULL, "create date");
	pos += 4;
	read_one_timestamp(c, d, pos, fi1, fi2, "mod date");
	pos += 4;
	read_one_timestamp(c, d, pos, NULL, NULL, "backup date");
	pos += 4;
}

static void do_extract_dir(deark *c, lctx *d, struct nodedata *nd,
	struct recorddata *rd, de_finfo *fi)
{
	i64 pos = rd->datapos;
	dbuf *outf = NULL;

	pos += 2; // common fields, already read
	pos += 2; // dirFlags
	pos += 2; // dirVal
	pos += 4; // dirDirID

	read_timestamp_fields(c, d, pos, fi, NULL);
	pos += 12;

	fi->is_directory = 1;

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);
	dbuf_close(outf);
}

struct fork_data {
	i64 first_alloc_blk;
	i64 logical_eof;
	i64 physical_eof;
	struct ExtDescriptor ExtRec[3];
};

static void do_extract_fork(deark *c, lctx *d, struct recorddata *rd,
	struct fork_data *fkd, de_finfo *fi, int is_rsrc)
{
	i64 dlen;
	i64 len_avail;
	i64 nbytes_still_to_write;
	size_t k;
	dbuf *outf = NULL;

	dlen = fkd->logical_eof;
	len_avail = d->drAlBlkSiz * (fkd->ExtRec[0].num_alloc_blks +
		fkd->ExtRec[1].num_alloc_blks + fkd->ExtRec[2].num_alloc_blks);
	if(dlen > len_avail) {
		// TODO: Need to be able to read the Extents Overflow tree.
		de_err(c, "%s: Files with more than 3 fragments are not supported",
			ucstring_getpsz(rd->name));
		goto done;
	}

	outf = dbuf_create_output_file(c, NULL, fi, 0x0);

	nbytes_still_to_write = dlen;

	for(k=0; k<3; k++) {
		i64 fragment_dpos;
		i64 nbytes_to_write_this_time;

		if(nbytes_still_to_write<=0) break;

		fragment_dpos = allocation_blk_dpos(d, fkd->ExtRec[k].first_alloc_blk);
		nbytes_to_write_this_time = d->drAlBlkSiz * fkd->ExtRec[k].num_alloc_blks;
		if(nbytes_to_write_this_time > nbytes_still_to_write) {
			nbytes_to_write_this_time = nbytes_still_to_write;
		}

		if(fragment_dpos + nbytes_to_write_this_time > c->infile->len) {
			de_err(c, "Member file data goes beyond end of file");
			goto done;
		}

		dbuf_copy(c->infile, fragment_dpos, nbytes_to_write_this_time, outf);

		nbytes_still_to_write -= nbytes_to_write_this_time;
	}

done:
	dbuf_close(outf);
}

static void read_finder_info(deark *c, lctx *d, i64 pos1)
{
	i64 pos = pos1;
	struct de_fourcc filetype;
	struct de_fourcc creator;

	dbuf_read_fourcc(c->infile, pos, &filetype, 4, 0x0);
	de_dbg(c, "filetype: '%s'", filetype.id_dbgstr);
	pos += 4;
	dbuf_read_fourcc(c->infile, pos, &creator, 4, 0x0);
	de_dbg(c, "creator: '%s'", creator.id_dbgstr);
	pos += 4;
}

static void do_extract_file(deark *c, lctx *d, struct nodedata *nd,
	struct recorddata *rd, de_finfo *fi_data, de_finfo *fi_rsrc)
{
	i64 pos = rd->datapos;
	i64 n;
	struct fork_data fkd_data;
	struct fork_data fkd_rsrc;

	pos += 2; // common fields, already read

	n = (i64)de_getbyte_p(&pos);
	de_dbg(c, "filFlags: %d", (int)n);

	n = (i64)de_getbyte_p(&pos);
	de_dbg(c, "filTyp: %d", (int)n);

	read_finder_info(c, d, pos);
	pos += 16; // filUsrWds, Finder info

	pos += 4; // filFlNum, file id

	fkd_data.first_alloc_blk = de_getu16be_p(&pos);
	de_dbg(c, "data fork first alloc blk: %d", (int)fkd_data.first_alloc_blk);
	fkd_data.logical_eof = de_getu32be_p(&pos);
	de_dbg(c, "data fork logical eof: %d", (int)fkd_data.logical_eof);
	fkd_data.physical_eof = de_getu32be_p(&pos);
	de_dbg(c, "data fork physical eof: %d", (int)fkd_data.physical_eof);

	fkd_rsrc.first_alloc_blk = de_getu16be_p(&pos);
	de_dbg(c, "rsrc fork first alloc blk: %d", (int)fkd_rsrc.first_alloc_blk);
	fkd_rsrc.logical_eof = de_getu32be_p(&pos);
	de_dbg(c, "rsrc fork logical eof: %d", (int)fkd_rsrc.logical_eof);
	fkd_rsrc.physical_eof = de_getu32be_p(&pos);
	de_dbg(c, "rsrc fork physical eof: %d", (int)fkd_rsrc.physical_eof);

	read_timestamp_fields(c, d, pos, fi_data, fi_rsrc);
	pos += 12;

	pos += 16; // filFndrInfo sizeof(FXInfo)

	n = de_getu16be_p(&pos);
	de_dbg(c, "filClpSize: %d", (int)n);

	read_ExtDataRecs(c, d, pos, fkd_data.ExtRec, 3, "filExtRec");
	pos += 12;
	read_ExtDataRecs(c, d, pos, fkd_rsrc.ExtRec, 3, "filRExtRec");
	pos += 12;

	if(fkd_data.logical_eof>0 || fkd_rsrc.logical_eof==0) {
		do_extract_fork(c, d, rd, &fkd_data, fi_data, 0);
	}
	if(fkd_rsrc.logical_eof>0) {
		do_extract_fork(c, d, rd, &fkd_rsrc, fi_rsrc, 1);
	}
}

static void do_leaf_node_record_extract_item(deark *c, lctx *d, struct nodedata *nd,
	struct recorddata *rd)
{
	de_ucstring *fullpath = NULL;
	de_finfo *fi_data = NULL;
	de_finfo *fi_rsrc = NULL;
	i64 oldlen;

	fi_data = de_finfo_create(c);
	fi_data->original_filename_flag = 1;
	fi_rsrc = de_finfo_create(c);
	fi_rsrc->original_filename_flag = 1;

	fullpath = ucstring_create(c);

	// TODO: This is not very efficient. Maybe we should at least cache the
	// previous file's path, since it's usually the same.
	get_full_path_from_dirid(c, d, rd->ParID, fullpath, 0);

	de_dbg(c, "path: \"%s\"", ucstring_getpsz_d(fullpath));
	oldlen = fullpath->len;
	if(ucstring_isnonempty(rd->name)) {
		ucstring_append_ucstring(fullpath, rd->name);
	}
	else {
		ucstring_append_sz(fullpath, "_", DE_ENCODING_LATIN1);
	}

	squash_slashes(fullpath, oldlen);
	de_finfo_set_name_from_ucstring(c, fi_data, fullpath, DE_SNFLAG_FULLPATH);
	if(rd->cdrType==CDRTYPE_FILE) {
		ucstring_append_sz(fullpath, ".rsrc", DE_ENCODING_LATIN1);
		de_finfo_set_name_from_ucstring(c, fi_rsrc, fullpath, DE_SNFLAG_FULLPATH);
	}

	if(rd->cdrType==CDRTYPE_DIR) {
		do_extract_dir(c, d, nd, rd, fi_data);
	}
	else if(rd->cdrType==CDRTYPE_FILE) {
		do_extract_file(c, d, nd, rd, fi_data, fi_rsrc);
	}

	ucstring_destroy(fullpath);
	de_finfo_destroy(c, fi_data);
	de_finfo_destroy(c, fi_rsrc);
}

static void do_leaf_node_record(deark *c, lctx *d, struct nodedata *nd, i64 idx, int pass)
{
	i64 pos1_rel, pos;
	i64 len;
	i64 ckrKeyLen;
	i64 nlen;
	struct recorddata *rd = NULL;

	rd = de_malloc(c, sizeof(struct recorddata));
	pos1_rel = nd->offsets[idx];
	rd->pos1 = nd->dpos + pos1_rel;
	len = nd->offsets[idx+1] - nd->offsets[idx];
	de_dbg(c, "leaf node record[%d] at %"I64_FMT"+%"I64_FMT", len=%"I64_FMT,
		(int)idx, nd->dpos, pos1_rel, len);
	de_dbg_indent(c, 1);

	// == Catalog File Key
	pos = rd->pos1;
	ckrKeyLen = (i64)de_getbyte_p(&pos);
	de_dbg(c, "ckrKeyLen: %d", (int)ckrKeyLen);
	if(ckrKeyLen==0) {
		de_dbg(c, "[deleted record]");
		goto done;
	}

	rd->datapos = rd->pos1 + 1 + ckrKeyLen;
	if((ckrKeyLen%2)==0) rd->datapos++; // padding

	// Look ahead to get the cdrType
	rd->cdrType = (int)dbuf_geti8(c->infile, rd->datapos);
	de_dbg(c, "cdrType: %d (%s)", rd->cdrType, get_cdrType_name(rd->cdrType));

	if(pass==1) {
		if(rd->cdrType!=CDRTYPE_DIR) goto done;
	}
	else if(pass==2) {
		if(rd->cdrType!=CDRTYPE_DIR && rd->cdrType!=CDRTYPE_FILE) goto done;
	}
	else {
		goto done;
	}

	pos++; // ckrResrv1
	rd->ParID = (u32)de_getu32be_p(&pos);
	de_dbg(c, "ckrParID: %u", (unsigned int)rd->ParID);

	nlen = (i64)de_getbyte_p(&pos);
	de_dbg(c, "name len: %d", (int)nlen);
	rd->name = ucstring_create(c);
	dbuf_read_to_ucstring(c->infile, pos, nlen, rd->name, 0, d->input_encoding);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(rd->name));

	// == Catalog File Data Record

	switch(rd->cdrType) {
	case CDRTYPE_DIR:
		if(pass==1) {
			do_leaf_node_record_directory_pass1(c, d, nd, rd);
		}
		else if(pass==2) {
			do_leaf_node_record_extract_item(c, d, nd, rd);
		}
		break;
	case CDRTYPE_FILE:
		if(pass==2) {
			do_leaf_node_record_extract_item(c, d, nd, rd);
		}
		break;
	}

done:
	de_dbg_indent(c, -1);
	if(rd) {
		ucstring_destroy(rd->name);
		de_free(c, rd);
	}
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

	if(pass==1) {
		if(!de_inthashtable_add_item(c, d->nodes_seen, nd->nodenum, NULL)) {
			de_err(c, "Invalid node list");
			goto done;
		}
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
	int retval = 0;

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
	pos = allocation_blk_dpos(d, d->drCTExtRec[0].first_alloc_blk);
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

	// TODO: In the leaf list, is it possible/legal for a parent-dir-ID number to
	// appear before the record for that dir-ID? I haven't seen it happen, but
	// for all I know it is possible. If it doesn't happen, that would be good,
	// because we wouldn't have to make an extra pass to collect directory info.
	// But for now, we'll make two passes.

	// Pass 1 to figure out the directory tree structure, and detect node loops
	if(!do_all_leaf_nodes(c, d, hdr_node, 1)) goto done;
	// Pass 2 to extract files
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

	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);

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
	i64 drAlBlkSiz;
	int has_ext;

	if(dbuf_memcmp(c->infile, 1024, "BD", 2)) return 0;

	// Allocation block size must be a nonzero multiple of 512.
	drAlBlkSiz = de_getu32be(1024+20);
	if(drAlBlkSiz==0 || (drAlBlkSiz%512)!=0) return 0;

	has_ext = de_input_file_has_ext(c, "hfs");
	return has_ext?90:15;
}

void de_module_hfs(deark *c, struct deark_module_info *mi)
{
	mi->id = "hfs";
	mi->desc = "HFS filesystem image";
	mi->run_fn = de_run_hfs;
	mi->identify_fn = de_identify_hfs;
}
