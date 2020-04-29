// This file is part of Deark.
// Copyright (C) 2018 Jason Summers
// See the file COPYING for terms of use.

// Microsoft Cabinent (CAB) format

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_cab);

struct folder_info {
	i64 folder_idx;
	i64 coffCabStart;
	i64 cCFData;
	unsigned int typeCompress_raw;
	unsigned int cmpr_type;
};

typedef struct localctx_struct {
	u8 versionMinor, versionMajor;
	unsigned int header_flags;
	i64 cbCabinet;
	i64 coffFiles;
	i64 cFolders;
	i64 cFiles;
	i64 cbCFHeader, cbCFFolder, cbCFData;
	i64 CFHEADER_len;
} lctx;

static const char *get_cmpr_type_name(unsigned int n)
{
	const char *name;

	switch(n) {
	case 0: name="none"; break;
	case 1: name="MSZIP"; break;
	case 2: name="Quantum"; break;
	case 3: name="LZX"; break;
	default: name="?"; break;
	}
	return name;
}

static int do_one_CFDATA(deark *c, lctx *d, struct folder_info *fldi, i64 pos1,
	i64 *bytes_consumed)
{
	u32 csum;
	i64 cbData;
	i64 cbUncomp;
	i64 pos = pos1;

	csum = (u32)de_getu32le_p(&pos);
	de_dbg(c, "csum: 0x%08x", (unsigned int)csum);

	cbData = de_getu16le_p(&pos);
	de_dbg(c, "cbData: %d", (int)cbData);

	cbUncomp = de_getu16le_p(&pos);
	de_dbg(c, "cbUncomp: %d", (int)cbUncomp);

	if((d->header_flags&0x0004) && (d->cbCFData>0)) {
		de_dbg(c, "[%d bytes of abReserve data at %d]", (int)d->cbCFData,
			(int)pos);
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, c->infile, pos, d->cbCFData, 256, NULL, 0x1);
		de_dbg_indent(c, -1);
		pos += d->cbCFData;
	}

	de_dbg(c, "[%d bytes of %scompressed data at %d]", (int)cbData,
		(fldi->cmpr_type==0)?"un":"", (int)pos);
	pos += cbData;

	*bytes_consumed = pos - pos1;
	return 1;
}

static void do_CFDATA_for_one_CFFOLDER(deark *c, lctx *d, struct folder_info *fldi)
{
	i64 i;
	int saved_indent_level;
	i64 pos = fldi->coffCabStart;

	de_dbg_indent_save(c, &saved_indent_level);
	if(fldi->cCFData<1) goto done;
	de_dbg(c, "CFDATA blocks for CFFOLDER[%d], at %d, #=%d", (int)fldi->folder_idx,
		(int)fldi->coffCabStart, (int)fldi->cCFData);
	de_dbg_indent(c, 1);

	for(i=0; i<fldi->cCFData; i++) {
		i64 bytes_consumed = 0;

		if(pos>=c->infile->len) goto done;
		de_dbg(c, "CFDATA[%d] for CFFOLDER[%d], at %d", (int)i,
			(int)fldi->folder_idx, (int)pos);
		de_dbg_indent(c, 1);
		if(!do_one_CFDATA(c, d, fldi, pos, &bytes_consumed)) {
			goto done;
		}
		de_dbg_indent(c, -1);
		pos += bytes_consumed;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static int do_one_CFFOLDER(deark *c, lctx *d, i64 folder_idx,
	i64 pos1, i64 *bytes_consumed)
{
	i64 pos = pos1;
	struct folder_info *fldi = NULL;

	fldi = de_malloc(c, sizeof(struct folder_info));
	fldi->folder_idx = folder_idx;

	fldi->coffCabStart = de_getu32le_p(&pos);
	de_dbg(c, "first CFDATA blk offset (coffCabStart): %"I64_FMT, fldi->coffCabStart);

	fldi->cCFData = de_getu16le_p(&pos);
	de_dbg(c, "no. of CFDATA blks for this folder (cCFData): %d", (int)fldi->cCFData);

	fldi->typeCompress_raw = (unsigned int)de_getu16le_p(&pos);
	fldi->cmpr_type = fldi->typeCompress_raw & 0x000f;
	de_dbg(c, "typeCompress field: 0x%04x", fldi->typeCompress_raw);
	de_dbg_indent(c, 1);
	de_dbg(c, "compression type: 0x%04x (%s)", fldi->cmpr_type,
		get_cmpr_type_name(fldi->cmpr_type));
	de_dbg_indent(c, -1);

	if((d->header_flags&0x0004) && (d->cbCFFolder>0)) {
		de_dbg(c, "[%d bytes of abReserve data at %d]", (int)d->cbCFFolder,
			(int)pos);
		de_dbg_indent(c, 1);
		de_dbg_hexdump(c, c->infile, pos, d->cbCFFolder, 256, NULL, 0x1);
		de_dbg_indent(c, -1);
		pos += d->cbCFFolder;
	}

	*bytes_consumed = pos-pos1;

	do_CFDATA_for_one_CFFOLDER(c, d, fldi);

	de_free(c, fldi);
	return 1;
}

static void do_CFFOLDERs(deark *c, lctx *d)
{
	i64 pos = d->CFHEADER_len;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->cFolders<1) goto done;
	de_dbg(c, "CFFOLDER section at %d, nfolders=%d", (int)pos, (int)d->cFolders);

	de_dbg_indent(c, 1);
	for(i=0; i<d->cFolders; i++) {
		i64 bytes_consumed = 0;

		if(pos>=c->infile->len) break;
		de_dbg(c, "CFFOLDER[%d] at %d", (int)i, (int)pos);
		de_dbg_indent(c, 1);
		if(!do_one_CFFOLDER(c, d, i, pos, &bytes_consumed)) {
			goto done;
		}
		de_dbg_indent(c, -1);
		pos += bytes_consumed;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

static const char *get_special_folder_name(i64 n)
{
	const char *name;
	switch(n) {
	case 0xfffd: name="CONTINUED_FROM_PREV"; break;
	case 0xfffe: name="CONTINUED_TO_NEXT"; break;
	case 0xffff: name="CONTINUED_PREV_AND_NEXT"; break;
	default: name="?"; break;
	}
	return name;
}

static int do_one_CFFILE(deark *c, lctx *d, i64 pos1, i64 *bytes_consumed)
{
	i64 cbFile;
	i64 uoffFolderStart;
	i64 iFolder;
	i64 pos = pos1;
	i64 date_;
	i64 time_;
	unsigned int attribs;
	int retval = 0;
	struct de_stringreaderdata *szName = NULL;
	de_ucstring *attribs_str = NULL;
	struct de_timestamp ts;
	char timestamp_buf[64];
	char tmps[80];

	cbFile = de_getu32le_p(&pos);
	de_dbg(c, "uncompressed file size (cbFile): %"I64_FMT, cbFile);

	uoffFolderStart = de_getu32le_p(&pos);
	de_dbg(c, "offset in folder (uoffFolderStart): %"I64_FMT, uoffFolderStart);

	iFolder = de_getu16le_p(&pos);
	if(iFolder>=0xfffd) {
		de_snprintf(tmps, sizeof(tmps), "0x%04x (%s)", (unsigned int)iFolder,
			get_special_folder_name(iFolder));
	}
	else {
		de_snprintf(tmps, sizeof(tmps), "%u", (unsigned int)iFolder);
	}
	de_dbg(c, "folder index (iFolder): %s", tmps);

	date_ = de_getu16le_p(&pos);
	time_ = de_getu16le_p(&pos);
	de_dos_datetime_to_timestamp(&ts, date_, time_);
	ts.tzcode = DE_TZCODE_LOCAL;
	de_timestamp_to_string(&ts, timestamp_buf, sizeof(timestamp_buf), 0);
	de_dbg(c, "timestamp: %s", timestamp_buf);

	attribs = (unsigned int)de_getu16le_p(&pos);
	attribs_str = ucstring_create(c);
	de_describe_dos_attribs(c, (attribs & 0x3f), attribs_str, 0);
	if(attribs&0x40) ucstring_append_flags_item(attribs_str, "EXEC");
	if(attribs&0x80) ucstring_append_flags_item(attribs_str, "NAME_IS_UTF8");
	de_dbg(c, "attribs: 0x%04x (%s)", attribs, ucstring_getpsz(attribs_str));

	szName = dbuf_read_string(c->infile, pos, 257, 257,
		DE_CONVFLAG_STOP_AT_NUL,
		(attribs&0x80)?DE_ENCODING_UTF8:DE_ENCODING_ASCII);
	de_dbg(c, "szName: \"%s\"", ucstring_getpsz(szName->str));
	if(!szName->found_nul) goto done;
	pos += szName->bytes_consumed;

	*bytes_consumed = pos-pos1;
	retval = 1;
done:
	de_destroy_stringreaderdata(c, szName);
	ucstring_destroy(attribs_str);
	return retval;
}

static void do_CFFILEs(deark *c, lctx *d)
{
	i64 pos = d->coffFiles;
	i64 i;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	if(d->cFiles<1) goto done;
	de_dbg(c, "CFFILE section at %d, nfiles=%d", (int)pos, (int)d->cFiles);
	de_dbg_indent(c, 1);
	for(i=0; i<d->cFiles; i++) {
		i64 bytes_consumed = 0;

		if(pos>=c->infile->len) break;
		de_dbg(c, "CFFILE[%d] at %d", (int)i, (int)pos);
		de_dbg_indent(c, 1);
		if(!do_one_CFFILE(c, d, pos, &bytes_consumed)) {
			goto done;
		}
		de_dbg_indent(c, -1);
		pos += bytes_consumed;
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
}

// On success, sets d->CFHEADER_len.
static int do_CFHEADER(deark *c, lctx *d)
{
	int retval = 0;
	i64 pos = 0;
	de_ucstring *flags_str = NULL;
	struct de_stringreaderdata *CabinetPrev = NULL;
	struct de_stringreaderdata *DiskPrev = NULL;
	struct de_stringreaderdata *CabinetNext = NULL;
	struct de_stringreaderdata *DiskNext = NULL;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);
	de_dbg(c, "CFHEADER at %d", (int)pos);
	de_dbg_indent(c, 1);
	pos += 8; // signature, reserved1
	d->cbCabinet = de_getu32le_p(&pos);
	de_dbg(c, "cbCabinet: %"I64_FMT, d->cbCabinet);
	pos += 4; // reserved2
	d->coffFiles = de_getu32le_p(&pos);
	de_dbg(c, "coffFiles: %"I64_FMT, d->coffFiles);
	pos += 4; // reserved3
	d->versionMinor = de_getbyte_p(&pos);
	d->versionMajor = de_getbyte_p(&pos);
	de_dbg(c, "file format version: %u.%u", (unsigned int)d->versionMajor,
		(unsigned int)d->versionMinor);

	d->cFolders = de_getu16le_p(&pos);
	de_dbg(c, "cFolders: %d", (int)d->cFolders);

	d->cFiles = de_getu16le_p(&pos);
	de_dbg(c, "cFiles: %d", (int)d->cFiles);

	d->header_flags = (unsigned int)de_getu16le_p(&pos);
	flags_str = ucstring_create(c);
	// The specification has a diagram showing that PREV_CABINET is 0x2,
	// NEXT_CABINET is 0x04, etc. But the text below it says that PREV_CABINET
	// is 0x1, NEXT_CABINET is 0x02, etc. I'm sure it's the text that's correct.
	if(d->header_flags&0x0001) ucstring_append_flags_item(flags_str, "PREV_CABINET");
	if(d->header_flags&0x0002) ucstring_append_flags_item(flags_str, "NEXT_CABINET");
	if(d->header_flags&0x0004) ucstring_append_flags_item(flags_str, "RESERVE_PRESENT");
	de_dbg(c, "flags: 0x%04x (%s)", d->header_flags, ucstring_getpsz(flags_str));

	pos += 2; // setID (arbitrary ID for a collection of linked cab files)
	pos += 2; // iCabinet (sequence number in a mult-cab file)

	if(d->header_flags&0x0004) { // RESERVE_PRESENT
		d->cbCFHeader = de_getu16le_p(&pos);
		de_dbg(c, "cbCFHeader: %d", (int)d->cbCFHeader);
		d->cbCFFolder = (i64)de_getbyte_p(&pos);
		de_dbg(c, "cbCFFolder: %d", (int)d->cbCFFolder);
		d->cbCFData = (i64)de_getbyte_p(&pos);
		de_dbg(c, "cbCFData: %d", (int)d->cbCFData);

		if(d->cbCFHeader!=0) {
			de_dbg(c, "[%d bytes of abReserve data at %d]", (int)d->cbCFHeader,
				(int)pos);
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, pos, d->cbCFHeader, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
			pos += d->cbCFHeader;
		}
	}

	if(d->header_flags&0x0001) { // PREV_CABINET
		CabinetPrev = dbuf_read_string(c->infile, pos, 256, 256,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "szCabinetPrev: \"%s\"", ucstring_getpsz(CabinetPrev->str));
		if(!CabinetPrev->found_nul) goto done;
		pos += CabinetPrev->bytes_consumed;

		DiskPrev = dbuf_read_string(c->infile, pos, 256, 256,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "szDiskPrev: \"%s\"", ucstring_getpsz(DiskPrev->str));
		if(!DiskPrev->found_nul) goto done;
		pos += DiskPrev->bytes_consumed;
	}

	if(d->header_flags&0x0002) { // NEXT_CABINET
		CabinetNext = dbuf_read_string(c->infile, pos, 256, 256,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "szCabinetNext: \"%s\"", ucstring_getpsz(CabinetNext->str));
		if(!CabinetNext->found_nul) goto done;
		pos += CabinetNext->bytes_consumed;

		DiskNext = dbuf_read_string(c->infile, pos, 256, 256,
			DE_CONVFLAG_STOP_AT_NUL, DE_ENCODING_ASCII);
		de_dbg(c, "szDiskNext: \"%s\"", ucstring_getpsz(DiskNext->str));
		if(!DiskNext->found_nul) goto done;
		pos += DiskNext->bytes_consumed;
	}

	// TODO: Additional fields may be here

	de_dbg_indent(c, -1);

	if(d->versionMajor!=1 || d->versionMinor!=3) {
		de_err(c, "Unsupported CAB format version: %u.%u",
			(unsigned int)d->versionMajor, (unsigned int)d->versionMinor);
		goto done;
	}

	d->CFHEADER_len = pos;
	retval = 1;
done:
	de_destroy_stringreaderdata(c, CabinetPrev);
	de_destroy_stringreaderdata(c, DiskPrev);
	de_destroy_stringreaderdata(c, CabinetNext);
	de_destroy_stringreaderdata(c, DiskNext);
	ucstring_destroy(flags_str);
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static void de_run_cab(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	de_info(c, "Note: MS Cabinet files can be parsed, but no files can be extracted from them.");

	if(!do_CFHEADER(c, d)) goto done;
	do_CFFOLDERs(c, d);
	do_CFFILEs(c, d);

done:
	de_free(c, d);
}

static int de_identify_cab(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "MSCF", 4))
		return 100;
	return 0;
}

void de_module_cab(deark *c, struct deark_module_info *mi)
{
	mi->id = "cab";
	mi->desc = "Microsoft Cabinet (CAB)";
	mi->run_fn = de_run_cab;
	mi->identify_fn = de_identify_cab;
}
