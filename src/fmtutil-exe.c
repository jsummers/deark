// This file is part of Deark.
// Copyright (C) 2023 Jason Summers
// See the file COPYING for terms of use.

// Shared functions specific to EXE format

#define DE_NOT_IN_MODULE
#include "deark-private.h"
#include "deark-fmtutil.h"

//#define DE_EXECOMP_DEVMODE

struct execomp_ctx {
	char shortname[40];
};

static void read_exe_testbytes(struct fmtutil_exe_info *ei)
{
	if(ei->have_testbytes) return;
	ei->have_testbytes = 1;
	dbuf_read(ei->f, ei->ep64b, ei->entry_point, sizeof(ei->ep64b));
	dbuf_read(ei->f, ei->ovl64b, ei->end_of_dos_code, sizeof(ei->ovl64b));
}

static void calc_entrypoint_crc(deark *c, struct fmtutil_exe_info *ei)
{
	struct de_crcobj *crco = NULL;
	u32 crc1, crc2;

	if(ei->have_epcrcs) return;
	ei->have_epcrcs = 1;

	read_exe_testbytes(ei);

	// Sniff some bytes, starting at the code entry point.
	crco = de_crcobj_create(c, DE_CRCOBJ_CRC32_IEEE);
	de_crcobj_addbuf(crco, &ei->ep64b[0], 32);
	crc1 = de_crcobj_getval(crco);
	de_crcobj_reset(crco);
	de_crcobj_addbuf(crco, &ei->ep64b[32], 32);
	crc2 = de_crcobj_getval(crco);
	ei->entrypoint_crcs = ((u64)crc1 << 32) | crc2;
#ifdef DE_EXECOMP_DEVMODE
	de_dbg(c, "execomp crc: %016"U64_FMTx, ei->entrypoint_crcs);
#endif

	de_crcobj_destroy(crco);
}

// Classify a potential PKLITE EXE file by the bytes at the entry point.
// flags:
//   0xff = default behavior
//   0x01 = only check for normal PKLITE versions
//   0x02 = only check for beta versions
//   0x04 = only check for Megalite
// Returns a classification code, or 0 if not detected.
UI fmtutil_detect_pklite_by_exe_ep(deark *c, const u8 *mem, i64 mem_len, UI flags)
{
	if(mem_len<64) return 0;

	if(flags & 0x01) {
		if(de_memmatch(mem, (const u8*)"\xb8??\xba??\x8c\xdb\x03\xd8\x3b", 11, '?', 0)) {
			return 100; // v1.00-1.05, etc.
		}
		if(de_memmatch(mem, (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x06", 11, '?', 0)) {
			return 112; // v1.12-1.15, etc.
		}
		if(de_memmatch(mem, (const u8*)"\x50\xb8??\xba??\x05\x00\x00\x3b", 11, '?', 0)) {
			return 150; // v2.01, etc.
		}
		if(de_memmatch(mem, (const u8*)"\x9c\xba?\x00\x2d?\x00\x81\xe1?\x00\x81", 12, '?', 0)) {
			return 250; // Patched by UN^2PACK v2.0?
		}
	}

	if(flags & 0x02) {
		if(de_memmatch(mem, (const u8*)"\x2e\x8c\x1e??\x8b\x1e\x02\x00\x8c\xda\x81", 12, '?', 0)) {
			return 90; // Normal beta
		}
		if(de_memmatch(mem, (const u8*)"\x2e\x8c\x1e??\xfc\x8c\xc8\x2e\x2b\x06", 11, '?', 0)) {
			return 91; // beta/loadhigh
		}
	}

	if(flags & 0x04) {
		if(de_memmatch(mem, (const u8*)"\xb8??\xba??\x05\x00\x00\x3b\x2d", 11, '?', 0)) {
			return 251; // Megalite
		}
	}

	return 0;
}

static void detect_execomp_pklite(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	UI epflags = 0;
	UI intro_class;

	if(ei->regIP==256 && ei->regCS==(-16) && ei->num_relocs<=2 &&
		ei->entry_point==ei->start_of_dos_code)
	{
		epflags |= 1; // Maybe a typical PKLITE file
	}
	else if(ei->regIP==256 && ei->regCS>(-16) && ei->num_relocs==0 &&
		ei->entry_point>ei->start_of_dos_code)
	{
		epflags |= 2; // Maybe beta
	}
	else if(ei->regCS==0 && ei->regIP==0 && ei->num_relocs==1 && ei->reloc_table_pos==28 &&
		ei->entry_point==ei->start_of_dos_code)
	{
		epflags |= 4; // Maybe Megalite
	}

	if(epflags==0) {
		goto done;
	}

	read_exe_testbytes(ei);
	intro_class = fmtutil_detect_pklite_by_exe_ep(c, ei->ep64b, sizeof(ei->ep64b), epflags);
	if(intro_class) {
		edd->detected_fmt = DE_SPECIALEXEFMT_PKLITE;
	}

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_PKLITE) {
		de_strlcpy(ectx->shortname, "PKLITE", sizeof(ectx->shortname));
		edd->modname = "pklite";
	}
}

static int is_lzexe091_entry_point(struct fmtutil_exe_info *ei, i64 cs, i64 ip)
{
	i64 n;
	i64 ep;

	ep = ei->start_of_dos_code + cs*16 + ip;

	n = (UI)dbuf_getu32be(ei->f, ep);
	if(n!=0x060e1f8bU) return 0;

	// If this is the right place, the *FAB* signature should be at offset 233.
	if(dbuf_memcmp(ei->f, ep+233, (const void*)"*FAB*", 5)) {
		return 0;
	}
	return 1;
}

static int look_for_pcx2exe(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	i64 cs, ip;

	if((ei->entrypoint_crcs>>32)!=0xf537be26U) return 0;
	ip = dbuf_getu16le(ei->f, ei->entry_point+53);
	if(ip!=0x000e) return 0;
	cs = dbuf_geti16le(ei->f, ei->entry_point+55);
	if(!is_lzexe091_entry_point(ei, cs, ip)) {
		return 0;
	}

	edd->regCS_2 = cs;
	edd->regIP_2 = ip;
	return 1;
}

static int detect_lhark_sfx(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd);

static void detect_execomp_lzexe(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	u8 flag = 0;

	if(ei->entrypoint_crcs==0x4b6802c9cf419437LLU) {
		edd->detected_subfmt = 1;
		flag = 1;
	}
	else if(ei->entrypoint_crcs==0x246655c50ae99574LLU) {
		edd->detected_subfmt = 2;
		flag = 1;
	}
	else if(ei->entrypoint_crcs==0xd8a60f138f680f0cLLU) {
		edd->detected_subfmt = 3;
		flag = 1;
	}
	else if(detect_lhark_sfx(c, ei, edd)) {
		edd->detected_subfmt = 102;
		flag = 1;
	}
	else if(look_for_pcx2exe(c, ei, edd)) {
		edd->detected_subfmt = 202;
		flag = 1;
	}

	if(flag) {
		edd->detected_fmt = DE_SPECIALEXEFMT_LZEXE;
		de_strlcpy(ectx->shortname, "LZEXE", sizeof(ectx->shortname));
		edd->modname = "lzexe";
	}
}

static void detect_execomp_exepack(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	u8 x, x2;
	UI n;
	int has_RB = 0;

	if(ei->num_relocs!=0) goto done;
	if(ei->regIP!=16 && ei->regIP!=18) goto done;

	if(dbuf_getu16be(ei->f, ei->entry_point-2) == 0x5242) {
		has_RB = 1;
	}

	if(ei->entrypoint_crcs==0xa6ea214e6c16ee72LLU) {
		edd->detected_subfmt = 5;
		goto done;
	}
	else if(ei->entrypoint_crcs==0xb11baad36c16ee72LLU) {
		edd->detected_subfmt = 6;
		goto done;
	}
	else if(ei->entrypoint_crcs==0x4e04abaac5d3b465LLU) {
		n = (UI)dbuf_getu32be(ei->f, ei->entry_point+72);
		if(n==0xe80500e8U) {
			edd->detected_subfmt = 12; // EXEPATCK-patched
			goto done;
		}

		edd->detected_subfmt = 4;
		goto done;
	}
	else if(ei->entrypoint_crcs==0x1f449ca73852e197LLU) {
		n = (UI)dbuf_getu32be(ei->f, ei->entry_point+66);
		if(n==0xe80500e8U) {
			edd->detected_subfmt = 12; // EXEPATCK-patched
			goto done;
		}

		x = dbuf_getbyte(ei->f, ei->entry_point+73);
		x2 = dbuf_getbyte(ei->f, ei->entry_point+137);
		if(x==0x0a && x2==0x27) {
			edd->detected_subfmt = 2;
			goto done;
		}
		else if(x==0x0a) {
			edd->detected_subfmt = 1;
			goto done;
		}
		else if(x==0x09) {
			edd->detected_subfmt = 3;
			goto done;
		}
	}
	else if(ei->entrypoint_crcs==0x1da67457b559a299LLU) {
		edd->detected_subfmt = 10; // David Fifield's exepack v1.3.0
	}
	else if(ei->entrypoint_crcs==0x629aca0c6520250aLLU) {
		// EXPAKFIX-patched file. Original variant undetermined (TODO?).
		edd->detected_subfmt = 11;
	}

	// TODO: Is SP always 128?
	if(ei->regSP==128 && has_RB) {
		edd->detected_fmt = DE_SPECIALEXEFMT_EXEPACK;
		goto done;
	}

done:
	if(edd->detected_subfmt!=0) {
		edd->detected_fmt = DE_SPECIALEXEFMT_EXEPACK;
	}

	if(edd->detected_fmt==DE_SPECIALEXEFMT_EXEPACK) {
#ifdef DE_EXECOMP_DEVMODE
		de_dbg(c, "epvar: %u", (UI)edd->detected_subfmt);
#endif
		de_strlcpy(ectx->shortname, "EXEPACK", sizeof(ectx->shortname));
		edd->modname = "exepack";
	}
}

static void detect_execomp_tinyprog(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	i64 pos;
	i64 j;
	u8 x;
	static const u8 *tpsig1 = (u8*)"\x50\xbe\x05\x01\x03\x36\x01\x01\x8c\xd2\x8c\xd8\x03\x44";

	if(ei->num_relocs!=0) goto done;
	pos = ei->entry_point;
	x = dbuf_getbyte(ei->f, pos);
	if(x!=0xe9) goto done;
	j = dbuf_getu16le(ei->f, pos+1);
	pos += 3+j; // Jump over user data

	x = dbuf_getbyte(ei->f, pos);
	if(x != 0xeb) goto done;
	j = dbuf_geti8(ei->f, pos+1);
	pos += 2+j; // Jump over (some sort of) data

	if(!dbuf_memcmp(ei->f, pos, (const void*)tpsig1, 14)) {
		; // Old version (e.g. "6/8/90")
	}
	else if(!dbuf_memcmp(ei->f, pos+8, (const void*)tpsig1, 14)) {
		; // Newer version (e.g. 3.0-3.9)
	}
	else {
		goto done;
	}

	edd->detected_fmt = DE_SPECIALEXEFMT_TINYPROG;
	de_strlcpy(ectx->shortname, "TINYPROG", sizeof(ectx->shortname));
done:
	;
}

static int execomp_diet_check_fingerprint(dbuf *f, i64 pos)
{
	u8 x;

	if(dbuf_memcmp(f, pos,
		(const u8*)"\x8e\xdb\x8e\xc0\x33\xf6\x33\xff\xb9\x08\x00\xf3\xa5\x4b\x48\x4a", 16))
	{
		return 0;
	}

	// Attempt to screen out LGLZ-compressed files (x==0x95).
	x = dbuf_getbyte(f, pos+26);
	if(x==0x8b) return 1;
	return 0;
}

static void detect_execomp_diet(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	static const u8 offsets[] = {20, 40, 45};
	i64 foundpos = 0;
	size_t i;

	if(ei->regCS!=0) goto done;
	if(ei->regIP!=0 && ei->regIP!=3) goto done;
	if(ei->num_relocs>1) goto done;

	// Haven't figured out a good way to detect DIET. More research needed.
	for(i=0; i<DE_ARRAYCOUNT(offsets); i++) {
		if(execomp_diet_check_fingerprint(ei->f, ei->entry_point+(i64)offsets[i])) {
			foundpos = (i64)offsets[i];
			break;
		}
	}
	if(foundpos==0) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_DIET;
	de_strlcpy(ectx->shortname, "DIET", sizeof(ectx->shortname));
	edd->modname = "diet";
done:
	;
}

static void detect_execomp_wwpack(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	if(ei->num_relocs!=0) goto done;
	if(ei->start_of_dos_code!=32) goto done;
	if(ei->entry_point==ei->start_of_dos_code) goto done;

	read_exe_testbytes(ei);
	if(!de_memmatch(ei->ep64b, (const u8*)"\xb8??\x8c\xca\x03\xd0\x8c\xc9\x81\xc1", 11, '?', 0)) {
		goto done;
	}

	edd->detected_fmt = DE_SPECIALEXEFMT_EXECOMP;
	de_strlcpy(ectx->shortname, "WWPACK", sizeof(ectx->shortname));
done:
	;
}

// Caller initializes ei (to zeroes).
// Records some basic information about an EXE file, to be used by routines that
// detect special EXE formats.
// The input file (f) must stay open after this. The detection routines will need
// to read more of it.
void fmtutil_collect_exe_info(deark *c, dbuf *f, struct fmtutil_exe_info *ei)
{
	i64 hdrsize; // in 16-byte units
	i64 lfb, nblocks;

	ei->f = f;
	lfb = dbuf_getu16le(f, 2);
	nblocks = dbuf_getu16le(f, 4);
	nblocks &= 0x7ff;
	ei->num_relocs = dbuf_getu16le(f, 6);
	hdrsize = dbuf_getu16le(f, 8);
	ei->start_of_dos_code = hdrsize*16;
	ei->regSS = dbuf_geti16le(f, 14);
	ei->regSP = dbuf_getu16le(f, 16);
	ei->regIP = dbuf_getu16le(f, 20);
	ei->regCS = dbuf_geti16le(f, 22);
	ei->reloc_table_pos = dbuf_getu16le(f, 24);
	ei->entry_point = (hdrsize + ei->regCS)*16 + ei->regIP;

	ei->end_of_dos_code = nblocks*512;
	if(lfb>=1 && lfb<=511) {
		ei->end_of_dos_code = ei->end_of_dos_code - 512 + lfb;
	}
	ei->overlay_len = f->len - ei->end_of_dos_code;
	if(ei->overlay_len<0) ei->overlay_len = 0;
}

// Caller supplies ei -- must call fmtutil_collect_exe_info() first.
// Caller initializes edd, to receive the results.
// If success, sets edd->detected_fmt to nonzero.
// Always sets edd->detected_fmt_name to something, even if "unknown".
// If we think we can decompress the format, sets edd->modname.
void fmtutil_detect_execomp(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	struct execomp_ctx ectx;

	de_zeromem(&ectx, sizeof(struct execomp_ctx));
	edd->detected_fmt = 0;
	edd->detected_subfmt = 0;

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_PKLITE) {
		detect_execomp_pklite(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_TINYPROG) {
		detect_execomp_tinyprog(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_DIET) {
		detect_execomp_diet(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0) {
		detect_execomp_wwpack(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	calc_entrypoint_crc(c, ei);

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_LZEXE) {
		detect_execomp_lzexe(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

	if(edd->restrict_to_fmt==0 || edd->restrict_to_fmt==DE_SPECIALEXEFMT_EXEPACK) {
		detect_execomp_exepack(c, &ectx, ei, edd);
		if(edd->detected_fmt!=0) goto done;
	}

done:
	de_strlcpy(edd->detected_fmt_name, (ectx.shortname[0]?ectx.shortname:"unknown"),
		sizeof(edd->detected_fmt_name));
}

// If found, writes a copy of pos to *pfoundpos.
static int is_lhalike_data_at(struct fmtutil_exe_info *ei, i64 pos, u8 h_or_z, i64 *pfoundpos)
{
	u8 b2[8];

	if(pos+21 > ei->f->len) return 0;
	dbuf_read(ei->f, b2, pos, sizeof(b2));
	if(b2[2]!='-' || b2[6]!='-') return 0;
	if(b2[3]=='l' && b2[4]==h_or_z) {
		*pfoundpos = pos;
		return 1;
	}
	return 0;
}

static int is_lha_data_at(struct fmtutil_exe_info *ei, i64 pos, i64 *pfoundpos)
{
	return is_lhalike_data_at(ei, pos, 'h', pfoundpos);
}

// Detect LHA/LHarc self-extracting DOS EXE formats.
// TODO: This is a work in progress.
static void detect_exesfx_lha(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	u8 b[16];
	int found;
	i64 foundpos = 0;

	if(ei->regSS != -16) goto done;
	if(ei->regSP != 256) goto done;
	if(ei->regCS != -16) goto done;
	if(ei->regIP != 256) goto done;

	dbuf_read(ei->f, b, 28, sizeof(b));
	if(b[4]!=0xeb && b[4]!=0xe9) goto done;
	if(b[8]=='L' && b[9]=='H') {
		;
	}
	else if(b[9]=='L' && b[10]=='H') {
		;
	}
	else if(b[10]=='L' && b[11]=='H') {
		;
	}
	else if(b[10]=='S' && b[11]=='F') { // v1.00
		;
	}
	else {
		goto done;
	}

	found =
		is_lha_data_at(ei, ei->end_of_dos_code, &foundpos) ||
		is_lha_data_at(ei, ei->end_of_dos_code+1, &foundpos) ||
		is_lha_data_at(ei, ei->end_of_dos_code+3, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1292-32, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1295-32, &foundpos) ||
		is_lha_data_at(ei, ei->entry_point + 1322-32, &foundpos);
	if(!found) goto done;

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<21) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "lha";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "LHA", sizeof(ectx->shortname));
	}
}

static void detect_exesfx_larc(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int found;
	i64 foundpos = 0;

	calc_entrypoint_crc(c, ei);
	if(ei->entrypoint_crcs!=0x81681852d3882b18ULL) {
		goto done;
	}

	found = is_lhalike_data_at(ei, ei->entry_point+525, 'z', &foundpos);
	if(!found) goto done;

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<21) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "lzs";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "LArc", sizeof(ectx->shortname));
	}
}

// CAR (MylesHi) SFX
static void detect_exesfx_car(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	i64 foundpos = 0;

	if(ei->overlay_len<27) goto done;
	if(ei->entry_point!=11566 || ei->regSS!=978) {
		goto done;
	}

	if(dbuf_memcmp(ei->f, 11256,
		(const void*)"\x43\x41\x52\x20\x53\x65\x6c\xd8\xf0\x6e\x23\xf8\x0a\x41\xdd\xfd", 16))
	{
		goto done;
	}

	if(!is_lhalike_data_at(ei, ei->end_of_dos_code, 'h', &foundpos)) {
		goto done;
	}

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "car";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "CAR (MylesHi!)", sizeof(ectx->shortname));
	}
}

// LZEXE modified for LHARK-SFX
// TODO? This function may be run twice by the "exe" module, which is okay,
//  but not ideal.
static int detect_lhark_sfx(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	int found;
	i64 foundpos = 0;
	i64 cs, ip;

	if(ei->num_relocs != 0) return 0;
	if(ei->regSP != 128) return 0;
	if(ei->start_of_dos_code != 32) return 0;

	// LHARK SFX uses a modified LZEXE 0.91 decompressor.
	// Try to find the original entry point, and record it in regCS_2/regIP_2.
	ip = dbuf_getu16le(ei->f, ei->entry_point+0x0f);
	cs = dbuf_getu16le(ei->f, ei->entry_point+0x11);
	if(!is_lzexe091_entry_point(ei, cs, ip)) {
		return 0;
	}

	found = is_lhalike_data_at(ei, ei->end_of_dos_code, 'h', &foundpos);
	if(!found) return 0;

	edd->regCS_2 = cs;
	edd->regIP_2 = ip;

	return 1;
}

static void detect_exesfx_lhark(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	if(!detect_lhark_sfx(c, ei, edd)) {
		goto done;
	}

	edd->payload_pos = ei->end_of_dos_code;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<28) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "lzh";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "LHARK", sizeof(ectx->shortname));
	}
}

static int is_arc_data_at(struct fmtutil_exe_info *ei, i64 pos)
{
	u8 b[2];

	dbuf_read(ei->f, b, pos, 2);
	if(b[0]!=0x1a) return 0;
	if(b[1]>30) return 0;
	return 1;
}

// Detect some ARC self-extracting DOS EXE formats.
// TODO: This is pretty fragile. It only detects files made by known versions of
// MKSARC (from the ARC distribution).
static void detect_exesfx_arc(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int found = 0;
	i64 foundpos = 0;

	calc_entrypoint_crc(c, ei);
	if(ei->entrypoint_crcs==0x057db6d8be3c4895ULL) { // MKSARC v1.00 from ARC v6.01
		found = 1;
		foundpos = ei->end_of_dos_code;
	}
	else if(ei->entrypoint_crcs==0x8542182a98613fe0ULL ||
		ei->entrypoint_crcs==0x6bd653c8edd98eedULL)
	{
		// MKSARC v1.01 from ARC v6.02
		// (Found two different versions with the same version number.)
		// This version of MKSARC has a bug. Compared to the v1.00, the start of DOS
		// code was reduced by 480, from 512 to 32. But the *end* of DOS code was not
		// adjusted accordingly, leaving it 480 higher than it should be. This is
		// important, because the end of DOS code is where we expect the ARC data to
		// start.
		found = 1;
		foundpos = ei->end_of_dos_code - 480;
		if(!is_arc_data_at(ei, foundpos)) {
			foundpos = ei->end_of_dos_code; // In case there's a version without the bug
		}
	}
	else if(ei->entrypoint_crcs==0x3230b4d5fca84644ULL || // MKSARC v7.12, from ARC v7.12
		ei->entrypoint_crcs==0x003d0e01c3764195ULL || // PKARC 3.5
		ei->entrypoint_crcs==0x1bbcf0ae0422828eULL || // PKARC 3.6
		ei->entrypoint_crcs==0x684ca6156c27b16bULL) // PKPAK 3.61
	{
		found = 1;
		foundpos = ei->end_of_dos_code;
	}
	// TODO: Detect MKSARC v7.12 with the /P option (OS/2 protected mode).
	// Extraction would work, if we could detect it.

	if(!found) goto done;
	if(!is_arc_data_at(ei, foundpos)) {
		goto done;
	}

	edd->payload_pos = foundpos;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<2) goto done;
	// TODO: It would be nice to strip any padding from the end of the extracted ARC
	// file, but that could be more trouble than it's worth.

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = 1;
	edd->payload_file_ext = "arc";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "ARC", sizeof(ectx->shortname));
	}
}

static void detect_exesfx_pak_nogate(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int found = 0;
	int canextract = 0;

	read_exe_testbytes(ei);
	if(ei->ovl64b[0]!=0x1a && ei->ovl64b[0]!=0xfe) goto done;

	if(!de_memcmp(ei->ep64b, (const u8*)"\x55\x8b\xec\x83\xec\x50", 6)) {
		// PAK 1.51-2.51
		found = 1;

		// There's a problem with PAK v1.6. If there are any file or archive
		// comments, the payload will not be in proper PAK format. We can't tell
		// if there are any file comments without scanning the whole payload.
		// That's doable (TODO), as is converting it back to proper PAK format.
		// But it's more trouble than it's probably worth. For now, we just don't
		// support v1.6.
		if(ei->entry_point != 2656) canextract = 1;
	}
	if(!found && !de_memcmp(ei->ep64b, (const u8*)"\xfb\xba\x53\x03\x2e\x89\x16\x65", 8)) {
		// GSARC 1.0 and PAK 1.0
		found = 1;
		canextract = 1;
	}

	if(!found) goto done;
	if(ei->ovl64b[0] != 0x1a) canextract = 0;

	edd->payload_pos = ei->end_of_dos_code;
	edd->payload_len = ei->f->len - edd->payload_pos;
	if(edd->payload_len<2) goto done;

	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_valid = canextract;
	edd->payload_file_ext = "pak";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "PAK", sizeof(ectx->shortname));
	}
}

// Also uses/updates edd->zip_eocd_* settings.
static void detect_exesfx_zip(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int ret;
	i64 foundpos = 0;

	if(!edd->zip_eocd_looked_for) {
		if(c->infile==ei->f && c->detection_data && c->detection_data->zip_eocd_looked_for) {
			edd->zip_eocd_looked_for = 1;
			edd->zip_eocd_found = c->detection_data->zip_eocd_found;
			edd->zip_eocd_pos = c->detection_data->zip_eocd_pos;
		}
		else {
			edd->zip_eocd_found = (u8)fmtutil_find_zip_eocd(c, c->infile, 0, &edd->zip_eocd_pos);
			edd->zip_eocd_looked_for = 1;
		}
	}

	if(!edd->zip_eocd_found) goto done;

	// Look for a ZIP file in the overlay (approximately)
	if(ei->overlay_len < 10) goto done; // Overlay too small

	ret = dbuf_search(ei->f, (const u8*)"PK\x03\x04", 4, ei->end_of_dos_code-10, 20,
		&foundpos);
	if(!ret) goto done;
	edd->detected_fmt = DE_SPECIALEXEFMT_ZIPSFX;

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_ZIPSFX) {
		de_strlcpy(ectx->shortname, "ZIP", sizeof(ectx->shortname));
	}
}

static void detect_exesfx_zoo(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	if(ei->overlay_len < 24) goto done;
	read_exe_testbytes(ei);
	if((UI)de_getu32le_direct(&ei->ovl64b[20]) != 0xfdc4a7dcU) goto done;

	calc_entrypoint_crc(c, ei);
	switch((UI)(ei->entrypoint_crcs>>32)) {
	case 0x6d384fa1U: // SEZ 2.00
	case 0xec5138deU: // SEZ 2.30
		// TODO: More Zoo SFX variants
		break;
	default:
		goto done;
	}

	edd->payload_pos = ei->end_of_dos_code;
	edd->payload_len = ei->overlay_len;
	edd->payload_valid = 1;
	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_file_ext = "zoo";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "Zoo", sizeof(ectx->shortname));
	}
}

#define ARJ_MIN_FILE_SIZE 84

// Notes:
// ARJ SFX was introduced in ARJ v0.15.
// v0.15-0.20: LZEXE compression, "LZ91" signature at offset 28.
// v1.00-2.00: DIET compression.
// v2.10: LZEXE compression, "LZ91" signature at offset 28.
// v2.20-?: LZEXE compression, "RJFX" signature at offset 28,
//  string "aRJsfX" appears in the first 1000 bytes of the executable.
// Each version has at least two SFX formats (-je and -je1).
// So, it's hard to identify ARJ SFX by its decompressor. Instead, we look for
// a valid ARJ archive starting near the beginning of the overlay segment.
// (TODO: ARJ32)
static void detect_exesfx_arj(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	int ret;
	i64 foundpos = 0;

	if(ei->overlay_len < ARJ_MIN_FILE_SIZE) goto done;

	// Aribrarily allow up to 16 extra bytes before the ARJ data starts.
	// Maybe 2 is sufficient. Dunno.
	ret = fmtutil_scan_for_arj_data(ei->f, ei->end_of_dos_code, 16, 0, &foundpos);

	if(ret) {
		edd->detected_fmt = DE_SPECIALEXEFMT_ARJSFX;
		edd->payload_pos = foundpos;
		edd->payload_len = ei->f->len - foundpos;
		edd->payload_valid = 1;
		goto done;
	}

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_ARJSFX) {
		de_strlcpy(ectx->shortname, "ARJ", sizeof(ectx->shortname));
	}
}

static void detect_exesfx_rar(deark *c, struct execomp_ctx *ectx,
	struct fmtutil_exe_info *ei, struct fmtutil_specialexe_detection_data *edd)
{
	// TODO: Lots more work to do here. Maybe better to delete the RSFX test.
	if(ei->overlay_len < 8) goto done;

	read_exe_testbytes(ei);

	if(de_memcmp(ei->ovl64b, "Rar!\x1a\x07", 6) &&
		de_memcmp(ei->ovl64b, "RE\x7e\x5e", 4))
	{
		goto done;
	}

	if(dbuf_memcmp(ei->f, 28, (const u8*)"RSFX", 4)) {
		goto done;
	}

	edd->payload_pos = ei->end_of_dos_code;
	edd->payload_len = ei->overlay_len;
	edd->payload_valid = 1;
	edd->detected_fmt = DE_SPECIALEXEFMT_SFX;
	edd->payload_file_ext = "rar";

done:
	if(edd->detected_fmt==DE_SPECIALEXEFMT_SFX) {
		de_strlcpy(ectx->shortname, "RAR", sizeof(ectx->shortname));
	}
}

void fmtutil_detect_exesfx(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd)
{
	struct execomp_ctx ectx;

	de_zeromem(&ectx, sizeof(struct execomp_ctx));

	detect_exesfx_zip(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_lha(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_arc(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_larc(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_car(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_lhark(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_pak_nogate(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_rar(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_zoo(c, &ectx, ei, edd);
	if(edd->detected_fmt) goto done;

	detect_exesfx_arj(c, &ectx, ei, edd);

done:
	de_strlcpy(edd->detected_fmt_name, (ectx.shortname[0]?ectx.shortname:"unknown"),
		sizeof(edd->detected_fmt_name));
}
