// This file is part of Deark.
// Copyright (C) 2022 Jason Summers
// See the file COPYING for terms of use.

// de_arch mini-library

#ifndef DEARK_FMTUTIL_H_INC
#include "deark-fmtutil.h"
#endif

struct de_arch_localctx_struct;
typedef struct de_arch_localctx_struct de_arch_lctx;
struct de_arch_member_data;

typedef void (*de_arch_decompressor_cbfn)(struct de_arch_member_data *md);

struct de_arch_member_data {
	deark *c;
	de_arch_lctx *d;
	i64 member_idx;
	i64 member_hdr_pos;
	i64 member_hdr_size;
	i64 member_total_size;
	i64 cmpr_len;
	i64 orig_len;
	i64 cmpr_pos;
	u32 crc_reported; // CRC of decompressed file
	u8 orig_len_known;
	u8 name_for_msgs_flag; // Internal use, 1 if name_for_msgs is "good"
	de_finfo *fi; // Created and destroyed automatically
	de_ucstring *filename; // Allocated by de_arch_create_md().
	de_ucstring *name_for_msgs; // Allocated by de_arch_create_md().
	de_ucstring *tmpfn_base; // Client allocates, freed automatically.
	de_ucstring *tmpfn_path; // Client allocates, freed automatically.
	UI set_name_flags; // e.g. DE_SNFLAG_FULLPATH
	UI dos_attribs;
	u8 is_encrypted;
	u8 has_dos_attribs;

	// Private use fields for the format decoder:
	void *userdata;
	UI cmpr_meth;
	UI file_flags;

	u8 validate_crc; // Tell de_arch_extract_member_file() to check crc_reported
	u8 behavior_on_wrong_crc; // 0=error, 1="Not available" warning
	u8 extracted_ok; // Status returned by de_arch_extract_member_file()

	// The de_arch_extract_member_file() will temporarily set dcmpri/dcmpro/dres,
	// and call ->dfn() if it is set.
	de_arch_decompressor_cbfn dfn;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
};

struct de_arch_localctx_struct {
	deark *c;
	int is_le;
	u8 need_errmsg;
	de_encoding input_encoding;
	i64 num_members;
	i64 cmpr_data_curpos;
	struct de_crcobj *crco; // decoder must create; is destroyed automatically
	int fatalerrflag;

	// Private use fields for the format decoder:
	void *userdata;
	i64 data_startpos;
	int stop_flag;
	UI fmtcode;
	int fmtver;
	int private1;
	UI archive_flags;
	struct de_arch_member_data *cur_md;
};

struct de_arch_member_data *de_arch_create_md(deark *c, de_arch_lctx *d);
void de_arch_destroy_md(deark *c, struct de_arch_member_data *md);
de_arch_lctx *de_arch_create_lctx(deark *c);
void de_arch_destroy_lctx(deark *c, de_arch_lctx *d);
void de_arch_fixup_path(de_ucstring *s, UI flags);
void de_arch_read_field_orig_len_p(struct de_arch_member_data *md, i64 *ppos);
void de_arch_read_field_cmpr_len_p(struct de_arch_member_data *md, i64 *ppos);
void de_arch_handle_field_dos_attr(struct de_arch_member_data *md, UI attr);
void de_arch_read_field_dos_attr_p(struct de_arch_member_data *md, i64 *ppos);

enum de_arch_tstype_enum {
	DE_ARCH_TSTYPE_UNIX=1,
	DE_ARCH_TSTYPE_UNIX_U,
	DE_ARCH_TSTYPE_DOS_DT,
	DE_ARCH_TSTYPE_DOS_TD,
	DE_ARCH_TSTYPE_DOS_DXT,
	DE_ARCH_TSTYPE_FILETIME
};
void de_arch_read_field_dttm_p(de_arch_lctx *d,
	struct de_timestamp *ts, const char *name,
	enum de_arch_tstype_enum tstype, i64 *ppos);

int de_arch_good_cmpr_data_pos(struct de_arch_member_data *md);
void de_arch_extract_member_file(struct de_arch_member_data *md);
