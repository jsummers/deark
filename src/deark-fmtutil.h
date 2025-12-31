// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#define DEARK_FMTUTIL_H_INC

struct de_lz77buffer;

struct de_dfilter_in_params {
	dbuf *f;
	i64 pos;
	i64 len;
	UI id; // Mainly for debugging
};

struct de_dfilter_out_params {
	dbuf *f;
	u8 len_known;
	i64 expected_len;
};

struct de_dfilter_results {
	// Note: If this struct is changed, also update de_dfilter_results_clear().
	int errcode;
	u8 bytes_consumed_valid;
	i64 bytes_consumed;
	char errmsg[80];
};

// de_module_in_params::obj1
// Used if in_params::flags & 0x02
struct fmtutil_bmp_mparams_indata {
	de_bitmap *img;
	de_finfo *fi;
	UI createflags;
};

struct de_bmpinfo {
#define DE_BMPINFO_FMT_BMP 0
#define DE_BMPINFO_FMT_PNG 1
	int file_format;

	int hotspot_x, hotspot_y;
	i64 bitsoffset; // Literal value from FILEHEADER
	i64 infohdrsize;
	i64 width;
	i64 height;
	i64 bitcount;
	u32 compression_field;
	i64 sizeImage_field;

	i64 bytes_per_pal_entry;
	i64 pal_entries;
	i64 num_colors; // For use in ICO/CUR file headers.
	i64 rowspan;

	i64 foreground_size;
	i64 mask_rowspan;
	i64 mask_size;

	i64 pal_bytes; // Size of palette in bytes
	i64 size_of_headers_and_pal; // Relative offset to bitmap (bitsoffset might be absolute)
	i64 total_size;

	int is_compressed;
	int is_topdown;
};

#define DE_BMPINFO_HAS_FILEHEADER 0x1
#define DE_BMPINFO_ICO_FORMAT     0x2
#define DE_BMPINFO_HAS_HOTSPOT    0x4
#define DE_BMPINFO_CMPR_IS_4CC    0x8
#define DE_BMPINFO_NOERR          0x10

void fmtutil_get_bmp_compression_name(u32 code, char *s, size_t s_len,
	int is_os2v2);
int fmtutil_get_bmpinfo(deark *c,  dbuf *f, struct de_bmpinfo *bi, i64 pos,
	i64 len, unsigned int flags);
void fmtutil_generate_bmpfileheader(deark *c, dbuf *outf, const struct de_bmpinfo *bi,
	i64 file_size_override);

void fmtutil_handle_exif2(deark *c, i64 pos, i64 len,
	u32 *returned_flags, u32 *orientation, u32 *exifversion);
void fmtutil_handle_exif(deark *c, i64 pos, i64 len);

void fmtutil_handle_iptc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags);

void fmtutil_handle_photoshop_rsrc2(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags, struct de_module_out_params *oparams);
void fmtutil_handle_photoshop_rsrc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags);

void fmtutil_handle_plist(deark *c, dbuf *f, i64 pos, i64 len,
	de_finfo *fi, unsigned int flags);

// Definition of a "simple" (non-pushable) codec
typedef void (*de_codectype1_type)(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

void fmtutil_decompress_uncompressed(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, UI flags);

struct de_packbits_params {
	UI nbytes_per_unit; // 0=default (1)
};
void fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_packbits_params *pbparams);
int fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed);
void fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags);
void fmtutil_decompress_stos_pictbank(deark *c, dbuf *inf,
	i64 picdatapos, i64 rledatapos, i64 pointspos,
	dbuf *unc_pixels, i64 unc_image_size);

struct de_pcpaint_rle_params {
	u8 one_block_mode;
	u8 obm_run_marker; // if one_block_mode
	u8 num_blocks_known; // if !one_block_mode
	i64 num_blocks; // if num_blocks_known
};
void fmtutil_pcpaintrle_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_pcxrle_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

#define DE_DEFLATEFLAG_ISZLIB 0x1
#define DE_DEFLATEFLAG_USEMAXUNCMPRSIZE 0x2 // only used with fmtutil_decompress_deflate()
#define DE_DEFLATEFLAG_DEFLATE64 0x4
struct de_deflate_params {
	unsigned int flags;
	struct de_lz77buffer *ringbuf_to_use; // (Uses the data only, not the callback)
};
int fmtutil_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags);
void fmtutil_decompress_deflate_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_deflate_params *params);
void fmtutil_deflate_codectype1_miniz(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_deflate_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

struct de_lzss1_params {
	UI flags;
};
void fmtutil_decompress_lzss1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	UI flags);
void fmtutil_lzss1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

void fmtutil_lzssmmfw_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_hlp_lz77_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_huff_squeeze_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_huff_packit_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
int fmtutil_decompress_exepack_reloc_tbl(deark *c, i64 pos1, i64 endpos, dbuf *outf);

void fmtutil_xpk_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
int fmtutil_xpk_ismethodsupported(u32 method);

void fmtutil_xpkMASH_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_ic1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

struct de_dfilter_ctx;
typedef void (*dfilter_codec_type)(struct de_dfilter_ctx *dfctx, void *codec_private_params);
typedef void (*dfilter_codec_addbuf_type)(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len);
typedef void (*dfilter_codec_command_type)(struct de_dfilter_ctx *dfctx, int cmd, UI flags);
typedef void (*dfilter_codec_finish_type)(struct de_dfilter_ctx *dfctx);
typedef void (*dfilter_codec_destroy_type)(struct de_dfilter_ctx *dfctx);

struct de_dfilter_ctx {
	deark *c;
	struct de_dfilter_results *dres;
	struct de_dfilter_out_params *dcmpro;
	i64 input_file_offset; // Non-critical, may be used by dbg messages
	u8 finished_flag;
	void *codec_private;
	dfilter_codec_addbuf_type codec_addbuf_fn;
	dfilter_codec_command_type codec_command_fn;
	dfilter_codec_finish_type codec_finish_fn;
	dfilter_codec_destroy_type codec_destroy_fn;
};

enum de_lzwfmt_enum {
	DE_LZWFMT_UNKNOWN = 0,
	DE_LZWFMT_UNIXCOMPRESS,
	DE_LZWFMT_GIF,
	DE_LZWFMT_ZIPSHRINK,
	DE_LZWFMT_ZOOLZD,
	DE_LZWFMT_TIFFOLD,
	DE_LZWFMT_TIFFNEW,
	DE_LZWFMT_ARC5,
	DE_LZWFMT_DWC,
	DE_LZWFMT_SHRINKIT1,
	DE_LZWFMT_SHRINKIT2,
	DE_LZWFMT_PAKLEO,
	DE_LZWFMT_ASC2COM
};

struct de_lzw_params {
	enum de_lzwfmt_enum fmt;
#define DE_LZWFLAG_HAS3BYTEHEADER       0x1 // Unix-compress style, use with fmt=UNIXCOMPRESS
#define DE_LZWFLAG_HAS1BYTEHEADER       0x2 // ARC style, use with fmt=UNIXCOMPRESS
#define DE_LZWFLAG_TOLERATETRAILINGJUNK 0x4
	UI flags;
	unsigned int gif_root_code_size;
	unsigned int max_code_size; // 0 = no info
	u8 arc5_has_stop_code;
};
void fmtutil_decompress_lzw(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_lzw_params *lzwp);

void fmtutil_ibmlzw_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

void dfilter_lzw_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);
void dfilter_rle90_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);
void dfilter_packbits_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);
void dfilter_deflate_codec_miniz(struct de_dfilter_ctx *dfctx,
	void *codec_private_params);

struct de_lh5x_params {
#define DE_LH5X_FMT_LH5     5
#define DE_LH5X_FMT_LH6     6
#define DE_LH5X_FMT_LH7     7
#define DE_LH5X_FMT_LHARK   100
	int fmt;

	// How to handle a block with "0" codes:
#define DE_LH5X_ZCB_ERROR 0
#define DE_LH5X_ZCB_STOP  1
#define DE_LH5X_ZCB_0     2
#define DE_LH5X_ZCB_65536 3
	u8 zero_codes_block_behavior;
	u8 warn_about_zero_codes_block;

	u8 history_fill_val; // Set to 0x20 (space) if not sure.

	// Returned to caller:
	i64 max_offset_used;
};
void fmtutil_decompress_lh5x(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_lh5x_params *lzhp);
void fmtutil_lh5x_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

struct de_fax34_params {
	i64 image_width;
	i64 image_height;
	i64 out_rowspan;
	UI tiff_cmpr_meth;
	u8 is_lsb;
	u32 t4options;
	u32 t6options;
};
void fmtutil_fax34_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

struct de_dfilter_ctx *de_dfilter_create(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);
void de_dfilter_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len);
#define DE_DFILTER_COMMAND_SOFTRESET      1
#define DE_DFILTER_COMMAND_REINITIALIZE   2
#define DE_DFILTER_COMMAND_FINISH_BLOCK   3
#define DE_DFILTER_COMMAND_RESET_COUNTERS 4
void de_dfilter_command(struct de_dfilter_ctx *dfctx, int cmd, UI flags);
void de_dfilter_addslice(struct de_dfilter_ctx *dfctx,
	dbuf *inf, i64 pos, i64 len);
void de_dfilter_finish(struct de_dfilter_ctx *dfctx);
void de_dfilter_destroy(struct de_dfilter_ctx *dfctx);
void de_dfilter_transfer_error(deark *c, struct de_dfilter_results *src,
	struct de_dfilter_results *dst);
void de_dfilter_transfer_error2(deark *c, struct de_dfilter_results *src,
	struct de_dfilter_results *dst, const char *dst_modname);

void de_dfilter_decompress_oneshot(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);
struct de_dcmpr_two_layer_params {
	de_codectype1_type codec1_type1; // Set either this or codec1_pushable
	dfilter_codec_type codec1_pushable;
	void *codec1_private_params;
	dfilter_codec_type codec2;
	void *codec2_private_params;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	u8 intermed_len_known;
	i64 intermed_expected_len;
};
void de_dfilter_decompress_two_layer(deark *c, struct de_dcmpr_two_layer_params *tlp);

void fmtutil_decompress_zip_shrink(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *params);

struct de_zipreduce_params {
	unsigned int cmpr_factor;
};
void fmtutil_decompress_zip_reduce(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_zipreduce_params *params);

struct de_zipimplode_params {
	unsigned int bit_flags;
	u8 mml_bug;
};
void fmtutil_decompress_zip_implode(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct de_zipimplode_params *params);

void fmtutil_dclimplode_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void fmtutil_distilled_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

struct de_lzstac_params {
	UI flags;
};
void fmtutil_lzstac_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);

void fmtutil_get_lzhuf_d_code_and_len(UI n, UI *pd_code, UI *pd_len);

struct de_lh1_params {
	u8 is_crlzh11, is_crlzh20;
	u8 is_arc_trimmed; // (The LZH part of the scheme. Does not do RLE.)
	u8 is_dms_deep; // (The LZH part of the scheme.)
	u8 history_fill_val; // Set to 0x20 (space) if not sure.
};

void fmtutil_lh1_codectype1(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	void *codec_private_params);
void dfilter_lh1_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);

// Wrapper for miniz' tdefl functions

enum fmtutil_tdefl_status {
	FMTUTIL_TDEFL_STATUS_BAD_PARAM      = -2,
	FMTUTIL_TDEFL_STATUS_PUT_BUF_FAILED = -1,
	FMTUTIL_TDEFL_STATUS_OKAY           = 0,
	FMTUTIL_TDEFL_STATUS_DONE           = 1
};

enum fmtutil_tdefl_flush {
	FMTUTIL_TDEFL_NO_FLUSH   = 0,
	FMTUTIL_TDEFL_SYNC_FLUSH = 2,
	FMTUTIL_TDEFL_FULL_FLUSH = 3,
	FMTUTIL_TDEFL_FINISH     = 4
};

struct fmtutil_tdefl_ctx;
struct fmtutil_tdefl_ctx *fmtutil_tdefl_create(deark *c, dbuf *outf, int flags);
enum fmtutil_tdefl_status fmtutil_tdefl_compress_buffer(struct fmtutil_tdefl_ctx *tdctx,
	const void *pIn_buf, size_t in_buf_size, enum fmtutil_tdefl_flush flush);
void fmtutil_tdefl_destroy(struct fmtutil_tdefl_ctx *tdctx);
unsigned int fmtutil_tdefl_create_comp_flags_from_zip_params(int level, int window_bits,
	int strategy);

struct de_SAUCE_info {
	int is_valid;
	de_ucstring *title;
	de_ucstring *artist;
	de_ucstring *organization;
	struct de_timestamp creation_date;
	i64 original_file_size;
	u8 data_type;
	u8 file_type;
	u8 tflags;
	i64 width_in_chars; // 0 if unknown
	i64 number_of_lines; // Reported value. May be incorrect.
	i64 comment_block_pos; // Valid if num_comments>0.
	u16 tinfo1, tinfo2, tinfo3, tinfo4;
	de_ucstring *comment; // NULL if there is no comment
};

int fmtutil_detect_SAUCE(deark *c, dbuf *f, struct de_SAUCE_detection_data *sdd,
	unsigned int flags);
void fmtutil_handle_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si);
struct de_SAUCE_info *fmtutil_create_SAUCE(deark *c);
void fmtutil_free_SAUCE(deark *c, struct de_SAUCE_info *si);

struct de_boxesctx;

// Return 0 to stop reading
typedef int (*de_handle_box_fn)(deark *c, struct de_boxesctx *bctx);
typedef void (*de_identify_box_fn)(deark *c, struct de_boxesctx *bctx);

struct de_boxdata {
	// Per-box info supplied to handle_box_fn:
	struct de_boxdata *parent;
	int level;
	u32 boxtype;
	int is_uuid;
	u8 uuid[16]; // Valid only if is_uuid is set.
	i64 box_pos;
	i64 box_len;
	// Note: for UUID boxes, payload does not include the UUID
	i64 payload_pos;
	i64 payload_len;

	// To be filled in by identify_box_fn:
	void *box_userdata;
	const char *box_name;

	// To be filled in by handle_box_fn:
	int handled;
	int is_superbox;
	int num_children_is_known;
	i64 num_children; // valid if (is_superbox) && (num_children_is_known)
	i64 extra_bytes_before_children; // valid if (is_superbox)
};

struct de_boxesctx {
	void *userdata;
	void *private_data; // Used by the parser
	dbuf *f; // Input file
	de_identify_box_fn identify_box_fn;
	de_handle_box_fn handle_box_fn;

	struct de_boxdata *curbox;
};

double dbuf_fmtutil_read_fixed_16_16(dbuf *f, i64 pos);
int fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx);
void fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx);
void fmtutil_render_uuid(deark *c, const u8 *uuid, char *s, size_t s_len);
void fmtutil_guid_to_uuid(u8 *id);

struct atari_img_decode_data {
	i64 bpp;
	i64 ncolors;
	i64 w, h;
	dbuf *unc_pixels;
	int was_compressed;
	int is_spectrum512;
	de_color *pal;
	de_bitmap *img;
};

#define DE_FLAG_ATARI_15BIT_PAL 0x2
void fmtutil_read_atari_palette(deark *c, dbuf *f, i64 pos,
	de_color *dstpal, i64 ncolors_to_read, i64 ncolors_used, unsigned int flags);

int fmtutil_atari_decode_image(deark *c, struct atari_img_decode_data *adata);
void fmtutil_atari_set_standard_density(deark *c, struct atari_img_decode_data *adata,
	de_finfo *fi);
void fmtutil_atari_help_palbits(deark *c);

// The IFF parser supports IFF and similar formats, including RIFF.
struct de_iffctx;

// An IFF chunk handler is expected to do one of the following (if it returns 1):
// - Set ictx->is_std_container (ictx->handled is ignored).
// - Set ictx->is_raw_container (ictx->handled is ignored).
// - Handle the chunk, and set ictx->handled.
// - Do nothing, and set ictx->handled, to suppress default handling.
// - Do nothing, which will result in the default chunk handler being used.
//    Usually the default handler will do nothing, or a hex dump if the
//    debug_level is high enough. If the format is known to have standard
//    IFF chunks or something like that, they may be parsed.
// Return value: Normally 1; 0 to immediately stop processing the entire file.
typedef int (*de_handle_iff_chunk_fn)(struct de_iffctx *ictx);

// Mainly for identifying the chunk.
// The user can also adjust ictx->chunkctx->dlen.
// Return value: Normally 1 (reserved)
typedef int (*de_preprocess_iff_chunk_fn)(struct de_iffctx *ictx);

// Return value: Normally 1; 0 to immediately stop processing the entire file.
typedef int (*de_on_iff_container_end_fn)(struct de_iffctx *ictx);

// Return value: Normally 1; 0 to stop processing this container (the
// on_container_end_fn will not be called).
typedef int (*de_on_std_iff_container_start_fn)(struct de_iffctx *ictx);

// Caller can check for nonstandard non-chunk data at 'pos'. If found, set *plen
// to its length, process it if desired, and return 1.
typedef int (*de_handle_nonchunk_iff_data_fn)(struct de_iffctx *ictx,
	i64 pos, i64 *plen);

struct de_iffchunkctx {
	struct de_fourcc chunk4cc;
	i64 pos;
	i64 len;
	i64 dpos;
	i64 dlen;
	struct de_iffchunkctx *parent;

	// To be filled in by identify_chunk_fn:
	const char *chunk_name;

	// Other use:
	u32 user_flags;
};

struct de_iffctx {
	deark *c;
	void *private_data; // Used by the parser

	void *userdata;
	dbuf *f; // Input file
	de_handle_iff_chunk_fn handle_chunk_fn;
	de_preprocess_iff_chunk_fn preprocess_chunk_fn;

	// Called after the "FORM type" is read
	de_on_std_iff_container_start_fn on_std_container_start_fn;

	de_on_iff_container_end_fn on_container_end_fn;
	de_handle_nonchunk_iff_data_fn handle_nonchunk_data_fn;
	i64 alignment; // 0 = default
	i64 sizeof_len; // 0 = default
	int is_le; // For RIFF format
	u8 reversed_4cc;
	u8 has_standard_iff_chunks;
	de_encoding input_encoding;

	int level;

	// Info about the most-recent top-level container:
	struct de_fourcc main_fmt4cc; // E.g. "FORM"
	struct de_fourcc main_contentstype4cc; // E.g. "ILBM"

	// Current container:
	struct de_fourcc curr_container_fmt4cc;
	struct de_fourcc curr_container_contentstype4cc;

	// Per-chunk info supplied to chunk handling functions:
	struct de_iffchunkctx *chunkctx;

	// To be filled in by handle_chunk_fn:
	int handled;
	int is_std_container;
	int is_raw_container;
};

struct de_iffctx *fmtutil_create_iff_decoder(deark *c);
void fmtutil_destroy_iff_decoder(struct de_iffctx *ictx);
void fmtutil_read_iff_format(struct de_iffctx *ictx, i64 pos, i64 len);

const char *fmtutil_tiff_orientation_name(i64 n);
const char *fmtutil_get_windows_charset_name(u8 cs);
const char *fmtutil_get_windows_cb_data_type_name(unsigned int ty);

int fmtutil_find_zip_eocd(deark *c, dbuf *f, UI flags, i64 *foundpos);

struct de_id3info {
	int has_id3v1, has_id3v2;
	i64 main_start, main_end;
};
void fmtutil_handle_id3(deark *c, dbuf *f, struct de_id3info *id3i,
	unsigned int flags);

struct de_advfile;

struct de_advfile_cbparams {
#define DE_ADVFILE_WRITEMAIN 1
#define DE_ADVFILE_WRITERSRC 2
	int whattodo;
	dbuf *outf;
};

typedef int (*de_advfile_cbfn)(deark *c, struct de_advfile *advf,
	struct de_advfile_cbparams *afp);

struct de_advfile_forkinfo {
	u8 fork_exists;
	i64 fork_len;
	de_finfo *fi; // Note: do not set the name; use de_advfile.filename.
	void *userdata_for_writelistener;
	de_writelistener_cb_type writelistener_cb;
};

struct de_advfile {
	deark *c;
	void *userdata;
	struct de_advfile_forkinfo mainfork;
	struct de_advfile_forkinfo rsrcfork;
	de_advfile_cbfn writefork_cbfn;
	de_ucstring *filename;
	unsigned int snflags; // flags for de_finfo_set_name*
	unsigned int createflags;
	u8 enable_wbuffer;
	u8 original_filename_flag;
	u8 originally_appledouble;
	u8 has_typecode;
	u8 has_creatorcode;
	u8 has_finderflags;
	u16 finderflags;
	size_t orig_filename_len;
	u8 *orig_filename;
	u8 typecode[4];
	u8 creatorcode[4];
};

struct de_advfile *de_advfile_create(deark *c);
void de_advfile_destroy(struct de_advfile *advf);
void de_advfile_set_orig_filename(struct de_advfile *advf, const char *fn, size_t fnlen);
void de_advfile_run(struct de_advfile *advf);

void de_dfilter_set_errorf(deark *c, struct de_dfilter_results *dres, const char *modname,
	const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 4, 5)));
void de_dfilter_set_generic_error(deark *c, struct de_dfilter_results *dres, const char *modname);
const char *de_dfilter_get_errmsg(deark *c, struct de_dfilter_results *dres);
void de_dfilter_results_clear(deark *c, struct de_dfilter_results *dres);
void de_dfilter_init_objects(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);

struct de_riscos_file_attrs {
	u8 file_type_known;
	u32 load_addr, exec_addr;
	u32 attribs;
	unsigned int file_type;
	unsigned int lzwmaxbits;
	u32 crc_from_attribs;
	struct de_timestamp mod_time;
};

void fmtutil_riscos_read_load_exec(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa, i64 pos1);
#define DE_RISCOS_FLAG_HAS_CRC          0x1
#define DE_RISCOS_FLAG_HAS_LZWMAXBITS   0x2
void fmtutil_riscos_read_attribs_field(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa,
	i64 pos, unsigned int flags);
void fmtutil_riscos_append_type_to_filename(deark *c, de_finfo *fi, de_ucstring *fn,
	struct de_riscos_file_attrs *rfa, int is_dir, int enabled_by_default);

struct fmtutil_macbitmap_info {
	i64 rowbytes; // The rowBytes field
	i64 rowspan; // Actual number of bytes/row
	i64 npwidth, pdwidth, height;
	int is_uncompressed;
	i64 packing_type;
	i64 pixeltype, pixelsize;
	i64 cmpcount, cmpsize;
	double hdpi, vdpi;
	u32 pmTable;
	int pixmap_flag;
	int has_colortable; // Does the file contain a colortable for this bitmap?
	int uses_pal; // Are we using the palette below?
	i64 num_pal_entries;
	de_color pal[256];
};

void fmtutil_macbitmap_read_baseaddr(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos);
void fmtutil_macbitmap_read_rowbytes_and_bounds(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos);
void fmtutil_macbitmap_read_pixmap_only_fields(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos);
int fmtutil_macbitmap_read_colortable(deark *c, dbuf *f,
	struct fmtutil_macbitmap_info *bi, i64 pos, i64 *bytes_used);

i64 fmtutil_hlp_get_cus_p(dbuf *f, i64 *ppos);
i64 fmtutil_hlp_get_css_p(dbuf *f, i64 *ppos);
i64 fmtutil_hlp_get_cul_p(dbuf *f, i64 *ppos);
i64 fmtutil_hlp_get_csl_p(dbuf *f, i64 *ppos);

#define FMTUTIL_HUFFMAN_MAX_CODE_LENGTH 48
typedef i32 fmtutil_huffman_valtype;
struct fmtutil_huffman_codebook;
struct fmtutil_huffman_cursor;
struct fmtutil_huffman_code_builder;
struct fmtutil_huffman_decoder {
	struct fmtutil_huffman_cursor *cursor;
	struct fmtutil_huffman_codebook *bk;
	struct fmtutil_huffman_code_builder *builder;
};
struct fmtutil_huffman_decoder *fmtutil_huffman_create_decoder(deark *c, i64 initial_codes, i64 max_codes);
void fmtutil_huffman_destroy_decoder(deark *c, struct fmtutil_huffman_decoder *ht);
void fmtutil_huffman_reset_cursor(struct fmtutil_huffman_cursor *cursor);
int fmtutil_huffman_add_code(deark *c, struct fmtutil_huffman_codebook *bk,
	u64 code, UI code_nbits, fmtutil_huffman_valtype val);
int fmtutil_huffman_decode_bit(struct fmtutil_huffman_codebook *bk, struct fmtutil_huffman_cursor *cursor,
	u8 bitval, fmtutil_huffman_valtype *pval);
int fmtutil_huffman_read_next_value(struct fmtutil_huffman_codebook *bk,
	struct de_bitreader *bitrd, fmtutil_huffman_valtype *pval, UI *pnbits);
UI fmtutil_huffman_get_max_bits(struct fmtutil_huffman_codebook *bk);
i64 fmtutil_huffman_get_num_codes(struct fmtutil_huffman_codebook *bk);
void fmtutil_huffman_dump(deark *c, struct fmtutil_huffman_decoder *ht);
int fmtutil_huffman_record_a_code_length(deark *c, struct fmtutil_huffman_code_builder *builder,
	fmtutil_huffman_valtype val, UI len);
i64 fmtutil_huffman_hcb_get_num_codes(struct fmtutil_huffman_code_builder *builder);
#define FMTUTIL_MCTFLAG_LEFT_ALIGN_LEAVES     0x0 // default
#define FMTUTIL_MCTFLAG_LEFT_ALIGN_BRANCHES   0x1
#define FMTUTIL_MCTFLAG_LAST_CODE_FIRST       0x2 // Pretend codes were added in the reverse order
int fmtutil_huffman_make_canonical_code(deark *c, struct fmtutil_huffman_codebook *bk,
	struct fmtutil_huffman_code_builder *builder, UI flags, const char *title);

typedef void (*fmtutil_lz77buffer_cb_type)(struct de_lz77buffer *rb, u8 n);

struct de_lz77buffer {
	void *userdata;
	fmtutil_lz77buffer_cb_type writebyte_cb;
	UI curpos; // Must be kept valid at all times (0...bufsize-1)
	UI mask;
	UI bufsize; // Required to be a power of 2
	u8 *buf;
};
 struct de_lz77buffer *de_lz77buffer_create(deark *c, UI bufsize);
 void de_lz77buffer_destroy(deark *c, struct de_lz77buffer *rb);
 void de_lz77buffer_clear(struct de_lz77buffer *rb, UI val);
 void de_lz77buffer_set_curpos(struct de_lz77buffer *rb, UI newpos);
 void de_lz77buffer_add_literal_byte(struct de_lz77buffer *rb, u8 b);
 void de_lz77buffer_copy_from_hist(struct de_lz77buffer *rb, UI startpos, UI count);

 struct fmtutil_exe_info {
	dbuf *f;
	i64 num_relocs;
	i64 regSS;
	i64 regSP;
	i64 regCS;
	i64 regIP;
	i64 reloc_table_pos;
	i64 start_of_dos_code;
	i64 entry_point;
	i64 end_of_dos_code;
	i64 overlay_len;
	i64 ext_hdr_pos;
	u8 is_extended;
	u8 is_ne;
	u8 is_pe;
	u8 is_dll;
	u8 have_epcrcs;
	u8 have_testbytes; // Are ep/ovl fields populated?
	u64 entrypoint_crcs;
	u8 ep64b[64]; // Some bytes at entry point
	u8 ovl64b[64]; // Some bytes in overlay
};
void fmtutil_collect_exe_info(deark *c, dbuf *f, struct fmtutil_exe_info *ei);

#define DE_SPECIALEXEFMT_LZEXE     1
#define DE_SPECIALEXEFMT_PKLITE    2
#define DE_SPECIALEXEFMT_EXEPACK   3
#define DE_SPECIALEXEFMT_DIET      4
#define DE_SPECIALEXEFMT_TINYPROG  5
#define DE_SPECIALEXEFMT_EXECOMP   99 // Misc. unsupported executable compression
#define DE_SPECIALEXEFMT_SFX       100 // Generic extractable self-extracting archive
#define DE_SPECIALEXEFMT_ZIPSFX    101
#define DE_SPECIALEXEFMT_ARJSFX    102
#define DE_SPECIALEXEFMT_PAK16SFX  103
#define DE_SPECIALEXEFMT_ISHIELDNE 110
#define DE_SPECIALEXEFMT_GWS_EXEPIC 201 // Graphic Workshop
#define DE_SPECIALEXEFMT_READMAKE   202
#define DE_SPECIALEXEFMT_TEXE       203
#define DE_SPECIALEXEFMT_READAMATIC 204
#define DE_SPECIALEXEFMT_TEXTLIFE   205
#define DE_SPECIALEXEFMT_GRABBER    206
#define DE_SPECIALEXEFMT_DSKEXP     207

 struct fmtutil_specialexe_detection_data {
	u8 restrict_to_fmt; // DE_SPECIALEXEFMT_*; 0 = any
	u8 detected_fmt; // DE_SPECIALEXEFMT_*; 0 = unknown
	u8 detected_subfmt;
	u8 payload_valid;
	u8 zip_eocd_looked_for;
	u8 zip_eocd_found;
	UI flags_in; // 0x1 = set when called by main exe module
	UI flags_out; // format-specific
	i64 payload_pos;
	i64 payload_len;
	i64 special_pos_1; // format-specific
	i64 zip_eocd_pos;
	i64 regCS_2; // For some patched files, the original CS/IP
	i64 regIP_2;
	const char *payload_file_ext;
	const char *modname; // Non-NULL if we think we can decompress
	char detected_fmt_name[40];
};
void fmtutil_detect_execomp(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd);
void fmtutil_detect_exesfx(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd);
void fmtutil_detect_specialexe(deark *c, struct fmtutil_exe_info *ei,
	struct fmtutil_specialexe_detection_data *edd);
int fmtutil_scan_for_arj_data(dbuf *f, i64 startpos, i64 max_skip,
	UI flags, i64 *pfoundpos);
void fmtutil_get_std_jpeg_qtable(UI tbl_id, u8 tbl[64]);
void fmtutil_write_std_jpeg_dht(dbuf *outf, UI tbl_id);
UI fmtutil_detect_pklite_by_exe_ep(deark *c, const u8 *mem, i64 mem_len, UI flags);

struct fmtutil_char_simplectx {
	dbuf *inf;
	i64 inf_pos;
	i64 inf_len;
	de_encoding input_encoding;
	u8 use_default_pal;
	u8 nonblink;
	i64 width_in_chars, height_in_chars;
	i64 fg_stride, attr_offset;
};
void fmtutil_char_simple_run(deark *c, struct fmtutil_char_simplectx *csctx,
	struct de_char_context *charctx);

struct fmtutil_fmtid_ctx {
	// default mode 0 = Detect all fmts that are reasonably portable.
#define FMTUTIL_FMTIDMODE_ALL_IMG     1
#define FMTUTIL_FMTIDMODE_ISH_SFX     10
	u8 mode;
	u8 have_bof64bytes;
	const char *default_ext;
	dbuf *inf; // Can be NULL if have_bof64bytes is set, but may reduce quality.
	i64 inf_pos;
	i64 inf_len;
	u8 bof64bytes[64];

#define FMTUTIL_FMTID_OTHER   1 // Used when we only need the extension.
#define FMTUTIL_FMTID_JPEG    10
#define FMTUTIL_FMTID_BMP     11
#define FMTUTIL_FMTID_PNG     12
#define FMTUTIL_FMTID_GIF     13
#define FMTUTIL_FMTID_TIFF    14
#define FMTUTIL_FMTID_CDR     17
#define FMTUTIL_FMTID_WAVE    40
#define FMTUTIL_FMTID_ZIP     60
	UI fmtid; // 0 = unknown
	char ext_sz[8];
};

void fmtutil_fmtid(deark *c, struct fmtutil_fmtid_ctx *idctx);
