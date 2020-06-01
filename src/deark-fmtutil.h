// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

struct de_dfilter_in_params {
	dbuf *f;
	i64 pos;
	i64 len;
};

struct de_dfilter_out_params {
	dbuf *f;
	u8 len_known;
	i64 expected_len;
};

struct de_dfilter_results {
	int errcode;
	u8 bytes_consumed_valid;
	i64 bytes_consumed;
	char errmsg[80];
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

void de_fmtutil_get_bmp_compression_name(u32 code, char *s, size_t s_len,
	int is_os2v2);
int de_fmtutil_get_bmpinfo(deark *c,  dbuf *f, struct de_bmpinfo *bi, i64 pos,
	i64 len, unsigned int flags);
void de_fmtutil_generate_bmpfileheader(deark *c, dbuf *outf, const struct de_bmpinfo *bi,
	i64 file_size_override);

void de_fmtutil_handle_exif2(deark *c, i64 pos, i64 len,
	u32 *returned_flags, u32 *orientation, u32 *exifversion);
void de_fmtutil_handle_exif(deark *c, i64 pos, i64 len);

void de_fmtutil_handle_iptc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags);

void de_fmtutil_handle_photoshop_rsrc2(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags, struct de_module_out_params *oparams);
void de_fmtutil_handle_photoshop_rsrc(deark *c, dbuf *f, i64 pos, i64 len,
	unsigned int flags);

void de_fmtutil_handle_plist(deark *c, dbuf *f, i64 pos, i64 len,
	de_finfo *fi, unsigned int flags);

void fmtutil_decompress_uncompressed(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, UI flags);

#define DE_DEFLATEFLAG_ISZLIB 0x1
#define DE_DEFLATEFLAG_USEMAXUNCMPRSIZE 0x2
int fmtutil_decompress_deflate(dbuf *inf, i64 inputstart, i64 inputsize, dbuf *outf,
	i64 maxuncmprsize, i64 *bytes_consumed, unsigned int flags);
void fmtutil_decompress_deflate_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags, const u8 *starting_dict);

void de_fmtutil_decompress_packbits_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);
int de_fmtutil_decompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed);
void de_fmtutil_decompress_packbits16_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);
int de_fmtutil_decompress_packbits16(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed);
void de_fmtutil_decompress_rle90_ex(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags);
void fmtutil_decompress_szdd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags);
void fmtutil_decompress_hlp_lz77(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);

struct de_dfilter_ctx;
typedef void (*dfilter_codec_type)(struct de_dfilter_ctx *dfctx, void *codec_private_params);
typedef void (*dfilter_codec_addbuf_type)(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len);
typedef void (*dfilter_codec_finish_type)(struct de_dfilter_ctx *dfctx);
typedef void (*dfilter_codec_destroy_type)(struct de_dfilter_ctx *dfctx);

struct de_dfilter_ctx {
	deark *c;
	struct de_dfilter_results *dres;
	struct de_dfilter_out_params *dcmpro;
	u8 finished_flag;
	void *codec_private;
	dfilter_codec_addbuf_type codec_addbuf_fn;
	dfilter_codec_finish_type codec_finish_fn;
	dfilter_codec_destroy_type codec_destroy_fn;
};

enum lzwfmt_enum {
	DE_LZWFMT_GENERIC = 0,
	DE_LZWFMT_UNIXCOMPRESS,
	DE_LZWFMT_GIF,
	DE_LZWFMT_ZIPSHRINK,
	DE_LZWFMT_ZOOLZD
};

struct delzw_params {
	enum lzwfmt_enum fmt;
#define DE_LZWFLAG_HAS3BYTEHEADER       0x1 // Unix-compress style, use with fmt=UNIXCOMPRESS
#define DE_LZWFLAG_HAS1BYTEHEADER       0x2 // ARC style, use with fmt=UNIXCOMPRESS
#define DE_LZWFLAG_TOLERATETRAILINGJUNK 0x4
	UI flags;
	unsigned int gif_root_code_size;
	unsigned int max_code_size; // 0 = no info
};
void de_fmtutil_decompress_lzw(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	struct delzw_params *delzwp);

void dfilter_rle90_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);
void dfilter_hlp_lz77_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);

struct de_dfilter_ctx *de_dfilter_create(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);
void de_dfilter_addbuf(struct de_dfilter_ctx *dfctx,
	const u8 *buf, i64 buf_len);
void de_dfilter_finish(struct de_dfilter_ctx *dfctx);
void de_dfilter_destroy(struct de_dfilter_ctx *dfctx);

void de_dfilter_decompress_oneshot(deark *c,
	dfilter_codec_type codec_init_fn, void *codec_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);
 void de_dfilter_decompress_two_layer(deark *c,
	dfilter_codec_type codec1, void *codec1_private_params,
	dfilter_codec_type codec2, void *codec2_private_params,
	struct de_dfilter_in_params *dcmpri, struct de_dfilter_out_params *dcmpro,
	struct de_dfilter_results *dres);

void dfilter_lzw_codec(struct de_dfilter_ctx *dfctx, void *codec_private_params);
struct de_dfilter_ctx *de_dfilter_create_delzw(deark *c, struct delzw_params *delzwp,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);

void fmtutil_decompress_zip_shrink(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int flags);
void fmtutil_decompress_zip_reduce(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int cmpr_factor, unsigned int flags);
void fmtutil_decompress_zip_implode(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres,
	unsigned int bit_flags, unsigned int flags);

void de_fmtutil_decompress_zoo_lzd(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres, int maxbits);
void de_fmtutil_decompress_zoo_lzh(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres);

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

int de_fmtutil_detect_SAUCE(deark *c, dbuf *f, struct de_SAUCE_detection_data *sdd,
	unsigned int flags);
void de_fmtutil_handle_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si);
struct de_SAUCE_info *de_fmtutil_create_SAUCE(deark *c);
void de_fmtutil_free_SAUCE(deark *c, struct de_SAUCE_info *si);

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
	dbuf *f; // Input file
	de_identify_box_fn identify_box_fn;
	de_handle_box_fn handle_box_fn;

	struct de_boxdata *curbox;
};

double dbuf_fmtutil_read_fixed_16_16(dbuf *f, i64 pos);
int de_fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx);
void de_fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx);
void de_fmtutil_render_uuid(deark *c, const u8 *uuid, char *s, size_t s_len);
void de_fmtutil_guid_to_uuid(u8 *id);

struct atari_img_decode_data {
	i64 bpp;
	i64 ncolors;
	i64 w, h;
	dbuf *unc_pixels;
	int was_compressed;
	int is_spectrum512;
	u32 *pal;
	de_bitmap *img;
};

#define DE_FLAG_ATARI_15BIT_PAL 0x2
void de_fmtutil_read_atari_palette(deark *c, dbuf *f, i64 pos,
	u32 *dstpal, i64 ncolors_to_read, i64 ncolors_used, unsigned int flags);

int de_fmtutil_atari_decode_image(deark *c, struct atari_img_decode_data *adata);
void de_fmtutil_atari_set_standard_density(deark *c, struct atari_img_decode_data *adata,
	de_finfo *fi);
void de_fmtutil_atari_help_palbits(deark *c);

// The IFF parser supports IFF and similar formats, including RIFF.
struct de_iffctx;

// An IFF chunk handler is expected to do one of the following:
// - Set ictx->is_std_container (ictx->handled is ignored).
// - Set ictx->is_raw_container (ictx->handled is ignored).
// - Handle the chunk, and set ictx->handled.
// - Do nothing, and set ictx->handled, to suppress default handling.
// - Do nothing, in which case standard IFF chunks (ANNO, at least) will
//   handled by the IFF parser.
// Return value: Normally 1; 0 to immediately stop processing the entire file.
typedef int (*de_handle_iff_chunk_fn)(deark *c, struct de_iffctx *ictx);

// Mainly for identifying the chunk.
// The user can also adjust ictx->chunkctx->dlen.
// Return value: Normally 1 (reserved)
typedef int (*de_preprocess_iff_chunk_fn)(deark *c, struct de_iffctx *ictx);

// Return value: Normally 1; 0 to immediately stop processing the entire file.
typedef int (*de_on_iff_container_end_fn)(deark *c, struct de_iffctx *ictx);

// Return value: Normally 1; 0 to stop processing this container (the
// on_container_end_fn will not be called).
typedef int (*de_on_std_iff_container_start_fn)(deark *c, struct de_iffctx *ictx);

// Caller can check for nonstandard non-chunk data at 'pos'. If found, set *plen
// to its length, process it if desired, and return 1.
typedef int (*de_handle_nonchunk_iff_data_fn)(deark *c, struct de_iffctx *ictx,
	i64 pos, i64 *plen);

struct de_iffchunkctx {
	struct de_fourcc chunk4cc;
	i64 pos;
	i64 len;
	i64 dpos;
	i64 dlen;

	// To be filled in by identify_chunk_fn:
	void *chunk_userdata;
	const char *chunk_name;
};

struct de_iffctx {
	void *userdata;
	dbuf *f; // Input file
	de_handle_iff_chunk_fn handle_chunk_fn;
	de_preprocess_iff_chunk_fn preprocess_chunk_fn;
	de_on_std_iff_container_start_fn on_std_container_start_fn;
	de_on_iff_container_end_fn on_container_end_fn;
	de_handle_nonchunk_iff_data_fn handle_nonchunk_data_fn;
	i64 alignment; // 0 = default
	i64 sizeof_len; // 0 = default
	int is_le; // For RIFF format
	int reversed_4cc;
	int input_encoding;

	int level;

	// Top-level container type:
	struct de_fourcc main_fmt4cc; // E.g. "FORM"
	struct de_fourcc main_contentstype4cc; // E.g. "ILBM"

	// Current container type:
	struct de_fourcc curr_container_fmt4cc;
	struct de_fourcc curr_container_contentstype4cc;

	// Per-chunk info supplied to handle_chunk_fn:
	struct de_iffchunkctx *chunkctx;

	// To be filled in by handle_chunk_fn:
	int handled;
	int is_std_container;
	int is_raw_container;
};

void de_fmtutil_read_iff_format(deark *c, struct de_iffctx *ictx,
	i64 pos, i64 len);
int de_fmtutil_is_standard_iff_chunk(deark *c, struct de_iffctx *ictx,
	u32 ct);
void de_fmtutil_default_iff_chunk_identify(deark *c, struct de_iffctx *ictx);

const char *de_fmtutil_tiff_orientation_name(i64 n);
const char *de_fmtutil_get_windows_charset_name(u8 cs);
const char *de_fmtutil_get_windows_cb_data_type_name(unsigned int ty);

int de_fmtutil_find_zip_eocd(deark *c, dbuf *f, i64 *foundpos);

struct de_id3info {
	int has_id3v1, has_id3v2;
	i64 main_start, main_end;
};
void de_fmtutil_handle_id3(deark *c, dbuf *f, struct de_id3info *id3i,
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
	u8 original_filename_flag;
	u8 no_applesingle;
	u8 no_appledouble;
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

void de_fmtutil_riscos_read_load_exec(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa, i64 pos1);
#define DE_RISCOS_FLAG_HAS_CRC          0x1
#define DE_RISCOS_FLAG_HAS_LZWMAXBITS   0x2
void de_fmtutil_riscos_read_attribs_field(deark *c, dbuf *f, struct de_riscos_file_attrs *rfa,
	i64 pos, unsigned int flags);

struct fmtutil_macbitmap_info {
	i64 rowbytes; // The rowBytes field
	i64 rowspan; // Actual number of bytes/row
	i64 width, height;
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
	u32 pal[256];
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
