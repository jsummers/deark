// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

struct de_bmpinfo {
#define DE_BMPINFO_FMT_BMP 0
#define DE_BMPINFO_FMT_PNG 1
	int file_format;

	i64 hotspot_x, hotspot_y;
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

int de_fmtutil_uncompress_packbits(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed);
int de_fmtutil_uncompress_packbits16(dbuf *f, i64 pos1, i64 len,
	dbuf *unc_pixels, i64 *cmpr_bytes_consumed);
int de_fmtutil_decompress_rle90(dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, unsigned int has_maxlen, i64 max_out_len, unsigned int flags);

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
	i64 num_comments;
	u16 tinfo1, tinfo2, tinfo3, tinfo4;
	struct de_char_comment *comments; // arrays of [num_comments]
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
	i64 alignment; // 0 = default
	i64 sizeof_len; // 0 = default
	int is_le; // For RIFF format
	int reversed_4cc;

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
