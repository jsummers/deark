// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

struct de_bmpinfo {
#define DE_BMPINFO_FMT_BMP 0
#define DE_BMPINFO_FMT_PNG 1
	int file_format;

	de_int64 hotspot_x, hotspot_y;
	de_int64 bitsoffset; // Literal value from FILEHEADER
	de_int64 infohdrsize;
	de_int64 width;
	de_int64 height;
	de_int64 bitcount;
	de_uint32 compression_field;

	de_int64 bytes_per_pal_entry;
	de_int64 pal_entries;
	de_int64 num_colors; // For use in ICO/CUR file headers.
	de_int64 rowspan;

	de_int64 foreground_size;
	de_int64 mask_rowspan;
	de_int64 mask_size;

	de_int64 pal_bytes; // Size of palette in bytes
	de_int64 size_of_headers_and_pal; // Relative offset to bitmap (bitsoffset might be absolute)
	de_int64 total_size;

	int is_topdown;
};

#define DE_BMPINFO_HAS_FILEHEADER 0x1
#define DE_BMPINFO_ICO_FORMAT     0x2
#define DE_BMPINFO_HAS_HOTSPOT    0x4
#define DE_BMPINFO_CMPR_IS_4CC    0x8

void de_fmtutil_get_bmp_compression_name(de_uint32 code, char *s, size_t s_len,
	int is_os2v2);
int de_fmtutil_get_bmpinfo(deark *c,  dbuf *f, struct de_bmpinfo *bi, de_int64 pos,
	de_int64 len, unsigned int flags);
void de_fmtutil_generate_bmpfileheader(deark *c, dbuf *outf, const struct de_bmpinfo *bi,
	de_int64 file_size_override);

void de_fmtutil_handle_exif2(deark *c, de_int64 pos, de_int64 len,
	de_uint32 *returned_flags, de_uint32 *orientation, de_uint32 *exifversion);
void de_fmtutil_handle_exif(deark *c, de_int64 pos, de_int64 len);

void de_fmtutil_handle_iptc(deark *c, de_int64 pos, de_int64 len);

void de_fmtutil_handle_photoshop_rsrc2(deark *c, de_int64 pos, de_int64 len,
	de_uint32 *returned_flags);
void de_fmtutil_handle_photoshop_rsrc(deark *c, de_int64 pos, de_int64 len);

int de_fmtutil_uncompress_packbits(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels, de_int64 *cmpr_bytes_consumed);
int de_fmtutil_uncompress_packbits16(dbuf *f, de_int64 pos1, de_int64 len,
	dbuf *unc_pixels, de_int64 *cmpr_bytes_consumed);

struct de_SAUCE_info {
	de_ucstring *title;
	de_ucstring *artist;
	de_ucstring *organization;
	de_ucstring *creation_date;
	de_int64 original_file_size;
	de_byte data_type;
	de_byte file_type;
	de_byte tflags;
	de_int64 width_in_chars; // 0 if unknown
	de_int64 number_of_lines; // Reported value. May be incorrect.
	de_int64 comment_block_pos; // Valid if num_comments>0.
	de_int64 num_comments;
	struct de_char_comment *comments; // arrays of [num_comments]
};

int de_detect_SAUCE(deark *c, dbuf *f, struct de_SAUCE_detection_data *sdd);
int de_read_SAUCE(deark *c, dbuf *f, struct de_SAUCE_info *si);
void de_free_SAUCE(deark *c, struct de_SAUCE_info *si);

struct de_boxesctx;

// Return 0 to stop reading
typedef int (*de_handle_box_fn)(deark *c, struct de_boxesctx *bctx);
typedef void (*de_identify_box_fn)(deark *c, struct de_boxesctx *bctx);

struct de_boxdata {
	// Per-box info supplied to handle_box_fn:
	struct de_boxdata *parent;
	int level;
	de_uint32 boxtype;
	int is_uuid;
	de_byte uuid[16]; // Valid only if is_uuid is set.
	de_int64 box_pos;
	de_int64 box_len;
	// Note: for UUID boxes, payload does not include the UUID
	de_int64 payload_pos;
	de_int64 payload_len;

	// To be filled in by identify_box_fn:
	void *box_userdata;
	const char *box_name;

	// To be filled in by handle_box_fn:
	int handled;
	int is_superbox;
	int num_children_is_known;
	de_int64 num_children; // valid if (is_superbox) && (num_children_is_known)
	de_int64 extra_bytes_before_children; // valid if (is_superbox)
};

struct de_boxesctx {
	void *userdata;
	dbuf *f; // Input file
	de_identify_box_fn identify_box_fn;
	de_handle_box_fn handle_box_fn;

	struct de_boxdata *curbox;
};

double dbuf_fmtutil_read_fixed_16_16(dbuf *f, de_int64 pos);
int de_fmtutil_default_box_handler(deark *c, struct de_boxesctx *bctx);
void de_fmtutil_read_boxes_format(deark *c, struct de_boxesctx *bctx);
void de_fmtutil_render_uuid(deark *c, const de_byte *uuid, char *s, size_t s_len);
void de_fmtutil_guid_to_uuid(de_byte *id);

struct atari_img_decode_data {
	de_int64 bpp;
	de_int64 ncolors;
	de_int64 w, h;
	dbuf *unc_pixels;
	int was_compressed;
	int is_spectrum512;
	de_uint32 *pal;
	de_bitmap *img;
};

#define DE_FLAG_ATARI_15BIT_PAL 0x2
void de_fmtutil_read_atari_palette(deark *c, dbuf *f, de_int64 pos,
	de_uint32 *dstpal, de_int64 ncolors_to_read, de_int64 ncolors_used, unsigned int flags);

int de_fmtutil_atari_decode_image(deark *c, struct atari_img_decode_data *adata);
void de_fmtutil_atari_set_standard_density(deark *c, struct atari_img_decode_data *adata);

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

// Return value: Normally 1; 0 to immediately stop processing the entire file.
typedef int (*de_on_iff_container_end_fn)(deark *c, struct de_iffctx *ictx);

// Return value: Normally 1; 0 to stop processing this container (the
// on_container_end_fn will not be called).
typedef int (*de_on_std_iff_container_start_fn)(deark *c, struct de_iffctx *ictx);

struct de_iffchunkctx {
	struct de_fourcc chunk4cc;
	de_int64 chunk_pos;
	de_int64 chunk_len;
	de_int64 chunk_dpos;
	de_int64 chunk_dlen;
};

struct de_iffctx {
	void *userdata;
	dbuf *f; // Input file
	de_handle_iff_chunk_fn handle_chunk_fn;
	de_on_std_iff_container_start_fn on_std_container_start_fn;
	de_on_iff_container_end_fn on_container_end_fn;
	de_int64 alignment; // 0 = default
	de_int64 sizeof_len; // 0 = default
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
	const struct de_iffchunkctx *chunkctx;

	// To be filled in by handle_chunk_fn:
	int handled;
	int is_std_container;
	int is_raw_container;
};

void de_fmtutil_read_iff_format(deark *c, struct de_iffctx *ictx,
	de_int64 pos, de_int64 len);
int de_fmtutil_is_standard_iff_chunk(deark *c, struct de_iffctx *ictx,
	de_uint32 ct);

const char *de_fmtutil_tiff_orientation_name(de_int64 n);
