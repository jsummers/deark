// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#ifdef DEARK_PRIVATE_H_INC
#error "deark-private.h included multiple times"
#endif
#define DEARK_PRIVATE_H_INC

#include <string.h>
#include <stdarg.h>
#include "deark.h"

#define DE_MAX_FILE_SIZE 100000000
#define DE_DEFAULT_MAX_IMAGE_DIMENSION 10000

#define DE_ENCODING_ASCII   0
#define DE_ENCODING_UTF8    1
#define DE_ENCODING_LATIN1  2
#define DE_ENCODING_PETSCII      8
#define DE_ENCODING_CP437_G      10
#define DE_ENCODING_CP437_C      11
#define DE_ENCODING_WINDOWS1252  20
#define DE_ENCODING_UTF16LE      30
#define DE_ENCODING_UTF16BE      31
#define DE_ENCODING_DEC_SPECIAL_GRAPHICS 80
#define DE_ENCODING_UNKNOWN      99

#define DE_INVALID_CODEPOINT ((de_int32)-1)

typedef struct de_module_params_struct {
	const char *codes;
} de_module_params;

#define DE_DECLARE_MODULE(x) void x(deark *c, struct deark_module_info *mi)

// 'mparams' is used for sending data to, and receiving data from, a module.
typedef void (*de_module_run_fn)(deark *c, de_module_params *mparams);

typedef int (*de_module_identify_fn)(deark *c);

struct deark_module_info {
	const char *id;
	const char *desc;
	de_module_run_fn run_fn;
	de_module_identify_fn identify_fn;
#define DE_MODFLAG_HIDDEN       0x01
#define DE_MODFLAG_NONWORKING   0x02
#define DE_MODFLAG_NOEXTRACT    0x04
	de_uint32 flags;
#define DE_MAX_MODULE_ALIASES 2
	const char *id_alias[DE_MAX_MODULE_ALIASES];
};
typedef void (*de_module_getinfo_fn)(deark *c, struct deark_module_info *mi);

struct de_ucstring_struct {
	deark *c;
	de_int32 *str;
	de_int64 len; // len and alloc are measured in characters, not bytes
	de_int64 alloc;
};
typedef struct de_ucstring_struct de_ucstring;

struct de_timestamp {
	de_byte is_valid;
	de_int64 unix_time; // Unix time_t format
};

// dbuf is our generalized I/O object. Used for many purposes.
struct dbuf_struct {
#define DBUF_TYPE_NULL    0
#define DBUF_TYPE_IFILE   1
#define DBUF_TYPE_OFILE   2
#define DBUF_TYPE_MEMBUF  3
#define DBUF_TYPE_DBUF    4 // nested dbuf
#define DBUF_TYPE_STDOUT  5
#define DBUF_TYPE_STDIN   6
	int btype;

	deark *c;
	FILE *fp;
	de_int64 len;

	de_int64 max_len; // Valid if has_max_len is set. May only work for type MEMBUF.
	int has_max_len;

	int file_pos_known;
	de_int64 file_pos;

	struct dbuf_struct *parent_dbuf; // used for DBUF_TYPE_DBUF
	de_int64 offset_into_parent_dbuf; // used for DBUF_TYPE_DBUF

	de_byte is_executable; // Make the output file executable?

	int write_memfile_to_zip_archive; // used for DBUF_TYPE_OFILE, at least
	char *name; // used for DBUF_TYPE_OFILE

	de_int64 membuf_alloc;
	de_byte *membuf_buf;

#define DE_CACHE_POLICY_NONE    0
#define DE_CACHE_POLICY_ENABLED 1
	int cache_policy;
	de_int64 cache_start_pos;
	de_int64 cache_bytes_used;
	de_byte *cache;

	// cache2 is a simple 1-byte cache, mainly to speed up de_convert_row_bilevel().
	de_int64 cache2_start_pos;
	de_int64 cache2_bytes_used;
	de_byte cache2[1];

	struct de_timestamp mod_time;
};
typedef struct dbuf_struct dbuf;

// Extended information about a file to be written.
struct de_finfo_struct {
	char *file_name; // utf-8 encoded
	struct de_timestamp mod_time;
	de_byte original_filename_flag; // Indicates if .file_name is a real file name
	de_byte is_executable;
};
typedef struct de_finfo_struct de_finfo;

struct deark_bitmap {
	deark *c;
	de_int64 width;
	de_int64 height;
	int invalid_image_flag;
	int bytes_per_pixel;
	int flipped;
	de_byte *bitmap;
	de_int64 bitmap_size; // bytes allocated for bitmap
	int orig_colortype; // Optional; can be used by modules
	int orig_bitdepth; // Optional; can be used by modules

#define DE_DENSITY_UNKNOWN   0
#define DE_DENSITY_UNK_UNITS 1
#define DE_DENSITY_DPI       2
	int density_code;
	// Note: If units are unknown, xdens and ydens must be integers.
	double xdens;
	double ydens;
};

struct de_SAUCE_detection_data {
	de_byte detection_attempted;
	de_byte has_SAUCE;
	de_byte data_type;
	de_byte file_type;
};

struct de_detection_data_struct {
	struct de_SAUCE_detection_data sauce;
	int has_utf8_bom;
};

struct deark_ext_option {
	char *name;
	char *val;
};

struct deark_struct {
	int debug_level;
	void *userdata;

	////////////////////////////////////////////////////
	int module_nesting_level;

	// Data specific to the current module.

	// TODO: There really ought to be a stack of standard-module-local data
	// objects, but that may be more trouble than it's worth.
	// For now, we just need to use caution when changing these fields.

	// The current primary input file.
	// Modules may change this, provided they change it back when they're done.
	dbuf *infile;

	// A flag to remember whether we've printed the specific format of the
	// top-level file.
	int format_declared;

	////////////////////////////////////////////////////

	int file_count; // Counts the number of files written.
	int error_count;

	const char *input_filename;
	const char *input_format_req; // Format requested
	de_int64 slice_start_req; // Used if we're only to look at part of the file.
	de_int64 slice_size_req;
	int slice_size_req_valid;

	int output_style; // DE_OUTPUTSTYLE_*
	int input_style; // DE_INPUTSTYLE_*

	int extract_policy; // DE_EXTRACTPOLICY_*
	int extract_level;
	int list_mode;
	int first_output_file; // first file = 0
	int max_output_files; // -1 = no limit
	de_int64 max_image_dimension;
	int show_messages;
	int show_warnings;
	int dbg_indent_amount;
	int write_bom;
	int write_density;
	int ascii_html;
	int filenames_from_file;
	int preserve_file_times;
	int reproducible_output;

	de_msgfn_type msgfn; // Caller's message output function
	de_fatalerrorfn_type fatalerrorfn;

	void *zip_file;

	char *base_output_filename;
	char *output_archive_filename;

	struct de_timestamp current_time;

	int num_modules;
	struct deark_module_info *module_info; // Pointer to an array

#define DE_MAX_EXT_OPTIONS 16
	int num_ext_options;
	struct deark_ext_option ext_option[DE_MAX_EXT_OPTIONS];

	// This struct is for data that can be shared by the various format
	// identification functions. It should not be used outside of them.
	struct de_detection_data_struct detection_data;
};

void de_fatalerror(deark *c);

void de_register_modules(deark *c);

int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams);
int de_run_module_by_id(deark *c, const char *id, de_module_params *mparams);
void de_run_module_by_id_on_slice(deark *c, const char *id, de_module_params *mparams,
	dbuf *f, de_int64 pos, de_int64 len);
struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id);

void de_strlcpy(char *dst, const char *src, size_t dstlen);
char *de_strchr(const char *s, int c);
#define de_strlen   strlen
#define de_strcmp   strcmp
#define de_memcmp   memcmp
#define de_memcpy   memcpy
#define de_memset   memset
#define de_memchr   memchr
#ifdef DE_WINDOWS
#define de_sscanf   sscanf_s
#else
#define de_sscanf   sscanf
#endif

void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap);

void de_snprintf(char *buf, size_t buflen, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 3, 4)));

void de_dbg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_dbg2(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_dbg3(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_err(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_msg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_warn(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

FILE* de_fopen(deark *c, const char *fn, const char *mode,
	char *errmsg, size_t errmsg_len);

int de_fclose(FILE *fp);

// Test if the file seems suitable for reading, and return its size.
int de_examine_file_by_name(deark *c, const char *fn, de_int64 *len,
	char *errmsg, size_t errmsg_len);

void de_update_file_time(dbuf *f);

void de_declare_fmt(deark *c, const char *fmtname);

void de_dbg_indent(deark *c, int n);
void de_dbg_pal_entry(deark *c, de_int64 idx, de_uint32 clr);

int de_identify_none(deark *c);

///////////////////////////////////////////

const char *de_get_input_file_ext(deark *c);
int de_input_file_has_ext(deark *c, const char *ext);

///////////////////////////////////////////

int de_uncompress_zlib(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf);

int de_zip_create_file(deark *c);
void de_zip_add_file_to_archive(deark *c, dbuf *f);
void de_zip_close_file(deark *c);

int de_write_png(deark *c, struct deark_bitmap *img, dbuf *f);

de_uint32 de_crc32(const void *buf, de_int64 buf_len);

///////////////////////////////////////////

de_int64 de_getui16be_direct(const de_byte *m);
de_int64 de_getui16le_direct(const de_byte *m);
de_int64 de_getui32be_direct(const de_byte *m);
de_int64 de_getui32le_direct(const de_byte *m);
de_int64 de_geti64be_direct(const de_byte *m);
de_int64 de_geti64le_direct(const de_byte *m);

void dbuf_read(dbuf *f, de_byte *buf, de_int64 pos, de_int64 len);
de_int64 dbuf_standard_read(dbuf *f, de_byte *buf, de_int64 n, de_int64 *fpos);
de_byte dbuf_getbyte(dbuf *f, de_int64 pos);

de_int64 dbuf_getui16be(dbuf *f, de_int64 pos);
de_int64 dbuf_getui16le(dbuf *f, de_int64 pos);
de_int64 dbuf_getui16x(dbuf *f, de_int64 pos, int is_le);
de_int64 dbuf_geti16be(dbuf *f, de_int64 pos);
de_int64 dbuf_geti16le(dbuf *f, de_int64 pos);
de_int64 dbuf_geti16x(dbuf *f, de_int64 pos, int is_le);
de_int64 dbuf_getui32be(dbuf *f, de_int64 pos);
de_int64 dbuf_getui32le(dbuf *f, de_int64 pos);
de_int64 dbuf_getui32x(dbuf *f, de_int64 pos, int is_le);
de_int64 dbuf_geti32be(dbuf *f, de_int64 pos);
de_int64 dbuf_geti32le(dbuf *f, de_int64 pos);
de_int64 dbuf_geti32x(dbuf *f, de_int64 pos, int is_le);
de_int64 dbuf_geti64be(dbuf *f, de_int64 pos);
de_int64 dbuf_geti64le(dbuf *f, de_int64 pos);
de_int64 dbuf_geti64x(dbuf *f, de_int64 pos, int is_le);

#define de_read(b,p,l) dbuf_read(c->infile,b,p,l);
#define de_getbyte(p) dbuf_getbyte(c->infile,p)

#define de_getui16be(p) dbuf_getui16be(c->infile,p)
#define de_getui16le(p) dbuf_getui16le(c->infile,p)
#define de_getui32be(p) dbuf_getui32be(c->infile,p)
#define de_getui32le(p) dbuf_getui32le(c->infile,p)
#define de_geti64be(p) dbuf_geti64be(c->infile,p)
#define de_geti64le(p) dbuf_geti64le(c->infile,p)

#define DE_GETRGBFLAG_BGR 0x1 // Assume BGR order instead of RGB
de_uint32 dbuf_getRGB(dbuf *f, de_int64 pos, unsigned int flags);

// Convert and append encoded bytes from a dbuf to a ucstring.
// (see also ucstring_append_*)
void dbuf_read_to_ucstring(dbuf *f, de_int64 pos, de_int64 len,
	de_ucstring *s, unsigned int conv_flags, int encoding);

// At least one of 'ext' or 'fi' should be non-NULL.
#define DE_CREATEFLAG_IS_AUX   0x1
dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi, unsigned int createflags);

dbuf *dbuf_open_input_file(deark *c, const char *fn);
dbuf *dbuf_open_input_stdin(deark *c, const char *fn);

dbuf *dbuf_open_input_subfile(dbuf *parent, de_int64 offset, de_int64 size);

// Flag:
//  0x1: Set the maximum size to the 'initialsize'
dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize, unsigned int flags);

// If f is NULL, this is a no-op.
void dbuf_close(dbuf *f);

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len);
void dbuf_write_zeroes(dbuf *f, de_int64 len);
void dbuf_truncate(dbuf *f, de_int64 len);
void dbuf_write_run(dbuf *f, de_byte n, de_int64 len);

void de_writeui16le_direct(de_byte *m, de_int64 n);
void de_writeui32le_direct(de_byte *m, de_int64 n);
void de_writeui32be_direct(de_byte *m, de_int64 n);
void dbuf_writebyte(dbuf *f, de_byte n);
void dbuf_writebyte_at(dbuf *f, de_int64 pos, de_byte n);
void dbuf_writeui16le(dbuf *f, de_int64 n);
void dbuf_writeui32le(dbuf *f, de_int64 n);

// Write a NUL-terminated string to a file
void dbuf_puts(dbuf *f, const char *sz);

void dbuf_printf(dbuf *f, const char *fmt, ...);

// Read a slice of one dbuf, and append it to another dbuf.
void dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf);

// Copy the entire contents of the dbuf (which are not expected to be
// NUL-terminated) to a NUL-terminated string.
void dbuf_copy_all_to_sz(dbuf *f, char *dst, size_t dst_size);

// Read a NUL-terminated string from a dbuf.
void dbuf_read_sz(dbuf *f, de_int64 pos, char *dst, size_t dst_size);

// Compare bytes in a dbuf to s. The dbuf bytes are thrown away after the memcmp.
int dbuf_memcmp(dbuf *f, de_int64 pos, const void *s, size_t n);

// Read a slice of a dbuf, and create a new file containing only that.
// At least one of 'ext' or 'fi' should be non-NULL.
int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size,
	const char *ext, de_finfo *fi, unsigned int createflags);

int dbuf_has_utf8_bom(dbuf *f, de_int64 pos);

int dbuf_dump_to_file(dbuf *inf, const char *fn);

// Remove everything from the dbuf.
// May be valid only for memory buffers.
void dbuf_empty(dbuf *f);

de_int64 dbuf_get_length(dbuf *f);

// Enforce a maximum size when writing to a dbuf.
// May be valid only for memory buffers.
void dbuf_set_max_length(dbuf *f, de_int64 max_len);

int dbuf_search_byte(dbuf *f, const de_byte b, de_int64 startpos,
	de_int64 haystack_len, de_int64 *foundpos);

int dbuf_search(dbuf *f, const de_byte *needle, de_int64 needle_len,
	de_int64 startpos, de_int64 haystack_len, de_int64 *foundpos);

int dbuf_find_line(dbuf *f, de_int64 pos1, de_int64 *pcontent_len, de_int64 *ptotal_len);

struct de_fourcc {
  de_byte bytes[4];
  de_uint32 id;
  char id_printable[8];
};
void dbuf_read_fourcc(dbuf *f, de_int64 pos, struct de_fourcc *fcc, int is_reversed);

///////////////////////////////////////////

void de_bitmap_write_to_file(struct deark_bitmap *img, const char *token, unsigned int createflags);
void de_bitmap_write_to_file_finfo(struct deark_bitmap *img, de_finfo *fi, unsigned int createflags);

void de_bitmap_setsample(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_int64 samplenum, de_byte v);

void de_bitmap_setpixel_gray(struct deark_bitmap *img, de_int64 x, de_int64 y, de_byte v);

void de_bitmap_setpixel_rgb(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color);

void de_bitmap_setpixel_rgba(struct deark_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color);

de_uint32 de_bitmap_getpixel(struct deark_bitmap *img, de_int64 x, de_int64 y);

struct deark_bitmap *de_bitmap_create_noinit(deark *c);
struct deark_bitmap *de_bitmap_create(deark *c, de_int64 width, de_int64 height, int bypp);

void de_bitmap_destroy(struct deark_bitmap *b);

#define DE_COLOR_A(x)  (((x)>>24)&0xff)
#define DE_COLOR_R(x)  (((x)>>16)&0xff)
#define DE_COLOR_G(x)  (((x)>>8)&0xff)
#define DE_COLOR_B(x)  ((x)&0xff)
#define DE_COLOR_K(x)  (((x)>>16)&0xff) // Gray value. Arbitrarily use the Red channel.

#define DE_STOCKCOLOR_BLACK   0xff000000U
#define DE_STOCKCOLOR_WHITE   0xffffffffU
#define DE_STOCKCOLOR_TRANSPARENT 0x00000000U

#define DE_MAKE_RGBA(r,g,b,a)  ((((de_uint32)(a))<<24)|((r)<<16)|((g)<<8)|(b))
#define DE_MAKE_RGB(r,g,b)     ((((de_uint32)0xff)<<24)|((r)<<16)|((g)<<8)|(b))
#define DE_MAKE_GRAY(k)        ((((de_uint32)0xff)<<24)|((k)<<16)|((k)<<8)|(k))
#define DE_SET_ALPHA(v,a)      (((v)&0x00ffffff)|(((de_uint32)(a))<<24))
#define DE_MAKE_OPAQUE(v)      (((de_uint32)(v))|0xff000000U)

// Return the index'th symbol in the bitmap row beginning at file position rowstart.
// A symbol has bps bits. bps must be 1, 2, 4, or 8.
de_byte de_get_bits_symbol(dbuf *f, de_int64 bps, de_int64 rowstart, de_int64 index);

de_byte de_get_bits_symbol_lsb(dbuf *f, de_int64 bps, de_int64 rowstart, de_int64 index);

de_byte de_get_bits_symbol2(dbuf *f, int nbits, de_int64 bytepos, de_int64 bitpos);

// Conversion flags used by some functions.
#define DE_CVTF_WHITEISZERO 0x1
#define DE_CVTF_LSBFIRST    0x2

// Utility function for the common case of reading a packed bi-level row, and
// writing to a bitmap.
void de_convert_row_bilevel(dbuf *f, de_int64 fpos, struct deark_bitmap *img,
	de_int64 rownum, unsigned int flags);

void de_convert_image_bilevel(dbuf *f, de_int64 fpos, de_int64 rowspan,
	struct deark_bitmap *img, unsigned int flags);

void de_convert_and_write_image_bilevel(dbuf *f, de_int64 fpos,
	de_int64 w, de_int64 height, de_int64 rowspan, unsigned int cvtflags,
	de_finfo *fi, unsigned int createflags);

void de_read_palette_rgb(dbuf *f,
	de_int64 fpos, de_int64 num_entries, de_int64 entryspan,
	de_uint32 *pal, de_int64 ncolors_in_pal,
	unsigned int flags);

// Utility function that will work for many of the common kinds of paletted images.
void de_convert_image_paletted(dbuf *f, de_int64 fpos,
	de_int64 bpp, de_int64 rowspan, const de_uint32 *pal,
	struct deark_bitmap *img, unsigned int flags);

// Calculate the number of bits required to store n symbols.
// Intended to be used with bitmap graphics.
// Returns a minimum of 1, maximum of 32.
de_int64 de_log2_rounded_up(de_int64 n);

// Test if the image dimensions are valid and supported.
int de_good_image_dimensions_noerr(deark *c, de_int64 w, de_int64 h);

// Test if the image dimensions are valid and supported. Report an error if not.
int de_good_image_dimensions(deark *c, de_int64 w, de_int64 h);

// Test if the number of images is sane. Report an error if not.
int de_good_image_count(deark *c, de_int64 n);

int de_is_grayscale_palette(const de_uint32 *pal, de_int64 num_entries);

#define DE_BITMAPFLAG_WHITEISTRNS 0x1
void de_bitmap_apply_mask(struct deark_bitmap *fg, struct deark_bitmap *mask,
	unsigned int flags);

///////////////////////////////////////////

char de_get_hexchar(int n);
de_byte de_decode_hex_digit(de_byte x, int *errorflag);

de_uint32 de_palette_vga256(int index);
de_uint32 de_palette_ega64(int index);
de_uint32 de_palette_pc16(int index);
de_uint32 de_palette_pcpaint_cga4(int palnum, int index);

const de_byte *de_get_vga_cp437_font_ptr(void);

void de_color_to_css(de_uint32 color, char *buf, int buflen);

de_byte de_sample_nbit_to_8bit(de_int64 n, unsigned int x);
de_byte de_scale_63_to_255(de_byte x);
de_byte de_scale_1000_to_255(de_int64 x);
de_uint32 de_rgb565_to_888(de_uint32 x);
de_uint32 de_bgr555_to_888(de_uint32 x);
de_uint32 de_rgb555_to_888(de_uint32 x);

de_int32 de_char_to_unicode(deark *c, de_int32 a, int encoding);
void de_uchar_to_utf8(de_int32 u1, de_byte *utf8buf, de_int64 *p_utf8len);
void dbuf_write_uchar_as_utf8(dbuf *outf, de_int32 u);
int de_utf8_to_uchar(const de_byte *utf8buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf8len);
int de_utf16le_to_uchar(const de_byte *utf16buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf16len);

int de_is_ascii(const de_byte *buf, de_int64 buflen);

#define DE_CONVFLAG_STOP_AT_NUL 0x1

// Convert encoded bytes to a NUL-terminated string that can be
// printed to the terminal.
// Consider using dbuf_read_to_ucstring+ucstring_to_printable_sz instead.
void de_bytes_to_printable_sz(const de_byte *src, de_int64 src_len,
	char *dst, de_int64 dst_len, unsigned int conv_flags, int src_encoding);

de_finfo *de_finfo_create(deark *c);
void de_finfo_destroy(deark *c, de_finfo *fi);

// Consider using dbuf_read_to_ucstring+de_finfo_set_name_from_ucstring instead.
void de_finfo_set_name_from_slice(deark *c, de_finfo *fi, dbuf *f,
	de_int64 pos, de_int64 len, unsigned int conv_flags, int encoding);

void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1,
	int encoding);
void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s);
void de_finfo_set_name_from_bytes(deark *c, de_finfo *fi, const de_byte *name1,
	de_int64 name1_len, unsigned int conv_flags, int encoding);
de_int32 de_char_to_valid_fn_char(deark *c, de_int32 c1);

de_ucstring *ucstring_create(deark *c);
de_ucstring *ucstring_clone(de_ucstring *src);
void ucstring_destroy(de_ucstring *s);
void ucstring_truncate(de_ucstring *s, de_int64 newlen);
void ucstring_append_char(de_ucstring *s, de_int32 ch);
void ucstring_append_ucstring(de_ucstring *s1, const de_ucstring *s2);

// Convert and append an encoded array of bytes to the string.
void ucstring_append_bytes(de_ucstring *s, const de_byte *buf, de_int64 buflen, unsigned int conv_flags, int encoding);

void ucstring_append_sz(de_ucstring *s, const char *sz, int encoding);

void ucstring_write_as_utf8(deark *c, de_ucstring *s, dbuf *outf, int add_bom_if_needed);

// Supported encodings are DE_ENCODING_UTF8, DE_ENCODING_ASCII, DE_ENCODING_LATIN1.
void ucstring_to_sz(de_ucstring *s, char *szbuf, size_t szbuf_len, int encoding);

void ucstring_to_printable_sz(de_ucstring *s, char *szbuf, size_t szbuf_len);

void ucstring_make_printable(de_ucstring *s);

void de_write_codepoint_to_html(deark *c, dbuf *f, de_int32 ch);

void de_copy_bits(const de_byte *src, de_int64 srcbitnum,
	de_byte *dst, de_int64 dstbitnum, de_int64 bitstocopy);

///////////////////////////////////////////

struct de_bitmap_font_char {
	de_int32 codepoint_nonunicode;

	// If font->has_unicode_codepoints is set, then ->codepoint_unicode
	// must be set to a Unicode codepoint, or to DE_INVALID_CODEPOINT.
	de_int32 codepoint_unicode;

	int width, height;
	int v_offset; // Used if the glyphs do not all have the same height
	de_int64 rowspan;
	de_byte *bitmap;
};

struct de_bitmap_font {
	int nominal_width, nominal_height;
	de_int64 index_of_replacement_char; // -1 if none

	// Flag: Are the char_array[]->codepoint_nonunicode codes set?
	// (This should be ignored if has_unicode_codepoints is not set.)
	de_byte has_nonunicode_codepoints;

	// Flag: Are the char_array[]->codepoint_unicode codes set?
	de_byte has_unicode_codepoints;

	// If the font has both unicode and non-unicode codpoints, this flag tells which
	// to prefer when displaying the font.
	de_byte prefer_unicode;

	de_int64 num_chars;
	struct de_bitmap_font_char *char_array;
};

struct de_bitmap_font *de_create_bitmap_font(deark *c);
void de_destroy_bitmap_font(deark *c, struct de_bitmap_font *font);

#define DE_PAINTFLAG_TRNSBKGD 0x01
#define DE_PAINTFLAG_VGA9COL  0x02 // Render an extra column, like VGA does
#define DE_PAINTFLAG_LEFTHALF   0x04 // Note: The "HALF" flags must fit into a byte,
#define DE_PAINTFLAG_RIGHTHALF  0x08 // because they are stored in de_char_cell::size_flags.
#define DE_PAINTFLAG_TOPHALF    0x10
#define DE_PAINTFLAG_BOTTOMHALF 0x20
void de_font_paint_character_idx(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int64 char_idx,
	de_int64 xpos, de_int64 ypos, de_uint32 fgcol, de_uint32 bgcol, unsigned int flags);
void de_font_paint_character_cp(deark *c, struct deark_bitmap *img,
	struct de_bitmap_font *font, de_int32 codepoint,
	de_int64 xpos, de_int64 ypos, de_uint32 fgcol, de_uint32 bgcol, unsigned int flags);

void de_font_bitmap_font_to_image(deark *c, struct de_bitmap_font *font, de_finfo *fi, unsigned int createflags);
int de_font_is_standard_vga_font(deark *c, de_uint32 crc);

///////////////////////////////////////////

// Note that this struct is assumed to be copyable with a simple struct copy.
// It should not contain pointers.
struct de_char_cell {
	de_int32 codepoint;
	de_int32 codepoint_unicode;
	// The color fields are interpreted as follows:
	//  A color value <=0x0000000f is a palette index.
	//  A color value >=0xff000000 is an RGB color, e.g. from DE_MAKE_RGB().
#define DE_IS_PAL_COLOR(x) ((de_uint32)(x)<=0xfU)
	de_uint32 fgcol;
	de_uint32 bgcol;
	de_byte underline;
	de_byte strikethru;
	de_byte blink;
	de_byte size_flags;
};

struct de_char_screen {
	de_int64 width;
	de_int64 height;
	struct de_char_cell **cell_rows; // Array of [height] row pointers
};

struct de_char_context {
	de_byte prefer_image_output;
	de_byte prefer_9col_mode;
	de_byte no_density;
	de_byte suppress_custom_font_warning;
	de_int64 nscreens;
	struct de_char_screen **screens; // Array of [nscreens] screens
	de_uint32 pal[16];
	struct de_bitmap_font *font; // Optional
	de_ucstring *title;
	de_ucstring *artist;
	de_ucstring *organization;
	de_ucstring *creation_date;
};

void de_char_output_to_file(deark *c, struct de_char_context *charctx);

void de_free_charctx(deark *c, struct de_char_context *charctx);

///////////////////////////////////////////

void de_unix_time_to_timestamp(de_int64 ut, struct de_timestamp *ts);
void de_FILETIME_to_timestamp(de_int64 ft, struct de_timestamp *ts);
de_int64 de_timestamp_to_unix_time(const struct de_timestamp *ts);
void de_make_timestamp(struct de_timestamp *ts,
	de_int64 yr, de_int64 mo, de_int64 da,
	de_int64 hr, de_int64 mi, double se);
void de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags);
void de_current_time_to_timestamp(struct de_timestamp *ts);
