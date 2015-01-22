// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include <string.h>
#include <stdarg.h>
#include "deark.h"

#define DE_MAX_FILE_SIZE 100000000
#define DE_MAX_IMAGE_DIMENSION 10000
#define DE_MAX_IMAGES_PER_FILE 10000

#define DE_ENCODING_ASCII   0
#define DE_ENCODING_UTF8    1
#define DE_ENCODING_LATIN1  2

// 'params' can be used by the module in whatever way it wishes.
typedef void (*de_module_run_fn)(deark *c, const char *params);

typedef int (*de_module_identify_fn)(deark *c);

struct deark_module_info {
	const char *id;
	de_module_run_fn run_fn;
	de_module_identify_fn identify_fn;
};
typedef void (*de_module_getinfo_fn)(deark *c, struct deark_module_info *mi);

struct de_ucstring_struct {
	deark *c;
	de_int32 *str;
	de_int64 len; // len and alloc are measured in characters, not bytes
	de_int64 alloc;
};
typedef struct de_ucstring_struct de_ucstring;

// dbuf is our generalized I/O object. Used for many purposes.
struct dbuf_struct {
#define DBUF_TYPE_IFILE   1
#define DBUF_TYPE_OFILE   2
#define DBUF_TYPE_MEMBUF  3
#define DBUF_TYPE_DBUF    4 // nested dbuf
	int btype;

	deark *c;
	FILE *fp;
	de_int64 len;
	de_int64 max_len; // 0=no maximum. May only apply to DBUF_TYPE_MEMBUF
	int is_little_endian; // Flag that changes the behavior of some functions

	int file_pos_known;
	de_int64 file_pos;

	struct dbuf_struct *parent_dbuf; // used for DBUF_TYPE_DBUF
	de_int64 offset_into_parent_dbuf; // used for DBUF_TYPE_DBUF

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

	de_byte mod_time_valid;
	de_int64 mod_time;
};
typedef struct dbuf_struct dbuf;

// Extended information about a file to be written.
struct de_finfo_struct {
	char *file_name; // utf-8 encoded
	de_int64 mod_time; // Unix time_t format
	de_byte mod_time_valid;
};
typedef struct de_finfo_struct de_finfo;

struct deark_bitmap {
	deark *c;
	de_int64 width;
	de_int64 height;
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

struct deark_ext_option {
	const char *name;
	const char *val;
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

	int extract_level;
	int list_mode;
	int first_output_file; // first file = 0
	int max_output_files; // -1 = no limit
	int show_messages;
	int show_warnings;
	int dbg_indent_amount;
	int write_bom;
	int write_density;
	int filenames_from_file;
	int preserve_file_times;

	de_msgfn_type msgfn; // Caller's message output function
	de_fatalerrorfn_type fatalerrorfn;

	void *zip_file;

	char *base_output_filename;
	char *output_archive_filename;

	// TODO: Allow any number of modules and options.
#define DE_MAX_MODULES 96
	int num_modules;
	struct deark_module_info module_info[DE_MAX_MODULES];

#define DE_MAX_EXT_OPTIONS 16
	int num_ext_options;
	struct deark_ext_option ext_option[DE_MAX_EXT_OPTIONS];
};

void de_fatalerror(deark *c);

void de_register_modules(deark *c);

int de_run_module(deark *c, struct deark_module_info *mi, const char *params);
int de_run_module_by_id(deark *c, const char *id, const char *params);
struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id);

void de_strlcpy(char *dst, const char *src, size_t dstlen);
char *de_strchr(const char *s, int c);
#define de_strlen   strlen
#define de_strcmp   strcmp
#define de_memcmp   memcmp
#define de_memcpy   memcpy
#define de_memset   memset
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

void de_err(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_msg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

void de_warn(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

FILE* de_fopen(deark *c, const char *fn, const char *mode,
	char *errmsg, size_t errmsg_len);

int de_fclose(FILE *fp);

int de_get_file_size(FILE *fp, de_int64 *pfsize);

void de_update_file_time(dbuf *f);

void de_declare_fmt(deark *c, const char *fmtname);

void de_dbg_indent(deark *c, int n);

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

///////////////////////////////////////////

de_int64 de_getui16be_direct(const de_byte *m);
de_int64 de_getui16le_direct(const de_byte *m);
de_int64 de_getui32be_direct(const de_byte *m);
de_int64 de_getui32le_direct(const de_byte *m);
de_int64 de_geti64be_direct(const de_byte *m);
de_int64 de_geti64le_direct(const de_byte *m);

void dbuf_read(dbuf *f, de_byte *buf, de_int64 pos, de_int64 len);
de_byte dbuf_getbyte(dbuf *f, de_int64 pos);

de_int64 dbuf_getui16be(dbuf *f, de_int64 pos);
de_int64 dbuf_getui16le(dbuf *f, de_int64 pos);
de_int64 dbuf_getui32be(dbuf *f, de_int64 pos);
de_int64 dbuf_getui32le(dbuf *f, de_int64 pos);
de_int64 dbuf_geti64be(dbuf *f, de_int64 pos);
de_int64 dbuf_geti64le(dbuf *f, de_int64 pos);

// Endianness is selected by calling dbuf_set_endianness().
// This is useful for formats like TIFF that can use either endianness.
// For formats that always have the same endianness, it is recommended to use
// the "le" and "be" functions and macros instead.
de_int64 dbuf_getui32(dbuf *f, de_int64 pos);
de_int64 dbuf_getui16(dbuf *f, de_int64 pos);
de_int64 dbuf_geti64(dbuf *f, de_int64 pos);

#define de_read(b,p,l) dbuf_read(c->infile,b,p,l);
#define de_getbyte(p) dbuf_getbyte(c->infile,p)

#define de_getui16be(p) dbuf_getui16be(c->infile,p)
#define de_getui16le(p) dbuf_getui16le(c->infile,p)
#define de_getui16(p) dbuf_getui16(c->infile,p)
#define de_getui32be(p) dbuf_getui32be(c->infile,p)
#define de_getui32le(p) dbuf_getui32le(c->infile,p)
#define de_getui32(p) dbuf_getui32(c->infile,p)
#define de_geti64be(p) dbuf_geti64be(c->infile,p)
#define de_geti64le(p) dbuf_geti64le(c->infile,p)
#define de_geti64(p) dbuf_geti64(c->infile,p)

#define DE_GETRGBFLAG_BGR 0x1 // Assume BGR order instead of RGB
de_uint32 dbuf_getRGB(dbuf *f, de_int64 pos, unsigned int flags);

// At least one of 'ext' or 'fi' should be non-NULL.
dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi);

dbuf *dbuf_open_input_file(deark *c, const char *fn);

dbuf *dbuf_open_input_subfile(dbuf *parent, de_int64 offset, de_int64 size);

dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize);

// If f is NULL, this is a no-op.
void dbuf_close(dbuf *f);

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len);
void dbuf_write_zeroes(dbuf *f, de_int64 len);
void dbuf_write_run(dbuf *f, de_byte n, de_int64 len);

void de_writeui16le_direct(de_byte *m, de_int64 n);
void de_writeui32le_direct(de_byte *m, de_int64 n);
void de_writeui32be_direct(de_byte *m, de_int64 n);
void dbuf_writebyte(dbuf *f, de_byte n);
void dbuf_writeui16le(dbuf *f, de_int64 n);
void dbuf_writeui32le(dbuf *f, de_int64 n);

// Write a NUL-terminated string to a file
void dbuf_fputs(dbuf *f, const char *sz);

void dbuf_fprintf(dbuf *f, const char *fmt, ...);

// Read a slice of one dbuf, and append it to another dbuf.
void dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf);

// Read a NUL-terminated string from a dbuf.
void dbuf_read_sz(dbuf *f, de_int64 pos, char *dst, size_t dst_size);

// Compare bytes in a dbuf to s. The dbuf bytes are thrown away after the memcmp.
int dbuf_memcmp(dbuf *f, de_int64 pos, const void *s, size_t n);

// Read a slice of a dbuf, and create a new file containing only that.
// At least one of 'ext' or 'fi' should be non-NULL.
int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size,
	const char *ext, de_finfo *fi);

// Remove everything from the dbuf.
// May be valid only for memory buffers.
void dbuf_empty(dbuf *f);

de_int64 dbuf_get_length(dbuf *f);

// Enforce a maximum size when writing to a dbuf.
// May be valid only for memory buffers.
void dbuf_set_max_length(dbuf *f, de_int64 max_len);

// See comments for dbuf_getui32().
void dbuf_set_endianness(dbuf *f, int is_le);

int dbuf_search_byte(dbuf *f, const de_byte b, de_int64 startpos,
	de_int64 haystack_len, de_int64 *foundpos);

int dbuf_search(dbuf *f, const de_byte *needle, de_int64 needle_len,
	de_int64 startpos, de_int64 haystack_len, de_int64 *foundpos);

int dbuf_find_line(dbuf *f, de_int64 pos1, de_int64 *pcontent_len, de_int64 *ptotal_len);

///////////////////////////////////////////

void de_bitmap_write_to_file(struct deark_bitmap *img, const char *token);
void de_bitmap_write_to_file_finfo(struct deark_bitmap *img, de_finfo *fi);

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

void de_convert_and_write_image_bilevel(dbuf *f, de_int64 fpos,
	de_int64 w, de_int64 height, de_int64 rowspan, unsigned int flags,
	de_finfo *fi);

// Calculate the number of bits required to store n symbols.
// Intended to be used with bitmap graphics.
// Returns a minimum of 1, maximum of 32.
de_int64 de_log2_rounded_up(de_int64 n);

int de_good_image_dimensions(deark *c, de_int64 w, de_int64 h);

///////////////////////////////////////////

de_byte de_decode_hex_digit(de_byte x, int *errorflag);

de_uint32 de_palette_vga256(int index);
de_uint32 de_palette_ega64(int index);
de_uint32 de_palette_pc16(int index);
de_uint32 de_palette_pcpaint_cga4(int palnum, int index);

void de_color_to_css(de_uint32 color, char *buf, int buflen);

de_byte de_palette_sample_6_to_8bit(de_byte samp);
de_uint32 de_rgb565_to_888(de_uint32 n);
de_uint32 de_bgr555_to_888(de_uint32 n);

de_int32 de_cp437g_to_unicode(deark *c, int a);
de_int32 de_cp437c_to_unicode(deark *c, int a);
void de_uchar_to_utf8(de_int32 u1, de_byte *utf8buf, de_int64 *p_utf8len);
void dbuf_write_uchar_as_utf8(dbuf *outf, de_int32 u);

int de_is_ascii(const de_byte *buf, de_int64 buflen);

#define DE_CONVFLAG_STOP_AT_NUL 0x1

void de_make_printable_ascii(de_byte *s1, de_int64 s1_len,
	char *s2, de_int64 s2_size, unsigned int conv_flags);

de_finfo *de_finfo_create(deark *c);
void de_finfo_destroy(deark *c, de_finfo *fi);
void de_finfo_set_name_from_slice(deark *c, de_finfo *fi, dbuf *f,
	de_int64 pos, de_int64 len, unsigned int conv_flags);
void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1,
	int encoding);
void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s);
void de_finfo_set_name_from_bytes(deark *c, de_finfo *fi, const de_byte *name1,
	de_int64 name1_len, unsigned int conv_flags, int encoding);
de_int32 de_char_to_valid_fn_char(deark *c, de_int32 c1);

de_ucstring *ucstring_create(deark *c);
void ucstring_destroy(de_ucstring *s);
void ucstring_append_char(de_ucstring *s, de_int32 ch);

de_int32 de_petscii_char_to_utf32(de_byte ch);

///////////////////////////////////////////
