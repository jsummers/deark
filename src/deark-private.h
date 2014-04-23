// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark.h"

#define DE_MAX_FILE_SIZE 100000000
#define DE_MAX_IMAGE_DIMENSION 10000
#define DE_MAX_IMAGES_PER_FILE 10000

// 'params' can be used by the module in whatever way it wishes.
typedef void (*de_module_run_fn)(deark *c, const char *params);

typedef int (*de_module_identify_fn)(deark *c);

struct deark_module_info {
	const char *id;
	de_module_run_fn run_fn;
	de_module_identify_fn identify_fn;
};
typedef void (*de_module_getinfo_fn)(deark *c, struct deark_module_info *mi);

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
	int is_little_endian; // Flag that changes the behavior of some functions

	struct dbuf_struct *parent_dbuf; // used for DBUF_TYPE_DBUF
	de_int64 offset_into_parent_dbuf; // used for DBUF_TYPE_DBUF

	int write_memfile_to_zip_archive; // used for DBUF_TYPE_OFILE, at least
	char *name; // used for DBUF_TYPE_OFILE

	de_int64 membuf_alloc;
	de_byte *membuf_buf;

	de_int64 cache_pos;
	de_int64 cache_bytes_used;
	de_byte cache[1];
};
typedef struct dbuf_struct dbuf;

struct deark_bitmap {
	deark *c;
	de_int64 width;
	de_int64 height;
	int bytes_per_pixel;
	int flipped;
	de_byte *bitmap;
	de_int64 bitmap_size; // bytes allocated for bitmap
};

struct deark_option {
	const char *name;
	const char *val;
};

struct deark_struct {
	int debug_level;
	const char *input_filename;

	// The current primary input file.
	// Modules may change this, provided they change it back when they're done.
	dbuf *infile;

	int file_count; // Counts the number of files written.
	int error_count;
	int format_declared;

	const char *input_format_req; // Format requested

	de_int64 slice_start_req; // Used if we're only to look at part of the file.
	de_int64 slice_size_req;
	int slice_size_req_valid;

	int output_style; // DE_OUTPUTSTYLE_*

	int extract_level;
	int list_mode;

	void *zip_file;

	char *base_output_filename;
	char *output_archive_filename;

	// TODO: Allow any number of modules and options.
#define DE_MAX_MODULES 24
	int num_modules;
	struct deark_module_info module_info[DE_MAX_MODULES];

#define DE_MAX_OPTIONS 16
	int num_options;
	struct deark_option option[DE_MAX_OPTIONS];
};

void de_fatalerror(deark *c);

void de_register_modules(deark *c);

int de_run_module(deark *c, struct deark_module_info *mi, const char *params);
int de_run_module_by_id(deark *c, const char *id, const char *params);
struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id);

void de_strlcpy(char *dst, const char *src, size_t dstlen);
int de_strcmp(const char *s1, const char *s2);
int de_memcmp(const void *s1, const void *s2, size_t n);
char *de_strchr(const char *s, int c);
size_t de_strlen(const char *s);

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

int de_get_file_size(FILE *fp, de_int64 *pfsize);

void de_declare_fmt(deark *c, const char *fmtname);

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

dbuf *dbuf_create_output_file(deark *c, const char *ext);

dbuf *dbuf_open_input_file(deark *c, const char *fn);

dbuf *dbuf_open_input_subfile(dbuf *parent, de_int64 offset, de_int64 size);

dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize);

// If f is NULL, this is a no-op.
void dbuf_close(dbuf *f);

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len);
void dbuf_writeui32le(dbuf *f, de_uint32 n);

// Write a NUL-terminated string to a file
void dbuf_fputs(dbuf *f, const char *sz);

void dbuf_fprintf(dbuf *f, const char *fmt, ...);

// Read a slice of one dbuf, and append it to another dbuf.
void dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf);

// Read a slice of a dbuf, and create a new file containing only that.
int dbuf_create_file_from_slice(dbuf *inf, de_int64 pos, de_int64 data_size, const char *ext);

// Remove everything from the dbuf.
// May be valid only for memory buffers.
void dbuf_empty(dbuf *f);

de_int64 dbuf_get_length(dbuf *f);

// See comments for dbuf_getui32().
void dbuf_set_endianness(dbuf *f, int is_le);

///////////////////////////////////////////

void de_bitmap_write_to_file(struct deark_bitmap *img, const char *token);

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

// Return the index'th symbol in the bitmap row beginning at file position rowstart.
// A symbol has bps bits. bps must be 1, 2, 4, or 8.
de_byte de_get_bits_symbol(dbuf *f, int bps, de_int64 rowstart, de_int64 index);

de_byte de_get_bits_symbol2(dbuf *f, int nbits, de_int64 bytepos, de_int64 bitpos);

// Utility function for the common case of reading a packed bi-level row, and
// writing to a bitmap.
void de_convert_row_bilevel(dbuf *f, de_int64 fpos, struct deark_bitmap *img,
	de_int64 rownum, int invert);

// Calculate the number of bits required to store n symbols.
// Intended to be used with bitmap graphics.
// Returns a minimum of 1, maximum of 32.
de_int64 de_log2_rounded_up(de_int64 n);

///////////////////////////////////////////

de_uint32 de_palette_vga256(int index);
de_uint32 de_palette_ega64(int index);
de_uint32 de_palette_pc16(int index);
de_uint32 de_palette_pcpaint_cga4(int palnum, int index);

void de_color_to_css(de_uint32 color, char *buf, int buflen);

de_byte de_palette_sample_6_to_8bit(de_byte samp);

int de_cp437_to_unicode(deark *c, int a);

///////////////////////////////////////////
