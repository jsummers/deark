// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Definitions not visible to the command-line utility.

#ifdef DEARK_PRIVATE_H_INC
#error "deark-private.h included multiple times"
#endif
#define DEARK_PRIVATE_H_INC

#ifndef DEARK_H_INC
#include "deark.h"
#endif

#define DE_MAX_FILE_SIZE 100000000
#define DE_DEFAULT_MAX_IMAGE_DIMENSION 10000

#define DE_ENCODING_ASCII   0
#define DE_ENCODING_UTF8    1
#define DE_ENCODING_LATIN1  2
#define DE_ENCODING_PRINTABLEASCII 7
#define DE_ENCODING_PETSCII      8
#define DE_ENCODING_CP437_G      10
#define DE_ENCODING_CP437_C      11
#define DE_ENCODING_WINDOWS1250  20
#define DE_ENCODING_WINDOWS1251  21
#define DE_ENCODING_WINDOWS1252  22
#define DE_ENCODING_UTF16LE      30
#define DE_ENCODING_UTF16BE      31
#define DE_ENCODING_MACROMAN     40
#define DE_ENCODING_PALM         50
#define DE_ENCODING_DEC_SPECIAL_GRAPHICS 80
#define DE_ENCODING_UNKNOWN      99

#define DE_CODEPOINT_HL          0x0001
#define DE_CODEPOINT_UNHL        0x0002
#define DE_CODEPOINT_RGBSAMPLE   0x0003
#define DE_CODEPOINT_MOVED      0xfde00
#define DE_CODEPOINT_INVALID 0x0fffffff // Generic invalid codepoint
#define DE_CODEPOINT_BYTE00  0x10000000 // More "invalid" codepoints
#define DE_CODEPOINT_BYTEFF  0x100000ff

#define DE_ITEMS_IN_ARRAY(x) (sizeof(x)/sizeof(x[0]))

struct de_module_in_params {
	const char *codes;
	//  0x01: offset_in_parent is set
	de_uint32 flags;
	de_int64 offset_in_parent;
};

struct de_module_out_params {
	// flags can be module-specific.
	//  psd: 0x02: has_iptc
	//  tiff: 0x08: has_exif_gps
	//  tiff: 0x10: first IFD has subsampling=cosited
	//  tiff: 0x20: uint1 = first IFD's orientation
	//  tiff: 0x40: uint2 = Exif version
	//  tiff: 0x80: int64_1 = MPF min expected file size, uint3 = image count
	de_uint32 flags;
	de_uint32 uint1;
	de_uint32 uint2;
	de_uint32 uint3;
	de_int64 int64_1;
};

typedef struct de_module_params_struct {
	struct de_module_in_params in_params;
	struct de_module_out_params out_params;

} de_module_params;

#define DE_DECLARE_MODULE(x) void x(deark *c, struct deark_module_info *mi)

// 'mparams' is used for sending data to, and receiving data from, a module.
typedef void (*de_module_run_fn)(deark *c, de_module_params *mparams);

typedef int (*de_module_identify_fn)(deark *c);

typedef void (*de_module_help_fn)(deark *c);

struct deark_module_info {
	const char *id;
	const char *desc;
	const char *desc2; // Additional notes
	de_module_run_fn run_fn;
	de_module_identify_fn identify_fn;
	de_module_help_fn help_fn;
#define DE_MODFLAG_HIDDEN       0x01 // Do not list
#define DE_MODFLAG_NONWORKING   0x02 // Do not list, and print a warning
#define DE_MODFLAG_NOEXTRACT    0x04 // Do not warn if no files are extracted
#define DE_MODFLAG_SECURITYWARNING 0x08
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
	char *tmp_string;
};
typedef struct de_ucstring_struct de_ucstring;

struct de_timestamp {
	de_byte is_valid;
	de_int64 unix_time; // Unix time_t format
};

struct dbuf_struct;
typedef struct dbuf_struct dbuf;
typedef void (*de_writecallback_fn)(dbuf *f, const de_byte *buf, de_int64 buf_len);

// dbuf is our generalized I/O object. Used for many purposes.
struct dbuf_struct {
#define DBUF_TYPE_NULL    0
#define DBUF_TYPE_IFILE   1
#define DBUF_TYPE_OFILE   2
#define DBUF_TYPE_MEMBUF  3
#define DBUF_TYPE_DBUF    4 // nested dbuf
#define DBUF_TYPE_STDOUT  5
#define DBUF_TYPE_STDIN   6
#define DBUF_TYPE_FIFO    7
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

#define DE_MODEFLAG_NONEXE 0x01 // Make the output file non-executable.
#define DE_MODEFLAG_EXE    0x02 // Make the output file executable.
	unsigned int mode_flags;

	int write_memfile_to_zip_archive; // used for DBUF_TYPE_OFILE, at least
	char *name; // used for DBUF_TYPE_OFILE (utf-8)

	de_int64 membuf_alloc;
	de_byte *membuf_buf;

	void *userdata;
	de_writecallback_fn writecallback_fn;

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

// Extended information about a file to be written.
struct de_finfo_struct {
	char *file_name; // utf-8 encoded
	struct de_timestamp mod_time;
	de_byte original_filename_flag; // Indicates if .file_name is a real file name
	unsigned int mode_flags;
};
typedef struct de_finfo_struct de_finfo;

struct deark_bitmap_struct {
	deark *c;
	de_int64 width;
	de_int64 height;
	int invalid_image_flag;
	int bytes_per_pixel;
	// 'flipped' changes the coordinate system when writing the bitmap to a file.
	// It is ignored by most other functions.
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
typedef struct deark_bitmap_struct de_bitmap;

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

typedef void (*de_module_register_fn_type)(deark *c);

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

#define DE_MODDISP_NONE       0 // No active module, or unknown
#define DE_MODDISP_AUTODETECT 1 // Format was autodetected
#define DE_MODDISP_EXPLICIT   2 // User used -m to select the module
#define DE_MODDISP_INTERNAL   3 // Another module is using this module
	int module_disposition; // Why are we using this module?

	////////////////////////////////////////////////////

	int file_count; // The number of extractable files encountered so far.

	// The number of files we've actually written (or listed), after taking
	// first_output_file/max_output_files into account.
	int num_files_extracted;

	int error_count;

	const char *input_filename;
	const char *input_format_req; // Format requested
	const char *modcodes_req;
	de_int64 slice_start_req; // Used if we're only to look at part of the file.
	de_int64 slice_size_req;
	int slice_size_req_valid;
	int suppress_detection_by_filename;

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
	struct de_timestamp reproducible_timestamp;
	int can_decode_fltpt;
	int host_is_le;
	int modhelp_req;
	int input_encoding;

	de_msgfn_type msgfn; // Caller's message output function
	de_specialmsgfn_type specialmsgfn;
	de_fatalerrorfn_type fatalerrorfn;
	const char *dprefix;

	void *zip_data;
	FILE *extrlist_file;

	char *base_output_filename;
	char *output_archive_filename;
	char *extrlist_filename;

	struct de_timestamp current_time;

	de_module_register_fn_type module_register_fn;

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

deark *de_create_internal(void);
int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams, int moddisp);
int de_run_module_by_id(deark *c, const char *id, de_module_params *mparams);
void de_run_module_by_id_on_slice(deark *c, const char *id, de_module_params *mparams,
	dbuf *f, de_int64 pos, de_int64 len);
void de_run_module_by_id_on_slice2(deark *c, const char *id, const char *codes,
	dbuf *f, de_int64 pos, de_int64 len);
struct deark_module_info *de_get_module_by_id(deark *c, const char *module_id);

void de_strlcpy(char *dst, const char *src, size_t dstlen);
char *de_strchr(const char *s, int c);
#define de_strlen   strlen
#define de_strcmp   strcmp
#define de_strncmp  strncmp
#define de_memcmp   memcmp
#define de_memcpy   memcpy
#define de_memmove  memmove
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

// de_dbg*, de_msg, de_warn, de_err: The output is a single line, to which a
// standard prefix like "Warning: " may be added. A newline will be added
// automatically.
// [For other output functions, see de_puts, de_printf (deark.h).]

void de_dbg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_dbg2(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_dbg3(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_msg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_vwarn(deark *c, const char *fmt, va_list ap);
void de_warn(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_verr(deark *c, const char *fmt, va_list ap);
void de_err(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

FILE* de_fopen_for_read(deark *c, const char *fn, de_int64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags);
FILE* de_fopen_for_write(deark *c, const char *fn,
	char *errmsg, size_t errmsg_len, unsigned int flags);

int de_fclose(FILE *fp);

void de_update_file_perms(dbuf *f);
void de_update_file_time(dbuf *f);

void de_declare_fmt(deark *c, const char *fmtname);

void de_dbg_indent(deark *c, int n);
void de_dbg_indent_save(deark *c, int *saved_indent_level);
void de_dbg_indent_restore(deark *c, int saved_indent_level);
void de_dbg_hexdump(deark *c, dbuf *f, de_int64 pos1, de_int64 nbytes_avail,
	de_int64 max_nbytes_to_dump, const char *prefix, unsigned int flags);
void de_dbg_dimensions(deark *c, de_int64 w, de_int64 h);
void de_dbg_pal_entry(deark *c, de_int64 idx, de_uint32 clr);
void de_dbg_pal_entry2(deark *c, de_int64 idx, de_uint32 clr,
	const char *txt_before, const char *txt_in, const char *txt_after);
char *de_get_colorsample_code(deark *c, de_uint32 clr, char *csamp,
	size_t csamplen);

int de_identify_none(deark *c);

///////////////////////////////////////////

const char *de_get_sz_ext(const char *sz);
int de_sz_has_ext(const char *sz, const char *ext);
const char *de_get_input_file_ext(deark *c);
int de_input_file_has_ext(deark *c, const char *ext);

///////////////////////////////////////////

int de_uncompress_zlib(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf);
int de_uncompress_deflate(dbuf *inf, de_int64 inputstart, de_int64 inputsize, dbuf *outf,
	de_int64 *bytes_consumed);

int de_zip_create_file(deark *c);
void de_zip_add_file_to_archive(deark *c, dbuf *f);
void de_zip_close_file(deark *c);

int de_write_png(deark *c, de_bitmap *img, dbuf *f);

de_uint32 de_crc32(const void *buf, de_int64 buf_len);
de_uint32 de_crc32_continue(de_uint32 prev_crc, const void *buf, de_int64 buf_len);

///////////////////////////////////////////

de_int64 de_getui16be_direct(const de_byte *m);
de_int64 de_getui16le_direct(const de_byte *m);
de_int64 de_getui32be_direct(const de_byte *m);
de_int64 de_getui32le_direct(const de_byte *m);
de_int64 de_geti64be_direct(const de_byte *m);
de_int64 de_geti64le_direct(const de_byte *m);
de_uint64 de_getui64be_direct(const de_byte *m);
de_uint64 de_getui64le_direct(const de_byte *m);

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
de_uint64 dbuf_getui64be(dbuf *f, de_int64 pos);
de_uint64 dbuf_getui64le(dbuf *f, de_int64 pos);
de_uint64 dbuf_getui64x(dbuf *f, de_int64 pos, int is_le);

de_int64 dbuf_getint_ext(dbuf *f, de_int64 pos, unsigned int nbytes,
	int is_le, int is_signed);

// The _p functions update a caller-supplied position.
de_byte dbuf_getbyte_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_getui16be_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_getui16le_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_getui32le_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_getui32be_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_geti16be_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_geti16le_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_geti32be_p(dbuf *f, de_int64 *ppos);
de_int64 dbuf_geti32le_p(dbuf *f, de_int64 *ppos);

// Only format modules should use these convenience macros.
// (The DE_WINDOWS condition has no functional purpose; it's a hack to make
// some development tools work better.)
#if !defined(DE_NOT_IN_MODULE) || defined(DE_WINDOWS)
#define de_read(b,p,l) dbuf_read(c->infile,b,p,l);
#define de_getbyte(p) dbuf_getbyte(c->infile,p)
#define de_getui16be(p) dbuf_getui16be(c->infile,p)
#define de_getui16le(p) dbuf_getui16le(c->infile,p)
#define de_geti16be(p) dbuf_geti16be(c->infile,p)
#define de_geti16le(p) dbuf_geti16le(c->infile,p)
#define de_getui32be(p) dbuf_getui32be(c->infile,p)
#define de_getui32le(p) dbuf_getui32le(c->infile,p)
#define de_geti32be(p) dbuf_geti32be(c->infile,p)
#define de_geti32le(p) dbuf_geti32le(c->infile,p)
#define de_geti64be(p) dbuf_geti64be(c->infile,p)
#define de_geti64le(p) dbuf_geti64le(c->infile,p)
#define de_getbyte_p(p) dbuf_getbyte_p(c->infile,p)
#define de_getui16be_p(p) dbuf_getui16be_p(c->infile,p)
#define de_getui16le_p(p) dbuf_getui16le_p(c->infile,p)
#define de_getui32be_p(p) dbuf_getui32be_p(c->infile,p)
#define de_getui32le_p(p) dbuf_getui32le_p(c->infile,p)
#define de_geti16be_p(p) dbuf_geti16be_p(c->infile,p)
#define de_geti16le_p(p) dbuf_geti16le_p(c->infile,p)
#define de_geti32be_p(p) dbuf_geti32be_p(c->infile,p)
#define de_geti32le_p(p) dbuf_geti32le_p(c->infile,p)
#endif

// Read IEEE 754 floating point
double de_getfloat32x_direct(deark *c, const de_byte *m, int is_le);
double dbuf_getfloat32x(dbuf *f, de_int64 pos, int is_le);
double de_getfloat64x_direct(deark *c, const de_byte *m, int is_le);
double dbuf_getfloat64x(dbuf *f, de_int64 pos, int is_le);

int dbuf_read_ascii_number(dbuf *f, de_int64 pos, de_int64 fieldsize,
	int base, de_int64 *value);

#define DE_GETRGBFLAG_BGR 0x1 // Assume BGR order instead of RGB
de_uint32 dbuf_getRGB(dbuf *f, de_int64 pos, unsigned int flags);

// Convert and append encoded bytes from a dbuf to a ucstring.
// (see also ucstring_append_*)
void dbuf_read_to_ucstring(dbuf *f, de_int64 pos, de_int64 len,
	de_ucstring *s, unsigned int conv_flags, int encoding);
// The _n version has an extra max_len field, for convenience.
void dbuf_read_to_ucstring_n(dbuf *f, de_int64 pos, de_int64 len, de_int64 max_len,
	de_ucstring *s, unsigned int conv_flags, int encoding);

// At least one of 'ext' or 'fi' should be non-NULL.
#define DE_CREATEFLAG_IS_AUX   0x1
#define DE_CREATEFLAG_OPT_IMAGE 0x2
dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi, unsigned int createflags);

dbuf *dbuf_open_input_file(deark *c, const char *fn);
dbuf *dbuf_open_input_stdin(deark *c);

dbuf *dbuf_open_input_subfile(dbuf *parent, de_int64 offset, de_int64 size);

// Flag:
//  0x1: Set the maximum size to the 'initialsize'
dbuf *dbuf_create_membuf(deark *c, de_int64 initialsize, unsigned int flags);

// If f is NULL, this is a no-op.
void dbuf_close(dbuf *f);

void dbuf_write(dbuf *f, const de_byte *m, de_int64 len);
void dbuf_write_at(dbuf *f, de_int64 pos, const de_byte *m, de_int64 len);
void dbuf_write_zeroes(dbuf *f, de_int64 len);
void dbuf_truncate(dbuf *f, de_int64 len);
void dbuf_write_run(dbuf *f, de_byte n, de_int64 len);

void de_writeui16le_direct(de_byte *m, de_int64 n);
void de_writeui16be_direct(de_byte *m, de_int64 n);
void de_writeui32le_direct(de_byte *m, de_int64 n);
void de_writeui32be_direct(de_byte *m, de_int64 n);
void dbuf_writebyte(dbuf *f, de_byte n);
void dbuf_writebyte_at(dbuf *f, de_int64 pos, de_byte n);
void dbuf_writeui16le(dbuf *f, de_int64 n);
void dbuf_writeui16be(dbuf *f, de_int64 n);
void dbuf_writeui32le(dbuf *f, de_int64 n);

// Write a NUL-terminated string to a file
void dbuf_puts(dbuf *f, const char *sz);

void dbuf_printf(dbuf *f, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

// Read a slice of one dbuf, and append it to another dbuf.
void dbuf_copy(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf);
void dbuf_copy_at(dbuf *inf, de_int64 input_offset, de_int64 input_len, dbuf *outf, de_int64 outpos);

struct de_stringreaderdata {
   // The number of bytes used by the string in the file (ie includes trailing NUL),
   // even if they aren't all stored in ->sz.
   de_int64 bytes_consumed;

   de_byte *sz; // Stores some or all of the bytes read. Always NUL terminated.
   de_ucstring *str; // Unicode version of ->sz
   char *sz_utf8; // UTF-8 version of ->str (+ NUL terminator) (optional)
   size_t sz_utf8_strlen;
   int was_truncated;
   int found_nul;
};

struct de_stringreaderdata *dbuf_read_string(dbuf *f, de_int64 pos,
	de_int64 max_bytes_to_scan,	de_int64 max_bytes_to_keep,
	unsigned int flags, int encoding);
void de_destroy_stringreaderdata(deark *c, struct de_stringreaderdata *srd);

// Compare bytes in a dbuf to s.
// Note that repeatedly comparing the same dbuf bytes might be inefficient.
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

int dbuf_get_utf16_NULterm_len(dbuf *f, de_int64 pos1, de_int64 bytes_avail,
	de_int64 *bytes_consumed);

int dbuf_find_line(dbuf *f, de_int64 pos1, de_int64 *pcontent_len, de_int64 *ptotal_len);

struct de_fourcc {
  de_byte bytes[4];
  de_uint32 id;
  char id_sanitized_sz[8]; // NUL-terminated printable ASCII
  char id_dbgstr[32]; // Usable only with de_dbg()
};
#define DE_4CCFLAG_REVERSED 0x1
void dbuf_read_fourcc(dbuf *f, de_int64 pos, struct de_fourcc *fcc, int nbytes,
	unsigned int flags);

///////////////////////////////////////////

void de_bitmap_write_to_file(de_bitmap *img, const char *token, unsigned int createflags);
void de_bitmap_write_to_file_finfo(de_bitmap *img, de_finfo *fi, unsigned int createflags);

void de_bitmap_setsample(de_bitmap *img, de_int64 x, de_int64 y,
	de_int64 samplenum, de_byte v);

void de_bitmap_setpixel_gray(de_bitmap *img, de_int64 x, de_int64 y, de_byte v);

void de_bitmap_setpixel_rgb(de_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color);

void de_bitmap_setpixel_rgba(de_bitmap *img, de_int64 x, de_int64 y,
	de_uint32 color);

de_uint32 de_bitmap_getpixel(de_bitmap *img, de_int64 x, de_int64 y);

de_bitmap *de_bitmap_create_noinit(deark *c);
de_bitmap *de_bitmap_create(deark *c, de_int64 width, de_int64 height, int bypp);

void de_bitmap_destroy(de_bitmap *b);

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
void de_convert_row_bilevel(dbuf *f, de_int64 fpos, de_bitmap *img,
	de_int64 rownum, unsigned int flags);

void de_convert_image_bilevel(dbuf *f, de_int64 fpos, de_int64 rowspan,
	de_bitmap *img, unsigned int flags);

void de_convert_and_write_image_bilevel(dbuf *f, de_int64 fpos,
	de_int64 w, de_int64 h, de_int64 rowspan, unsigned int cvtflags,
	de_finfo *fi, unsigned int createflags);

void de_read_palette_rgb(dbuf *f,
	de_int64 fpos, de_int64 num_entries, de_int64 entryspan,
	de_uint32 *pal, de_int64 ncolors_in_pal,
	unsigned int flags);

// Utility function that will work for many of the common kinds of paletted images.
void de_convert_image_paletted(dbuf *f, de_int64 fpos,
	de_int64 bpp, de_int64 rowspan, const de_uint32 *pal,
	de_bitmap *img, unsigned int flags);

de_int64 de_pad_to_2(de_int64 x);
de_int64 de_pad_to_4(de_int64 x);
de_int64 de_pad_to_n(de_int64 x, de_int64 n);

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
#define DE_BITMAPFLAG_MERGE       0x2

void de_bitmap_rect(de_bitmap *img,
	de_int64 xpos, de_int64 ypos, de_int64 width, de_int64 height,
	de_uint32 clr, unsigned int flags);
void de_bitmap_copy_rect(de_bitmap *srcimg, de_bitmap *dstimg,
	de_int64 srcxpos, de_int64 srcypos, de_int64 width, de_int64 height,
	de_int64 dstxpos, de_int64 dstypos, unsigned int flags);

void de_bitmap_apply_mask(de_bitmap *fg, de_bitmap *mask,
	unsigned int flags);

void de_optimize_image_alpha(de_bitmap *img, unsigned int flags);

void de_make_grayscale_palette(de_uint32 *pal, de_int64 num_entries, unsigned int flags);

///////////////////////////////////////////

char de_get_hexchar(int n);
de_byte de_decode_hex_digit(de_byte x, int *errorflag);

de_uint32 de_palette_vga256(int index);
de_uint32 de_palette_ega64(int index);
de_uint32 de_palette_pc16(int index);
de_uint32 de_palette_pcpaint_cga4(int palnum, int index);

const de_byte *de_get_8x8ascii_font_ptr(void);
const de_byte *de_get_vga_cp437_font_ptr(void);

void de_color_to_css(de_uint32 color, char *buf, int buflen);

de_byte de_sample_nbit_to_8bit(de_int64 n, unsigned int x);
de_byte de_scale_63_to_255(de_byte x);
de_byte de_scale_1000_to_255(de_int64 x);
de_byte de_scale_n_to_255(de_int64 n, de_int64 x);
de_uint32 de_rgb565_to_888(de_uint32 x);
de_uint32 de_bgr555_to_888(de_uint32 x);
de_uint32 de_rgb555_to_888(de_uint32 x);

de_int32 de_char_to_unicode(deark *c, de_int32 a, int encoding);
void de_uchar_to_utf8(de_int32 u1, de_byte *utf8buf, de_int64 *p_utf8len);
void dbuf_write_uchar_as_utf8(dbuf *outf, de_int32 u);
int de_utf8_to_uchar(const de_byte *utf8buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf8len);
int de_utf16x_to_uchar(const de_byte *utf16buf, de_int64 buflen,
	de_int32 *p_uchar, de_int64 *p_utf16len, int is_le);

int de_is_ascii(const de_byte *buf, de_int64 buflen);

#define DE_CONVFLAG_STOP_AT_NUL 0x1
#define DE_CONVFLAG_MAKE_PRINTABLE 0x2
#define DE_CONVFLAG_WANT_UTF8 0x10
#define DE_CONVFLAG_ALLOW_HL  0x20

char de_byte_to_printable_char(de_byte b);

// Convert encoded bytes to a NUL-terminated string that can be
// printed to the terminal.
// Consider using {dbuf_read_to_ucstring or dbuf_read_string or
// ucstring_append_bytes} followed by
// {ucstring_get_printable_sz or ucstring_to_printable_sz} instead.
void de_bytes_to_printable_sz(const de_byte *src, de_int64 src_len,
	char *dst, de_int64 dst_len, unsigned int conv_flags, int src_encoding);

de_finfo *de_finfo_create(deark *c);
void de_finfo_destroy(deark *c, de_finfo *fi);

void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s);
void de_finfo_set_name_from_bytes(deark *c, de_finfo *fi, const de_byte *name1,
	de_int64 name1_len, unsigned int conv_flags, int encoding);
void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1,
	int encoding);

de_int32 de_char_to_valid_fn_char(deark *c, de_int32 c1);

de_ucstring *ucstring_create(deark *c);
de_ucstring *ucstring_clone(de_ucstring *src);
void ucstring_destroy(de_ucstring *s);
void ucstring_empty(de_ucstring *s);
void ucstring_truncate(de_ucstring *s, de_int64 newlen);
void ucstring_truncate_at_NUL(de_ucstring *s);
void ucstring_strip_trailing_NUL(de_ucstring *s);
void ucstring_strip_trailing_spaces(de_ucstring *s);
void ucstring_append_char(de_ucstring *s, de_int32 ch);
void ucstring_append_ucstring(de_ucstring *s1, const de_ucstring *s2);
void ucstring_printf(de_ucstring *s, int encoding, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 3, 4)));

// Convert and append an encoded array of bytes to the string.
void ucstring_append_bytes(de_ucstring *s, const de_byte *buf, de_int64 buflen, unsigned int conv_flags, int encoding);

void ucstring_append_sz(de_ucstring *s, const char *sz, int encoding);

void ucstring_write_as_utf8(deark *c, de_ucstring *s, dbuf *outf, int add_bom_if_needed);
de_int64 ucstring_count_utf8_bytes(de_ucstring *s);

// Supported encodings are DE_ENCODING_UTF8, DE_ENCODING_ASCII, DE_ENCODING_LATIN1.
// flags: DE_CONVFLAG_*
void ucstring_to_sz(de_ucstring *s, char *szbuf, size_t szbuf_len, unsigned int flags, int encoding);

// "get printable string"
// Returns a pointer to a NUL-terminated string, that is valid until the
// next ucstring_* function is called on that string.
const char *ucstring_getpsz(de_ucstring *s);
// The _n version limits the number of bytes in the result.
// max_bytes does not count the terminating NUL.
const char *ucstring_getpsz_n(de_ucstring *s, de_int64 max_bytes);

#define DE_DBG_MAX_STRLEN 500
// Same as ..._n, with max_bytes=DE_DBG_MAX_STRLEN
const char *ucstring_getpsz_d(de_ucstring *s);

// Helper function for printing the contents of bit-flags fields
void ucstring_append_flags_item(de_ucstring *s, const char *str);

void de_write_codepoint_to_html(deark *c, dbuf *f, de_int32 ch);

int de_encoding_name_to_code(const char *encname);
int de_windows_codepage_to_encoding(deark *c, int wincodepage,
	char *encname, size_t encname_len, unsigned int flags);

void de_copy_bits(const de_byte *src, de_int64 srcbitnum,
	de_byte *dst, de_int64 dstbitnum, de_int64 bitstocopy);

void de_decode_base16(deark *c, dbuf *inf, de_int64 pos1, de_int64 len,
	dbuf *outf, unsigned int flags);

struct de_inthashtable;
struct de_inthashtable *de_inthashtable_create(deark *c);
void de_inthashtable_destroy(deark *c, struct de_inthashtable *ht);
int de_inthashtable_add_item(deark *c, struct de_inthashtable *ht, de_int64 key, void *value);
int de_inthashtable_get_item(deark *c, struct de_inthashtable *ht, de_int64 key, void **pvalue);
int de_inthashtable_item_exists(deark *c, struct de_inthashtable *ht, de_int64 key);
int de_inthashtable_remove_item(deark *c, struct de_inthashtable *ht, de_int64 key, void **pvalue);
int de_inthashtable_remove_any_item(deark *c, struct de_inthashtable *ht, de_int64 *pkey, void **pvalue);

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
void de_font_paint_character_idx(deark *c, de_bitmap *img,
	struct de_bitmap_font *font, de_int64 char_idx,
	de_int64 xpos, de_int64 ypos, de_uint32 fgcol, de_uint32 bgcol, unsigned int flags);
void de_font_paint_character_cp(deark *c, de_bitmap *img,
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

struct de_char_comment {
	de_ucstring *s;
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
	de_int64 num_comments;
	struct de_char_comment *comments; // Array of [num_comments] comments
};

void de_char_output_to_file(deark *c, struct de_char_context *charctx);

void de_free_charctx(deark *c, struct de_char_context *charctx);

///////////////////////////////////////////

void de_unix_time_to_timestamp(de_int64 ut, struct de_timestamp *ts);
void de_mac_time_to_timestamp(de_int64 mt, struct de_timestamp *ts);
void de_FILETIME_to_timestamp(de_int64 ft, struct de_timestamp *ts);
void de_dos_datetime_to_timestamp(struct de_timestamp *ts,
   de_int64 ddate, de_int64 dtime, de_int64 offset_seconds);
de_int64 de_timestamp_to_unix_time(const struct de_timestamp *ts);
void de_make_timestamp(struct de_timestamp *ts,
	de_int64 yr, de_int64 mo, de_int64 da,
	de_int64 hr, de_int64 mi, double se, de_int64 offset_seconds);
void de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags);
void de_current_time_to_timestamp(struct de_timestamp *ts);
