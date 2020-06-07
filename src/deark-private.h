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

#define DE_MAX_SANE_OBJECT_SIZE 100000000

enum de_encoding_enum {
	DE_ENCODING_UNKNOWN = 0,
	DE_ENCODING_ASCII,
	DE_ENCODING_UTF8,
	DE_ENCODING_UTF16LE,
	DE_ENCODING_UTF16BE,
	DE_ENCODING_LATIN1,
	DE_ENCODING_LATIN2,
	DE_ENCODING_WINDOWS1250,
	DE_ENCODING_WINDOWS1251,
	DE_ENCODING_WINDOWS1252,
	DE_ENCODING_WINDOWS1253,
	DE_ENCODING_WINDOWS1254,
	DE_ENCODING_CP437,
	DE_ENCODING_MACROMAN,
	DE_ENCODING_ATARIST,
	DE_ENCODING_PALM,
	DE_ENCODING_RISCOS,
	DE_ENCODING_PETSCII,
	DE_ENCODING_DEC_SPECIAL_GRAPHICS
};
#define DE_ENCODING_CP437_G DE_ENCODING_CP437

#define DE_ENCSUBTYPE_CONTROLS     2
#define DE_ENCSUBTYPE_HYBRID       3
#define DE_ENCSUBTYPE_PRINTABLE    4
typedef enum de_encoding_enum de_encoding;
typedef int de_ext_encoding;
#define DE_EXTENC_MAKE(b, st) (((int)(b) & 0xff) | ((int)(st)<<8))
#define DE_EXTENC_GET_BASE(ee) ((int)(ee) & 0xff)
#define DE_EXTENC_GET_SUBTYPE(ee) ((int)(ee) >> 8)

#define DE_CODEPOINT_HL          0x0001
#define DE_CODEPOINT_UNHL        0x0002
#define DE_CODEPOINT_RGBSAMPLE   0x0003
#define DE_CODEPOINT_MOVED      0xfde00
#define DE_CODEPOINT_MOVED_MAX  0xffffd
#define DE_CODEPOINT_INVALID 0x0fffffff // Generic invalid codepoint
#define DE_CODEPOINT_BYTE00  0x10000000 // More "invalid" codepoints
#define DE_CODEPOINT_BYTEFF  0x100000ff

#define DE_ARRAYCOUNT(x) (sizeof(x)/sizeof((x)[0]))

struct de_ucstring_struct;
typedef struct de_ucstring_struct de_ucstring;
struct dbuf_struct;
typedef struct dbuf_struct dbuf;
struct de_finfo_struct;
typedef struct de_finfo_struct de_finfo;

struct de_module_params_struct;
typedef struct de_module_params_struct de_module_params;

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
#define DE_MODFLAG_SHAREDDETECTION 0x10 // Module modifies deark::detection_data
#define DE_MODFLAG_DISABLEDETECT 0x100 // Ignore results of autodetection
	u32 flags;
	u32 unique_id; // or 0. Rarely used.
#define DE_MAX_MODULE_ALIASES 2
	const char *id_alias[DE_MAX_MODULE_ALIASES];
};
typedef void (*de_module_getinfo_fn)(deark *c, struct deark_module_info *mi);

struct de_ucstring_struct {
	deark *c;
	i32 *str;
	i64 len; // len and alloc are measured in characters, not bytes
	i64 alloc;
	char *tmp_string;
};

struct de_timestamp {
	u8 is_valid;
#define DE_TZCODE_UNKNOWN 0 // should be treated as UTC in most cases
#define DE_TZCODE_UTC     1 // known to be UTC
#define DE_TZCODE_LOCAL   2 // likely to be some local time
	u8 tzcode;
	// Timestamp precision codes are in order of increasing precision, except
	// for 0 (UNKNOWN).
#define DE_TSPREC_UNKNOWN 0 // default, usually treated as 1sec
#define DE_TSPREC_1DAY 10
#define DE_TSPREC_2SEC 20
#define DE_TSPREC_1SEC 30
#define DE_TSPREC_HIGH 40 // = better than 1 second
	u8 precision;
	i64 ts_FILETIME; // the timestamp, in Windows FILETIME format
};

typedef void (*de_writelistener_cb_type)(dbuf *f, void *userdata, const u8 *buf, i64 buf_len);
typedef void (*de_dbufcustomread_type)(dbuf *f, void *userdata, u8 *buf, i64 pos, i64 len);
typedef void (*de_dbufcustomwrite_type)(dbuf *f, void *userdata, const u8 *buf, i64 buf_len);

// dbuf is our generalized I/O object. Used for many purposes.
struct dbuf_struct {
#define DBUF_TYPE_NULL    0
#define DBUF_TYPE_IFILE   1
#define DBUF_TYPE_OFILE   2
#define DBUF_TYPE_MEMBUF  3
#define DBUF_TYPE_IDBUF   4 // nested dbuf, for input
#define DBUF_TYPE_STDOUT  5
#define DBUF_TYPE_STDIN   6
#define DBUF_TYPE_FIFO    7
#define DBUF_TYPE_ODBUF   8 // nested dbuf, for output
#define DBUF_TYPE_CUSTOM  9
	int btype;
	u8 is_managed;

	deark *c;
	FILE *fp;
	i64 len;

	i64 max_len_hard; // Serious error if this is exceeded
	i64 len_limit; // Valid if has_len_limit is set. May only work for type MEMBUF.
	int has_len_limit;

	int file_pos_known;
	i64 file_pos;

	struct dbuf_struct *parent_dbuf; // used for DBUF_TYPE_DBUF
	i64 offset_into_parent_dbuf; // used for DBUF_TYPE_DBUF

	u8 write_memfile_to_zip_archive;
	u8 writing_to_tar_archive;
	char *name; // used for DBUF_TYPE_OFILE (utf-8)

	i64 membuf_alloc;
	u8 *membuf_buf;

	void *userdata_for_writelistener;
	de_writelistener_cb_type writelistener_cb;
	void *userdata_for_customread;
	de_dbufcustomread_type customread_fn; // used for DBUF_TYPE_CUSTOM
	void *userdata_for_customwrite;
	de_dbufcustomwrite_type customwrite_fn; // used for DBUF_TYPE_CUSTOM

#define DE_CACHE_POLICY_NONE    0
#define DE_CACHE_POLICY_ENABLED 1
	int cache_policy;
	i64 cache_start_pos;
	i64 cache_bytes_used;
	u8 *cache;

	// cache2 is a simple 1-byte cache, mainly to speed up de_convert_row_bilevel().
	i64 cache2_start_pos;
	i64 cache2_bytes_used;
	u8 cache2[1];

	// Things copied from the de_finfo object at file creation
	de_finfo *fi_copy;
};

// Image density (resolution) settings
struct de_density_info {
#define DE_DENSITY_UNKNOWN   0
#define DE_DENSITY_UNK_UNITS 1
#define DE_DENSITY_DPI       2
	int code;
	// Note: If units are unknown, xdens and ydens must be integers.
	double xdens;
	double ydens;
};

// Extended information & metadata about a file to be written.
struct de_finfo_struct {
	de_ucstring *file_name_internal; // Modules should avoid using this field directly.
	u8 original_filename_flag; // Indicates if .file_name_internal is a real file name
	u8 is_directory; // Does the "file" represent a subdirectory?
	u8 is_root_dir; // Is this definitely the unnamed root (".") dir?
	u8 detect_root_dot_dir; // Directories named "." are special.
	u8 orig_name_was_dot; // Internal use
	u8 has_hotspot;

#define DE_MODEFLAG_NONEXE 0x01 // Make the output file non-executable.
#define DE_MODEFLAG_EXE    0x02 // Make the output file executable.
	unsigned int mode_flags;

#define DE_TIMESTAMPIDX_MODIFY      0 // External timestamps...
#define DE_TIMESTAMPIDX_CREATE      1
#define DE_TIMESTAMPIDX_ACCESS      2
#define DE_TIMESTAMPIDX_ATTRCHANGE  3
#define DE_TIMESTAMPIDX_BACKUP      4
#define DE_TIMESTAMPIDX_COUNT       5
	struct de_timestamp timestamp[DE_TIMESTAMPIDX_COUNT];

	struct de_timestamp internal_mod_time; // E.g. for PNG tIME chunk
	struct de_density_info density;
	de_ucstring *name_other; // Modules can use this field as needed.
	int hotspot_x, hotspot_y; // Measured from upper-left pixel (after handling 'flipped')
};

struct deark_bitmap_struct {
	deark *c;
	i64 width;
	i64 height;
	int invalid_image_flag;
	int bytes_per_pixel;
	// 'flipped' changes the coordinate system when writing the bitmap to a file.
	// It is ignored by most other functions.
	int flipped;
	u8 *bitmap;
	i64 bitmap_size; // bytes allocated for bitmap
	int orig_colortype; // Optional; can be used by modules
	int orig_bitdepth; // Optional; can be used by modules
};
typedef struct deark_bitmap_struct de_bitmap;

struct de_SAUCE_detection_data {
	u8 has_SAUCE;
	u8 data_type;
	u8 file_type;
};

struct de_ID3_detection_data {
	u8 detection_attempted;
	u8 has_id3v2;
	u32 bytes_at_start;
};

// This struct is a crude way for data to be shared by the various format
// identification functions. It generally should not be used outside of them --
// but it can be, provided it's only used as a cache.
struct de_detection_data_struct {
	int best_confidence_so_far;
	u8 has_utf8_bom;
	u8 is_macbinary;
	u8 SAUCE_detection_attempted;
	u8 zip_eocd_looked_for;
	u8 zip_eocd_found;
	i64 zip_eocd_pos; // valid if zip_eocd_found
	struct de_SAUCE_detection_data sauce;
	struct de_ID3_detection_data id3;
};

struct de_module_in_params {
	const char *codes;
	// Module-specific fields:
	u32 flags;
	de_encoding input_encoding;
	i64 offset_in_parent;
	dbuf *parent_dbuf;
	de_finfo *fi;
};

struct de_module_out_params {
	// Fields are module-specific.
	u32 flags;
	u32 uint1;
	u32 uint2;
	u32 uint3;
	u32 uint4;
	i64 int64_1;
	// The caller is responsible for freeing pointer fields.
	// The callee should not use these fields unless requested.
	de_finfo *fi;
	void *obj1;
};

struct de_module_params_struct {
	struct de_module_in_params in_params;
	struct de_module_out_params out_params;
};

struct deark_ext_option {
	char *name;
	char *val;
};

typedef void (*de_module_register_fn_type)(deark *c);

enum de_moddisp_enum {
	DE_MODDISP_NONE = 0,    // No active module, or unknown
	DE_MODDISP_AUTODETECT,  // Format was autodetected
	DE_MODDISP_EXPLICIT,    // User used -m to select the module
	DE_MODDISP_INTERNAL     // Another module is using this module
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

	enum de_moddisp_enum module_disposition; // Why are we using this module?

	// Always valid during identify(); can be NULL during run().
	struct de_detection_data_struct *detection_data;
	////////////////////////////////////////////////////

	int file_count; // The number of extractable files encountered so far.

	// The number of files we've actually written (or listed), after taking
	// first_output_file/max_output_files into account.
	int num_files_extracted;

	i64 total_output_size;
	int error_count;
	u8 serious_error_flag;

	const char *input_filename;
	const char *input_format_req; // Format requested
	const char *modcodes_req;
	i64 slice_start_req; // Used if we're only to look at part of the file.
	i64 slice_size_req;
	int slice_size_req_valid;
	int suppress_detection_by_filename;

	int output_style; // DE_OUTPUTSTYLE_*
	int archive_fmt; // If output_style==DE_OUTPUTSTYLE_ARCHIVE
	int input_style; // DE_INPUTSTYLE_*
	u8 archive_to_stdout;
	u8 allow_subdirs;

	int extract_policy; // DE_EXTRACTPOLICY_*
	int extract_level;
	u8 list_mode;
	u8 list_mode_include_file_id;
	int first_output_file; // first file = 0
	int max_output_files; // -1 = no limit
	i64 max_image_dimension;
	i64 max_output_file_size;
	i64 max_total_output_size;
	int show_infomessages;
	int show_warnings;
	int dbg_indent_amount;
	u8 write_bom;
	u8 write_density;
	u8 ascii_html;
	u8 keep_dir_entries;
	u8 filenames_from_file;
	u8 macformat_known;
	u8 macformat;
	int overwrite_mode;
	u8 preserve_file_times;
	u8 preserve_file_times_archives;
	u8 preserve_file_times_internal;
	u8 reproducible_output;
	struct de_timestamp reproducible_timestamp;
	int can_decode_fltpt;
	int host_is_le;
	u8 identify_only;
	u8 modhelp_req;
	de_encoding input_encoding;
	i64 input_tz_offs_seconds;

	de_msgfn_type msgfn; // Caller's message output function
	de_specialmsgfn_type specialmsgfn;
	de_fatalerrorfn_type fatalerrorfn;
	const char *dprefix;

	u8 tmpflag1;
	u8 tmpflag2;
	u8 pngcprlevel_valid;
	unsigned int pngcmprlevel;
	void *zip_data;
	void *tar_data;
	dbuf *extrlist_dbuf;

	char *base_output_filename;
	char *output_archive_filename;
	char *extrlist_filename;

	const char *onlymods_string;
	const char *disablemods_string;
	const char *onlydetectmods_string;
	const char *nodetectmods_string;

	struct de_timestamp current_time;

	de_module_register_fn_type module_register_fn;

	int num_modules;
	struct deark_module_info *module_info; // Pointer to an array

#define DE_MAX_EXT_OPTIONS 16
	int num_ext_options;
	struct deark_ext_option ext_option[DE_MAX_EXT_OPTIONS];
};

void de_fatalerror(deark *c);

deark *de_create_internal(void);
int de_run_module(deark *c, struct deark_module_info *mi, de_module_params *mparams,
	enum de_moddisp_enum moddisp);
int de_run_module_by_id(deark *c, const char *id, de_module_params *mparams);
int de_run_module_by_id_on_slice(deark *c, const char *id, de_module_params *mparams,
	dbuf *f, i64 pos, i64 len);
int de_run_module_by_id_on_slice2(deark *c, const char *id, const char *codes,
	dbuf *f, i64 pos, i64 len);
int de_get_module_idx_by_id(deark *c, const char *module_id);
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
#define de_zeromem(a,b) memset((a),0,(b))
#define de_memchr   memchr
#ifdef DE_WINDOWS
#define de_sscanf   sscanf_s
#else
#define de_sscanf   sscanf
#endif
#define de_strtod   strtod

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
void de_info(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_msg(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_vwarn(deark *c, const char *fmt, va_list ap);
void de_warn(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void de_verr(deark *c, const char *fmt, va_list ap);
void de_err(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));

FILE* de_fopen_for_read(deark *c, const char *fn, i64 *len,
	char *errmsg, size_t errmsg_len, unsigned int *returned_flags);
FILE* de_fopen_for_write(deark *c, const char *fn,
	char *errmsg, size_t errmsg_len, int overwrite_mode,
	unsigned int flags);
int de_fseek(FILE *fp, i64 offs, int whence);
i64 de_ftell(FILE *fp);
int de_fclose(FILE *fp);
void de_update_file_attribs(dbuf *f, u8 preserve_file_times);

void de_declare_fmt(deark *c, const char *fmtname);
void de_declare_fmtf(deark *c, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
de_encoding de_get_input_encoding(deark *c, de_module_params *mparams,
	de_encoding dflt);

void de_dbg_indent(deark *c, int n);
void de_dbg_indent_save(deark *c, int *saved_indent_level);
void de_dbg_indent_restore(deark *c, int saved_indent_level);
void de_dbg_hexdump(deark *c, dbuf *f, i64 pos1, i64 nbytes_avail,
	i64 max_nbytes_to_dump, const char *prefix, unsigned int flags);
void de_hexdump2(deark *c, dbuf *f, i64 pos1, i64 nbytes_avail,
	i64 max_nbytes_to_dump, unsigned int flags);
void de_dbg_dimensions(deark *c, i64 w, i64 h);
void de_dbg_pal_entry(deark *c, i64 idx, u32 clr);
void de_dbg_pal_entry2(deark *c, i64 idx, u32 clr,
	const char *txt_before, const char *txt_in, const char *txt_after);
char *de_get_colorsample_code(deark *c, u32 clr, char *csamp,
	size_t csamplen);

const char *de_get_ext_option(deark *c, const char *name);
int de_get_ext_option_bool(deark *c, const char *name, int defaultval);

///////////////////////////////////////////

const char *de_get_sz_ext(const char *sz);
int de_sz_has_ext(const char *sz, const char *ext);
const char *de_get_input_file_ext(deark *c);
int de_input_file_has_ext(deark *c, const char *ext);
int de_havemodcode(deark *c, de_module_params *mparams, int code);

///////////////////////////////////////////

int de_archive_initialize(deark *c);
void de_get_reproducible_timestamp(deark *c, struct de_timestamp *ts);

int de_tar_create_file(deark *c);
void de_tar_start_member_file(deark *c, dbuf *f);
void de_tar_end_member_file(deark *c, dbuf *f);
void de_tar_close_file(deark *c);

///////////////////////////////////////////

int de_zip_create_file(deark *c);
void de_zip_add_file_to_archive(deark *c, dbuf *f);
void de_zip_close_file(deark *c);

int de_write_png(deark *c, de_bitmap *img, dbuf *f);

///////////////////////////////////////////

i64 de_geti8_direct(const u8 *m);
i64 de_getu16be_direct(const u8 *m);
i64 de_getu16le_direct(const u8 *m);
i64 de_getu32be_direct(const u8 *m);
i64 de_getu32le_direct(const u8 *m);
i64 de_geti64be_direct(const u8 *m);
i64 de_geti64le_direct(const u8 *m);
u64 de_getu64be_direct(const u8 *m);
u64 de_getu64le_direct(const u8 *m);

void dbuf_read(dbuf *f, u8 *buf, i64 pos, i64 len);
i64 dbuf_standard_read(dbuf *f, u8 *buf, i64 n, i64 *fpos);

u8 dbuf_getbyte(dbuf *f, i64 pos);
i64 dbuf_geti8(dbuf *f, i64 pos);
i64 dbuf_getu16be(dbuf *f, i64 pos);
i64 dbuf_getu16le(dbuf *f, i64 pos);
i64 dbuf_getu16x(dbuf *f, i64 pos, int is_le);
i64 dbuf_geti16be(dbuf *f, i64 pos);
i64 dbuf_geti16le(dbuf *f, i64 pos);
i64 dbuf_geti16x(dbuf *f, i64 pos, int is_le);
i64 dbuf_getu32be(dbuf *f, i64 pos);
i64 dbuf_getu32le(dbuf *f, i64 pos);
i64 dbuf_getu32x(dbuf *f, i64 pos, int is_le);
i64 dbuf_geti32be(dbuf *f, i64 pos);
i64 dbuf_geti32le(dbuf *f, i64 pos);
i64 dbuf_geti32x(dbuf *f, i64 pos, int is_le);
i64 dbuf_geti64be(dbuf *f, i64 pos);
i64 dbuf_geti64le(dbuf *f, i64 pos);
i64 dbuf_geti64x(dbuf *f, i64 pos, int is_le);
u64 dbuf_getu64be(dbuf *f, i64 pos);
u64 dbuf_getu64le(dbuf *f, i64 pos);
u64 dbuf_getu64x(dbuf *f, i64 pos, int is_le);

i64 dbuf_getint_ext(dbuf *f, i64 pos, unsigned int nbytes,
	int is_le, int is_signed);

// The _p functions update a caller-supplied position.
u8 dbuf_getbyte_p(dbuf *f, i64 *ppos);
i64 dbuf_getu16be_p(dbuf *f, i64 *ppos);
i64 dbuf_getu16le_p(dbuf *f, i64 *ppos);
i64 dbuf_getu32le_p(dbuf *f, i64 *ppos);
i64 dbuf_getu32be_p(dbuf *f, i64 *ppos);
i64 dbuf_geti16be_p(dbuf *f, i64 *ppos);
i64 dbuf_geti16le_p(dbuf *f, i64 *ppos);
i64 dbuf_geti32be_p(dbuf *f, i64 *ppos);
i64 dbuf_geti32le_p(dbuf *f, i64 *ppos);

// Only format modules should use these convenience macros.
// (The DE_WINDOWS condition has no functional purpose; it's a hack to make
// some development tools work better.)
#if !defined(DE_NOT_IN_MODULE) || defined(DE_WINDOWS)
#define de_read(b,p,l) dbuf_read(c->infile,b,p,l);
#define de_getbyte(p) dbuf_getbyte(c->infile,p)
#define de_getu16be(p) dbuf_getu16be(c->infile,p)
#define de_getu16le(p) dbuf_getu16le(c->infile,p)
#define de_geti16be(p) dbuf_geti16be(c->infile,p)
#define de_geti16le(p) dbuf_geti16le(c->infile,p)
#define de_getu32be(p) dbuf_getu32be(c->infile,p)
#define de_getu32le(p) dbuf_getu32le(c->infile,p)
#define de_geti32be(p) dbuf_geti32be(c->infile,p)
#define de_geti32le(p) dbuf_geti32le(c->infile,p)
#define de_geti64be(p) dbuf_geti64be(c->infile,p)
#define de_geti64le(p) dbuf_geti64le(c->infile,p)
#define de_getbyte_p(p) dbuf_getbyte_p(c->infile,p)
#define de_getu16be_p(p) dbuf_getu16be_p(c->infile,p)
#define de_getu16le_p(p) dbuf_getu16le_p(c->infile,p)
#define de_getu32be_p(p) dbuf_getu32be_p(c->infile,p)
#define de_getu32le_p(p) dbuf_getu32le_p(c->infile,p)
#define de_geti16be_p(p) dbuf_geti16be_p(c->infile,p)
#define de_geti16le_p(p) dbuf_geti16le_p(c->infile,p)
#define de_geti32be_p(p) dbuf_geti32be_p(c->infile,p)
#define de_geti32le_p(p) dbuf_geti32le_p(c->infile,p)
#endif

// Read IEEE 754 floating point
double de_getfloat32x_direct(deark *c, const u8 *m, int is_le);
double dbuf_getfloat32x(dbuf *f, i64 pos, int is_le);
double de_getfloat64x_direct(deark *c, const u8 *m, int is_le);
double dbuf_getfloat64x(dbuf *f, i64 pos, int is_le);

int dbuf_read_ascii_number(dbuf *f, i64 pos, i64 fieldsize,
	int base, i64 *value);

#define DE_GETRGBFLAG_BGR 0x1 // Assume BGR order instead of RGB
u32 dbuf_getRGB(dbuf *f, i64 pos, unsigned int flags);

// Convert and append encoded bytes from a dbuf to a ucstring.
// (see also ucstring_append_*)
void dbuf_read_to_ucstring(dbuf *f, i64 pos, i64 len,
	de_ucstring *s, unsigned int conv_flags, de_ext_encoding encoding);
// The _n version has an extra max_len field, for convenience.
void dbuf_read_to_ucstring_n(dbuf *f, i64 pos, i64 len, i64 max_len,
	de_ucstring *s, unsigned int conv_flags, de_ext_encoding encoding);

// At least one of 'ext' or 'fi' should be non-NULL.
#define DE_CREATEFLAG_IS_AUX   0x1
#define DE_CREATEFLAG_OPT_IMAGE 0x2
dbuf *dbuf_create_output_file(deark *c, const char *ext, de_finfo *fi, unsigned int createflags);

dbuf *dbuf_create_unmanaged_file(deark *c, const char *fname, int overwrite_mode, unsigned int flags);
dbuf *dbuf_create_unmanaged_file_stdout(deark *c, const char *name);
dbuf *dbuf_open_input_file(deark *c, const char *fn);
dbuf *dbuf_open_input_stdin(deark *c);
dbuf *dbuf_open_input_subfile(dbuf *parent, i64 offset, i64 size);
dbuf *dbuf_create_custom_dbuf(deark *c, i64 apparent_size, unsigned int flags);

// Flag:
//  0x1: Set the maximum size to the 'initialsize'
dbuf *dbuf_create_membuf(deark *c, i64 initialsize, unsigned int flags);

// If f is NULL, this is a no-op.
void dbuf_close(dbuf *f);

void dbuf_set_writelistener(dbuf *f, de_writelistener_cb_type fn, void *userdata);

void dbuf_write(dbuf *f, const u8 *m, i64 len);
void dbuf_write_at(dbuf *f, i64 pos, const u8 *m, i64 len);
void dbuf_write_zeroes(dbuf *f, i64 len);
void dbuf_truncate(dbuf *f, i64 len);
void dbuf_write_run(dbuf *f, u8 n, i64 len);

void de_writeu16le_direct(u8 *m, i64 n);
void de_writeu16be_direct(u8 *m, i64 n);
void de_writeu32le_direct(u8 *m, i64 n);
void de_writeu32be_direct(u8 *m, i64 n);
void de_writeu64le_direct(u8 *m, u64 n);
void dbuf_writebyte(dbuf *f, u8 n);
void dbuf_writebyte_at(dbuf *f, i64 pos, u8 n);
void dbuf_writeu16le(dbuf *f, i64 n);
void dbuf_writeu16be(dbuf *f, i64 n);
void dbuf_writei16le(dbuf *f, i64 n);
void dbuf_writei16be(dbuf *f, i64 n);
void dbuf_writeu32le(dbuf *f, i64 n);
void dbuf_writeu32be(dbuf *f, i64 n);
void dbuf_writei32le(dbuf *f, i64 n);
void dbuf_writei32be(dbuf *f, i64 n);
void dbuf_writeu64le(dbuf *f, u64 n);

void dbuf_puts(dbuf *f, const char *sz);
void dbuf_printf(dbuf *f, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 2, 3)));
void dbuf_flush(dbuf *f);

// Read a slice of one dbuf, and append it to another dbuf.
void dbuf_copy(dbuf *inf, i64 input_offset, i64 input_len, dbuf *outf);
void dbuf_copy_at(dbuf *inf, i64 input_offset, i64 input_len, dbuf *outf, i64 outpos);

struct de_stringreaderdata {
   // The number of bytes used by the string in the file (ie includes trailing NUL),
   // even if they aren't all stored in ->sz.
   i64 bytes_consumed;

   char *sz; // Stores some or all of the bytes read. Always NUL terminated.
   size_t sz_strlen;
   de_ucstring *str; // Unicode version of ->sz
   char *sz_utf8; // UTF-8 version of ->str (+ NUL terminator) (optional)
   size_t sz_utf8_strlen;
   int was_truncated;
   int found_nul;
};

struct de_stringreaderdata *dbuf_read_string(dbuf *f, i64 pos,
	i64 max_bytes_to_scan,	i64 max_bytes_to_keep,
	unsigned int flags, de_ext_encoding ee);
void de_destroy_stringreaderdata(deark *c, struct de_stringreaderdata *srd);

// Compare bytes in a dbuf to s.
// Note that repeatedly comparing the same dbuf bytes might be inefficient.
int dbuf_memcmp(dbuf *f, i64 pos, const void *s, size_t n);

// Read a slice of a dbuf, and create a new file containing only that.
// At least one of 'ext' or 'fi' should be non-NULL.
int dbuf_create_file_from_slice(dbuf *inf, i64 pos, i64 data_size,
	const char *ext, de_finfo *fi, unsigned int createflags);

int dbuf_has_utf8_bom(dbuf *f, i64 pos);

int dbuf_dump_to_file(dbuf *inf, const char *fn);

// Remove everything from the dbuf.
// May be valid only for memory buffers.
void dbuf_empty(dbuf *f);

void dbuf_set_length_limit(dbuf *f, i64 max_len);

int dbuf_search_byte(dbuf *f, const u8 b, i64 startpos,
	i64 haystack_len, i64 *foundpos);

int dbuf_search(dbuf *f, const u8 *needle, i64 needle_len,
	i64 startpos, i64 haystack_len, i64 *foundpos);

int dbuf_get_utf16_NULterm_len(dbuf *f, i64 pos1, i64 bytes_avail,
	i64 *bytes_consumed);

int dbuf_find_line(dbuf *f, i64 pos1, i64 *pcontent_len, i64 *ptotal_len);

struct de_fourcc {
  u8 bytes[4];
  u32 id;
  char id_sanitized_sz[8]; // NUL-terminated printable ASCII
  char id_dbgstr[32]; // Usable only with de_dbg()
};
#define DE_4CCFLAG_REVERSED 0x1
void dbuf_read_fourcc(dbuf *f, i64 pos, struct de_fourcc *fcc, int nbytes,
	unsigned int flags);

struct de_bufferedreadctx {
	void *userdata;
	deark *c;
	i64 offset;
	i64 bytes_consumed;
	u8 eof_flag;
};
typedef int (*de_buffered_read_cbfn)(struct de_bufferedreadctx *brctx,
	const u8 *buf, i64 buf_len);
int dbuf_buffered_read(dbuf *f, i64 pos, i64 len,
	de_buffered_read_cbfn cbfn, void *userdata);

int de_is_all_zeroes(const u8 *b, i64 n);
int dbuf_is_all_zeroes(dbuf *f, i64 pos, i64 len);

///////////////////////////////////////////

void de_bitmap_write_to_file(de_bitmap *img, const char *token, unsigned int createflags);
void de_bitmap_write_to_file_finfo(de_bitmap *img, de_finfo *fi, unsigned int createflags);

void de_bitmap_setsample(de_bitmap *img, i64 x, i64 y,
	i64 samplenum, u8 v);

void de_bitmap_setpixel_gray(de_bitmap *img, i64 x, i64 y, u8 v);

void de_bitmap_setpixel_rgb(de_bitmap *img, i64 x, i64 y,
	u32 color);

void de_bitmap_setpixel_rgba(de_bitmap *img, i64 x, i64 y,
	u32 color);

u32 de_bitmap_getpixel(de_bitmap *img, i64 x, i64 y);

de_bitmap *de_bitmap_create_noinit(deark *c);
de_bitmap *de_bitmap_create(deark *c, i64 width, i64 height, int bypp);

void de_bitmap_destroy(de_bitmap *b);

#define DE_COLOR_A(x)  (((x)>>24)&0xff)
#define DE_COLOR_R(x)  (((x)>>16)&0xff)
#define DE_COLOR_G(x)  (((x)>>8)&0xff)
#define DE_COLOR_B(x)  ((x)&0xff)
#define DE_COLOR_K(x)  (((x)>>16)&0xff) // Gray value. Arbitrarily use the Red channel.

#define DE_STOCKCOLOR_BLACK   0xff000000U
#define DE_STOCKCOLOR_WHITE   0xffffffffU
#define DE_STOCKCOLOR_TRANSPARENT 0x00000000U

#define DE_MAKE_RGBA(r,g,b,a)  ((((u32)(a))<<24)|((r)<<16)|((g)<<8)|(b))
#define DE_MAKE_RGB(r,g,b)     ((((u32)0xff)<<24)|((r)<<16)|((g)<<8)|(b))
#define DE_MAKE_GRAY(k)        ((((u32)0xff)<<24)|((k)<<16)|((k)<<8)|(k))
#define DE_SET_ALPHA(v,a)      (((v)&0x00ffffff)|(((u32)(a))<<24))
#define DE_MAKE_OPAQUE(v)      (((u32)(v))|0xff000000U)

// Return the index'th symbol in the bitmap row beginning at file position rowstart.
// A symbol has bps bits. bps must be 1, 2, 4, or 8.
u8 de_get_bits_symbol(dbuf *f, i64 bps, i64 rowstart, i64 index);

u8 de_get_bits_symbol_lsb(dbuf *f, i64 bps, i64 rowstart, i64 index);

u8 de_get_bits_symbol2(dbuf *f, int nbits, i64 bytepos, i64 bitpos);

// Conversion flags used by some functions.
#define DE_CVTF_WHITEISZERO 0x1
#define DE_CVTF_LSBFIRST    0x2

// Utility function for the common case of reading a packed bi-level row, and
// writing to a bitmap.
void de_convert_row_bilevel(dbuf *f, i64 fpos, de_bitmap *img,
	i64 rownum, unsigned int flags);

void de_convert_image_bilevel(dbuf *f, i64 fpos, i64 rowspan,
	de_bitmap *img, unsigned int flags);

void de_convert_and_write_image_bilevel(dbuf *f, i64 fpos,
	i64 w, i64 h, i64 rowspan, unsigned int cvtflags,
	de_finfo *fi, unsigned int createflags);

void de_read_palette_rgb(dbuf *f,
	i64 fpos, i64 num_entries, i64 entryspan,
	u32 *pal, i64 ncolors_in_pal,
	unsigned int flags);

// Utility function that will work for many of the common kinds of paletted images.
void de_convert_image_paletted(dbuf *f, i64 fpos,
	i64 bpp, i64 rowspan, const u32 *pal,
	de_bitmap *img, unsigned int flags);

void de_convert_image_rgb(dbuf *f, i64 fpos,
	i64 rowspan, i64 pixelspan, de_bitmap *img, unsigned int flags);

i64 de_min_int(i64 n1, i64 n2);
i64 de_max_int(i64 n1, i64 n2);
i64 de_pad_to_2(i64 x);
i64 de_pad_to_4(i64 x);
i64 de_pad_to_n(i64 x, i64 n);
i64 de_pow2(i64 x);

// Calculate the number of bits required to store n symbols.
// Intended to be used with bitmap graphics.
// Returns a minimum of 1, maximum of 32.
i64 de_log2_rounded_up(i64 n);

// Test if the image dimensions are valid and supported.
int de_good_image_dimensions_noerr(deark *c, i64 w, i64 h);

// Test if the image dimensions are valid and supported. Report an error if not.
int de_good_image_dimensions(deark *c, i64 w, i64 h);

// Test if the number of images is sane. Report an error if not.
int de_good_image_count(deark *c, i64 n);

int de_is_grayscale_palette(const u32 *pal, i64 num_entries);

#define DE_BITMAPFLAG_WHITEISTRNS 0x1
#define DE_BITMAPFLAG_MERGE       0x2

void de_bitmap_rect(de_bitmap *img,
	i64 xpos, i64 ypos, i64 width, i64 height,
	u32 clr, unsigned int flags);
void de_bitmap_copy_rect(de_bitmap *srcimg, de_bitmap *dstimg,
	i64 srcxpos, i64 srcypos, i64 width, i64 height,
	i64 dstxpos, i64 dstypos, unsigned int flags);

void de_bitmap_apply_mask(de_bitmap *fg, de_bitmap *mask,
	unsigned int flags);

void de_optimize_image_alpha(de_bitmap *img, unsigned int flags);

void de_make_grayscale_palette(u32 *pal, i64 num_entries, unsigned int flags);

///////////////////////////////////////////

char de_get_hexchar(int n);
u8 de_decode_hex_digit(u8 x, int *errorflag);

u32 de_palette_vga256(int index);
u32 de_palette_ega64(int index);
u32 de_palette_pc16(int index);
u32 de_palette_pcpaint_cga4(int palnum, int index);

const u8 *de_get_8x8ascii_font_ptr(void);
const u8 *de_get_vga_cp437_font_ptr(void);

void de_color_to_css(u32 color, char *buf, int buflen);

u8 de_sample_nbit_to_8bit(i64 n, unsigned int x);
u8 de_scale_63_to_255(u8 x);
u8 de_scale_1000_to_255(i64 x);
u8 de_scale_n_to_255(i64 n, i64 x);
u32 de_rgb565_to_888(u32 x);
u32 de_bgr555_to_888(u32 x);
u32 de_rgb555_to_888(u32 x);

i32 de_char_to_unicode(deark *c, i32 a, de_ext_encoding ee);
void de_uchar_to_utf8(i32 u1, u8 *utf8buf, i64 *p_utf8len);
void dbuf_write_uchar_as_utf8(dbuf *outf, i32 u);
int de_utf8_to_uchar(const u8 *utf8buf, i64 buflen,
	i32 *p_uchar, i64 *p_utf8len);
int de_utf16x_to_uchar(const u8 *utf16buf, i64 buflen,
	i32 *p_uchar, i64 *p_utf16len, int is_le);

int de_is_ascii(const u8 *buf, i64 buflen);

#define DE_CONVFLAG_STOP_AT_NUL 0x1
#define DE_CONVFLAG_MAKE_PRINTABLE 0x2
#define DE_CONVFLAG_WANT_UTF8 0x10
#define DE_CONVFLAG_ALLOW_HL  0x20

char de_byte_to_printable_char(u8 b);

// Convert encoded bytes to a NUL-terminated string that can be
// printed to the terminal.
// Consider using {dbuf_read_to_ucstring or dbuf_read_string or
// ucstring_append_bytes} followed by
// {ucstring_get_printable_sz or ucstring_to_printable_sz} instead.
void de_bytes_to_printable_sz(const u8 *src, i64 src_len,
	char *dst, i64 dst_len, unsigned int conv_flags, de_ext_encoding src_ee);

de_finfo *de_finfo_create(deark *c);
void de_finfo_destroy(deark *c, de_finfo *fi);

#define DE_SNFLAG_FULLPATH 0x01
#define DE_SNFLAG_STRIPTRAILINGSLASH 0x2
void de_finfo_set_name_from_ucstring(deark *c, de_finfo *fi, de_ucstring *s, unsigned int flags);
void de_finfo_set_name_from_sz(deark *c, de_finfo *fi, const char *name1, unsigned int flags,
	de_ext_encoding ee);

de_ucstring *ucstring_create(deark *c);
de_ucstring *ucstring_clone(const de_ucstring *src);
void ucstring_destroy(de_ucstring *s);
void ucstring_empty(de_ucstring *s);
void ucstring_truncate(de_ucstring *s, i64 newlen);
void ucstring_truncate_at_NUL(de_ucstring *s);
void ucstring_strip_trailing_NUL(de_ucstring *s);
void ucstring_strip_trailing_spaces(de_ucstring *s);
void ucstring_append_char(de_ucstring *s, i32 ch);
void ucstring_append_ucstring(de_ucstring *s1, const de_ucstring *s2);
void ucstring_vprintf(de_ucstring *s, de_ext_encoding ee, const char *fmt, va_list ap);
void ucstring_printf(de_ucstring *s, de_ext_encoding ee, const char *fmt, ...)
  de_gnuc_attribute ((format (printf, 3, 4)));
int ucstring_isempty(const de_ucstring *s);
int ucstring_isnonempty(const de_ucstring *s);

// Convert and append an encoded array of bytes to the string.
void ucstring_append_bytes(de_ucstring *s, const u8 *buf, i64 buflen,
	unsigned int conv_flags, de_ext_encoding ee);

void ucstring_append_sz(de_ucstring *s, const char *sz, de_ext_encoding ee);

void ucstring_write_as_utf8(deark *c, de_ucstring *s, dbuf *outf, int add_bom_if_needed);
int de_is_printable_uchar(i32 ch);
i64 ucstring_count_utf8_bytes(de_ucstring *s);

// Supported encodings are DE_ENCODING_UTF8, DE_ENCODING_ASCII, DE_ENCODING_LATIN1.
// flags: DE_CONVFLAG_*
void ucstring_to_sz(de_ucstring *s, char *szbuf, size_t szbuf_len, unsigned int flags,
	de_ext_encoding ee);

// "get printable string"
// Returns a pointer to a NUL-terminated string, that is valid until the
// next ucstring_* function is called on that string.
const char *ucstring_getpsz(de_ucstring *s);
// The _n version limits the number of bytes in the result.
// max_bytes does not count the terminating NUL.
const char *ucstring_getpsz_n(de_ucstring *s, i64 max_bytes);

#define DE_DBG_MAX_STRLEN 500
// Same as ..._n, with max_bytes=DE_DBG_MAX_STRLEN
const char *ucstring_getpsz_d(de_ucstring *s);

// Helper functions for printing the contents of bit-flags fields
void ucstring_append_flags_item(de_ucstring *s, const char *str);
void ucstring_append_flags_itemf(de_ucstring *s, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 2, 3)));

struct de_strarray;
struct de_strarray *de_strarray_create(deark *c, size_t max_elems);
void de_strarray_destroy(struct de_strarray *sa);
int de_strarray_push(struct de_strarray *sa, de_ucstring *s);
int de_strarray_pop(struct de_strarray *sa);
#define DE_MPFLAG_NOTRAILINGSLASH 0x1
void de_strarray_make_path(struct de_strarray *sa, de_ucstring *path, unsigned int flags);

void de_write_codepoint_to_html(deark *c, dbuf *f, i32 ch);

de_encoding de_encoding_name_to_code(const char *encname);
de_encoding de_windows_codepage_to_encoding(deark *c, int wincodepage,
	char *encname, size_t encname_len, unsigned int flags);

void de_copy_bits(const u8 *src, i64 srcbitnum,
	u8 *dst, i64 dstbitnum, i64 bitstocopy);

void de_decode_base16(deark *c, dbuf *inf, i64 pos1, i64 len,
	dbuf *outf, unsigned int flags);

struct de_inthashtable;
struct de_inthashtable *de_inthashtable_create(deark *c);
void de_inthashtable_destroy(deark *c, struct de_inthashtable *ht);
int de_inthashtable_add_item(deark *c, struct de_inthashtable *ht, i64 key, void *value);
int de_inthashtable_get_item(deark *c, struct de_inthashtable *ht, i64 key, void **pvalue);
int de_inthashtable_item_exists(deark *c, struct de_inthashtable *ht, i64 key);
int de_inthashtable_remove_item(deark *c, struct de_inthashtable *ht, i64 key, void **pvalue);
int de_inthashtable_remove_any_item(deark *c, struct de_inthashtable *ht, i64 *pkey, void **pvalue);

#define DE_CRCOBJ_CRC32_IEEE   0x10
#define DE_CRCOBJ_CRC16_CCITT  0x20
#define DE_CRCOBJ_CRC16_ARC    0x21

struct de_crcobj;

struct de_crcobj *de_crcobj_create(deark *c, unsigned int flags);
void de_crcobj_destroy(struct de_crcobj *crco);
void de_crcobj_reset(struct de_crcobj *crco);
u32 de_crcobj_getval(struct de_crcobj *crco);
void de_crcobj_addbuf(struct de_crcobj *crco, const u8 *buf, i64 buf_len);
void de_crcobj_addbyte(struct de_crcobj *crco, u8 b);
void de_crcobj_addslice(struct de_crcobj *crco, dbuf *f, i64 pos, i64 len);

///////////////////////////////////////////

struct de_bitmap_font_char {
	i32 codepoint_nonunicode;

	// If font->has_unicode_codepoints is set, then ->codepoint_unicode
	// must be set to a Unicode codepoint, or to DE_INVALID_CODEPOINT.
	i32 codepoint_unicode;

	int width, height;
	int v_offset; // Used if the glyphs do not all have the same height
	i16 extraspace_l, extraspace_r;
	i64 rowspan;
	u8 *bitmap;
};

struct de_bitmap_font {
	int nominal_width, nominal_height;
	i64 index_of_replacement_char; // -1 if none

	// Flag: Are the char_array[]->codepoint_nonunicode codes set?
	// (This should be ignored if has_unicode_codepoints is not set.)
	u8 has_nonunicode_codepoints;

	// Flag: Are the char_array[]->codepoint_unicode codes set?
	u8 has_unicode_codepoints;

	// If the font has both unicode and non-unicode codpoints, this flag tells which
	// to prefer when displaying the font.
	u8 prefer_unicode;

	i64 num_chars;
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
	struct de_bitmap_font *font, i64 char_idx,
	i64 xpos, i64 ypos, u32 fgcol, u32 bgcol, unsigned int flags);
void de_font_paint_character_cp(deark *c, de_bitmap *img,
	struct de_bitmap_font *font, i32 codepoint,
	i64 xpos, i64 ypos, u32 fgcol, u32 bgcol, unsigned int flags);

void de_font_bitmap_font_to_image(deark *c, struct de_bitmap_font *font, de_finfo *fi, unsigned int createflags);
int de_font_is_standard_vga_font(deark *c, u32 crc);

///////////////////////////////////////////

// Note that this struct is assumed to be copyable with a simple struct copy.
// It should not contain pointers.
struct de_char_cell {
	i32 codepoint;
	i32 codepoint_unicode;
	// The color fields are interpreted as follows:
	//  A color value <=0x0000000f is a palette index.
	//  A color value >=0xff000000 is an RGB color, e.g. from DE_MAKE_RGB().
#define DE_IS_PAL_COLOR(x) ((u32)(x)<=0xfU)
	u32 fgcol;
	u32 bgcol;
	u8 underline;
	u8 strikethru;
	u8 blink;
	u8 size_flags;
};

struct de_char_screen {
	i64 width;
	i64 height;
	struct de_char_cell **cell_rows; // Array of [height] row pointers
};

struct de_char_context {
	u8 prefer_image_output;
	u8 prefer_9col_mode;
	u8 no_density;
	u8 suppress_custom_font_warning;
	u8 outfmt_known;
	int outfmt;
	i64 nscreens;
	struct de_char_screen **screens; // Array of [nscreens] screens
	u32 pal[16];
	struct de_bitmap_font *font; // Optional
	de_ucstring *title;
	de_ucstring *artist;
	de_ucstring *organization;
	struct de_timestamp creation_date;
	de_ucstring *comment; // NULL if there is no comment
};

void de_char_output_to_file(deark *c, struct de_char_context *charctx);
struct de_char_context *de_create_charctx(deark *c, unsigned int flags);
void de_char_decide_output_format(deark *c, struct de_char_context *charctx);
void de_destroy_charctx(deark *c, struct de_char_context *charctx);
void de_free_charctx_screens(deark *c, struct de_char_context *charctx);
void de_free_charctx(deark *c, struct de_char_context *charctx);

///////////////////////////////////////////

// Our version of "struct tm".
// Differences: Year is full year, removed some fields, added milliseconds field.
struct de_struct_tm {
	int is_valid;
	int tm_fullyear, tm_mon, tm_mday;
	int tm_hour, tm_min, tm_sec;
	int tm_subsec; // in ten-millionths of a second
};

void de_unix_time_to_timestamp(i64 ut, struct de_timestamp *ts, unsigned int flags);
void de_mac_time_to_timestamp(i64 mt, struct de_timestamp *ts);
void de_FILETIME_to_timestamp(i64 ft, struct de_timestamp *ts, unsigned int flags);
void de_dos_datetime_to_timestamp(struct de_timestamp *ts,
   i64 ddate, i64 dtime);
void de_describe_dos_attribs(deark *c, UI attr, de_ucstring *s, UI flags);
void de_riscos_loadexec_to_timestamp(u32 load_addr,
	u32 exec_addr, struct de_timestamp *ts);
void de_timestamp_set_subsec(struct de_timestamp *ts, double frac);
i64 de_timestamp_get_subsec(const struct de_timestamp *ts);
i64 de_timestamp_to_unix_time(const struct de_timestamp *ts);
i64 de_timestamp_to_FILETIME(const struct de_timestamp *ts);
void de_make_timestamp(struct de_timestamp *ts,
	i64 yr, i64 mo, i64 da,
	i64 hr, i64 mi, i64 se);
void de_timestamp_cvt_to_utc(struct de_timestamp *ts, i64 offset_seconds);
char *de_timestamp_to_string(const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags);
char *de_dbg_timestamp_to_string(deark *c, const struct de_timestamp *ts,
	char *buf, size_t buf_len, unsigned int flags);
void de_gmtime(const struct de_timestamp *ts, struct de_struct_tm *tm2);
void de_current_time_to_timestamp(struct de_timestamp *ts);
void de_cached_current_time_to_timestamp(deark *c, struct de_timestamp *ts);
