// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// * Photoshop PSD and PSB format
//  * PSD "image resources"
//  * PSD "series of tagged blocks"
// * Photoshop Action file format (.atn)
// * Photoshop Gradient file format (.grd)
// * Photoshop Styles (.asl)
// * Photoshop Brush (.abr)
// * Photoshop Custom Shape (.csh)
// * Photoshop Pattern file (.pat)

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_psd);
DE_DECLARE_MODULE(de_module_ps_action);
DE_DECLARE_MODULE(de_module_ps_gradient);
DE_DECLARE_MODULE(de_module_ps_styles);
DE_DECLARE_MODULE(de_module_ps_brush);
DE_DECLARE_MODULE(de_module_ps_csh);
DE_DECLARE_MODULE(de_module_ps_pattern);

#define CODE_8B64 0x38423634U
#define CODE_8BIM 0x3842494dU
#define CODE_AgHg 0x41674867U
#define CODE_Alph 0x416c7068U
#define CODE_AnDs 0x416e4473U
#define CODE_CgEd 0x43674564U
#define CODE_Clss 0x436c7373U
#define CODE_DCSR 0x44435352U
#define CODE_Enmr 0x456e6d72U
#define CODE_FEid 0x46456964U
#define CODE_FMsk 0x464d736bU
#define CODE_FXid 0x46586964U
#define CODE_GdFl 0x4764466cU
#define CODE_GlbC 0x476c6243U
#define CODE_GlbO 0x476c624fU
#define CODE_IRFR 0x49524652U
#define CODE_LMsk 0x4c4d736bU
#define CODE_Layr 0x4c617972U
#define CODE_Lr16 0x4c723136U
#define CODE_Lr32 0x4c723332U
#define CODE_MeSa 0x4d655361U
#define CODE_Mt16 0x4d743136U
#define CODE_Mt32 0x4d743332U
#define CODE_Mtrn 0x4d74726eU
#define CODE_ObAr 0x4f624172U
#define CODE_Objc 0x4f626a63U
#define CODE_PHUT 0x50485554U
#define CODE_Pat2 0x50617432U
#define CODE_Pat3 0x50617433U
#define CODE_Patt 0x50617474U
#define CODE_PtFl 0x5074466cU
#define CODE_PxSD 0x50785344U
#define CODE_PxSc 0x50785363U
#define CODE_SoCo 0x536f436fU
#define CODE_SoLd 0x536f4c64U
#define CODE_TEXT 0x54455854U
#define CODE_Txt2 0x54787432U
#define CODE_TySh 0x54795368U
#define CODE_UnFl 0x556e466cU
#define CODE_UntF 0x556e7446U
#define CODE_VlLs 0x566c4c73U
#define CODE_abdd 0x61626464U
#define CODE_alis 0x616c6973U
#define CODE_anFX 0x616e4658U
#define CODE_artb 0x61727462U
#define CODE_artd 0x61727464U
#define CODE_blwh 0x626c7768U
#define CODE_bool 0x626f6f6cU
#define CODE_clbl 0x636c626cU
#define CODE_comp 0x636f6d70U
#define CODE_cust 0x63757374U
#define CODE_desc 0x64657363U
#define CODE_doub 0x646f7562U
#define CODE_enum 0x656e756dU
#define CODE_fxrp 0x66787270U
#define CODE_indx 0x696e6478U
#define CODE_infx 0x696e6678U
#define CODE_knko 0x6b6e6b6fU
#define CODE_lfx2 0x6c667832U
#define CODE_liFD 0x6c694644U
#define CODE_lnk2 0x6c6e6b32U
#define CODE_lnk3 0x6c6e6b33U
#define CODE_lnkD 0x6c6e6b44U
#define CODE_lnsr 0x6c6e7372U
#define CODE_long 0x6c6f6e67U
#define CODE_lrFX 0x6c724658U
#define CODE_lsct 0x6c736374U
#define CODE_lspf 0x6c737066U
#define CODE_luni 0x6c756e69U
#define CODE_lyid 0x6c796964U
#define CODE_mani 0x6d616e69U
#define CODE_mlst 0x6d6c7374U
#define CODE_mopt 0x6d6f7074U
#define CODE_mset 0x6d736574U
#define CODE_name 0x6e616d65U
#define CODE_obj  0x6f626a20U
#define CODE_patt 0x70617474U
#define CODE_prop 0x70726f70U
#define CODE_pths 0x70746873U
#define CODE_rele 0x72656c65U
#define CODE_samp 0x73616d70U
#define CODE_shmd 0x73686d64U
#define CODE_tdta 0x74647461U
#define CODE_tySh 0x74795368U
#define CODE_type 0x74797065U
#define CODE_vibA 0x76696241U
#define CODE_vmsk 0x766d736bU
#define CODE_vogk 0x766f676bU
#define CODE_vscg 0x76736367U
#define CODE_vsms 0x76736d73U
#define CODE_vstk 0x7673746bU

#define PSD_CM_BITMAP   0
#define PSD_CM_GRAY     1
#define PSD_CM_PALETTE  2
#define PSD_CM_RGB      3

// (I can't think of a good name for this struct, and the corresponding variables.
// It's used so much that the name needs to be short, distinct, and easy to type.)
// PSD format involves so many nested data elements with implicit lengths that
// it's worth developing a way to handle this with a maximum of convenience.
// This struct helps to do that.
// A function that processes an element has an instance of it (named zz) that it
// got from its parent (caller). It often creates new zz structs to pass to its
// children.
// The struct is used for both input and output.
// A function updates the 'pos' field as it consumes the data, but 'startpos' and
// 'endpos' never change.
//
// Some functions assume that the zz passed to them was created just for them, and
// thus .pos should be equal to .startpos, and .endpos should be exactly the size of
// that data element, if known. The code is more robust if a function can't directly
// modify its parent's zz, and this lets the child use the .startpos field.
// However, for convenience, some functions are designed such that they can use
// their parent's zz.
//
// Note that the struct has no way to indicate an error. It is expected that the
// functions' return values will be used, when error handling is necessary.
typedef struct zz_struct {
	// Represents a segment of the input file, and a position within that segment.
	// All fields are byte offsets from the beginning of c->infile.
	i64 pos; // The "current position". Also used to calculate the number of bytes consumed.
	i64 startpos; // Offset of the first byte in the segment.
	i64 endpos; // Offset of first byte *after* the segment.
} zztype;

// The PSD spec calls this data structure a
// "4 bytes (length), followed either by string or (if length is zero) 4-byte ID",
// but that's too unwieldy for me, so I'll call it a "flexible_id".
struct flexible_id {
	int is_fourcc;
	struct de_fourcc fourcc;
	char *sz; // Present if !is_fourcc. Raw bytes (+NUL), used for matching.
	de_ucstring *s; // Present if !is_fourcc. Text form of sz.
	i64 bytes_consumed;
};

struct image_info {
	i64 width, height;
	i64 color_mode;
	i64 num_channels;
	i64 bits_per_channel;
	struct de_density_info density;

	i64 pal_entries;
	u32 pal[256];
};

typedef struct localctx_struct {
	int version; // 1=PSD, 2=PSB
	int is_le;
	int input_encoding;
	int tagged_blocks_only;
#define MAX_NESTING_LEVEL 50
	int nesting_level;
	u8 jpeg_rbswap_mode;
	i64 intsize_2or4;
	i64 intsize_4or8;

	int abr_major_ver, abr_minor_ver;
	u8 has_iptc;
	struct de_density_info density;

	struct image_info *main_iinfo;
} lctx;

struct rsrc_info;

typedef void (*rsrc_handler_fn)(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri);

struct rsrc_info {
	u16 id;

	// 0x0004 = Item consists of a version number, followed by a "Descriptor structure".
	// 0x0010 = Do not include ASCII in hexdumps.
	u32 flags;

	const char *idname;
	rsrc_handler_fn hfn;
};

#define DECLARE_HRSRC(x) static void x(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)

DECLARE_HRSRC(hrsrc_resolutioninfo);
DECLARE_HRSRC(hrsrc_namesofalphachannels);
DECLARE_HRSRC(hrsrc_printflags);
DECLARE_HRSRC(hrsrc_iptc);
DECLARE_HRSRC(hrsrc_exif);
DECLARE_HRSRC(hrsrc_xmp);
DECLARE_HRSRC(hrsrc_iccprofile);
DECLARE_HRSRC(hrsrc_slices);
DECLARE_HRSRC(hrsrc_thumbnail);
DECLARE_HRSRC(hrsrc_byte);
DECLARE_HRSRC(hrsrc_uint16);
DECLARE_HRSRC(hrsrc_uint32);
DECLARE_HRSRC(hrsrc_unicodestring);
DECLARE_HRSRC(hrsrc_unicodestring_multi);
DECLARE_HRSRC(hrsrc_pascalstring);
DECLARE_HRSRC(hrsrc_plaintext);
DECLARE_HRSRC(hrsrc_urllist);
DECLARE_HRSRC(hrsrc_versioninfo);
DECLARE_HRSRC(hrsrc_printscale);
DECLARE_HRSRC(hrsrc_pixelaspectratio);
DECLARE_HRSRC(hrsrc_layerselectionids);
DECLARE_HRSRC(hrsrc_pathinfo);
DECLARE_HRSRC(hrsrc_printflagsinfo);
DECLARE_HRSRC(hrsrc_pluginresource);

static const struct rsrc_info rsrc_info_arr[] = {
	{ 0x03e8, 0, "channels/rows/columns/depth/mode", NULL },
	{ 0x03e9, 0, "Macintosh print manager print info", NULL },
	{ 0x03ea, 0, "Macintosh page format information", NULL },
	{ 0x03eb, 0, "Indexed color table", NULL },
	{ 0x03ed, 0, "Resolution info", hrsrc_resolutioninfo },
	{ 0x03ee, 0, "Names of the alpha channels", hrsrc_namesofalphachannels },
	{ 0x03ef, 0, "Display information", NULL },
	{ 0x03f0, 0, "Caption", NULL },
	{ 0x03f1, 0, "Border information", NULL },
	{ 0x03f2, 0, "Background color", NULL },
	{ 0x03f3, 0, "Print flags", hrsrc_printflags },
	{ 0x03f4, 0, "Grayscale and multichannel halftoning information", NULL },
	{ 0x03f5, 0, "Color halftoning info", NULL },
	{ 0x03f6, 0, "Duotone halftoning information", NULL },
	{ 0x03f7, 0, "Grayscale and multichannel transfer function", NULL },
	{ 0x03f8, 0x0010, "Color transfer functions", NULL },
	{ 0x03f9, 0, "Duotone transfer functions", NULL },
	{ 0x03fa, 0, "Duotone image information", NULL },
	{ 0x03fb, 0, "Effective black and white values", NULL },
	//{ 0x03fc, 0, "(Obsolete)", NULL },
	{ 0x03fd, 0, "EPS options", NULL },
	{ 0x03fe, 0, "Quick Mask information", NULL },
	//{ 0x03ff, 0, "(Obsolete)", NULL },
	{ 0x0400, 0, "Layer state information", hrsrc_uint16 },
	{ 0x0401, 0, "Working path", hrsrc_pathinfo },
	{ 0x0402, 0x0010, "Layers group information", NULL },
	//{ 0x0403, 0, "(Obsolete)", NULL },
	{ 0x0404, 0, "IPTC-NAA", hrsrc_iptc },
	{ 0x0405, 0, "Image mode for raw format files", NULL },
	{ 0x0406, 0x0010, "JPEG quality", NULL },
	{ 0x0408, 0x0010, "Grid and guides info", NULL },
	{ 0x0409, 0, "Thumbnail - Photoshop 4.0", hrsrc_thumbnail },
	{ 0x040a, 0, "Copyright flag", hrsrc_byte },
	{ 0x040b, 0, "URL", hrsrc_plaintext },
	{ 0x040c, 0, "Thumbnail", hrsrc_thumbnail },
	{ 0x040d, 0, "Global Angle", hrsrc_uint32 },
	{ 0x040e, 0, "Color samplers resource (Photoshop 5.0)", NULL },
	{ 0x040f, 0, "ICC Profile", hrsrc_iccprofile },
	{ 0x0410, 0, "Watermark", hrsrc_byte },
	{ 0x0411, 0, "ICC Untagged Profile", hrsrc_byte },
	{ 0x0412, 0, "Effects visible", hrsrc_byte },
	{ 0x0413, 0, "Spot Halftone", NULL },
	{ 0x0414, 0, "Document-specific IDs seed number", hrsrc_uint32 },
	{ 0x0415, 0, "Unicode Alpha Names", hrsrc_unicodestring_multi },
	{ 0x0416, 0, "Indexed Color Table Count", NULL },
	{ 0x0417, 0, "Transparency Index", NULL },
	{ 0x0419, 0, "Global Altitude", hrsrc_uint32 },
	{ 0x041a, 0, "Slices", hrsrc_slices },
	{ 0x041b, 0, "Workflow URL", hrsrc_unicodestring },
	{ 0x041c, 0, "Jump To XPEP", NULL },
	{ 0x041d, 0, "Alpha Identifiers", NULL },
	{ 0x041e, 0, "URL List", hrsrc_urllist },
	{ 0x0421, 0, "Version Info", hrsrc_versioninfo },
	{ 0x0422, 0, "EXIF data 1", hrsrc_exif },
	{ 0x0423, 0, "EXIF data 3", NULL },
	{ 0x0424, 0, "XMP metadata", hrsrc_xmp },
	{ 0x0425, 0x0010, "Caption digest", NULL },
	{ 0x0426, 0, "Print scale", hrsrc_printscale },
	{ 0x0428, 0, "Pixel Aspect Ratio", hrsrc_pixelaspectratio },
	{ 0x0429, 0x0004, "Layer Comps", NULL },
	{ 0x042a, 0, "Alternate Duotone Colors", NULL },
	{ 0x042b, 0, "Alternate Spot Colors", NULL },
	{ 0x042d, 0, "Layer Selection ID(s)", hrsrc_layerselectionids },
	{ 0x042e, 0, "HDR Toning information", NULL },
	{ 0x042f, 0, "Auto Save Format", NULL },
	{ 0x0430, 0x0010, "Layer Group(s) Enabled ID", NULL },
	{ 0x0431, 0, "Color samplers resource (Photoshop CS3)", NULL },
	{ 0x0432, 0x0004, "Measurement Scale", NULL },
	{ 0x0433, 0x0004, "Timeline Information", NULL },
	{ 0x0434, 0x0004, "Sheet Disclosure", NULL },
	{ 0x0435, 0, "DisplayInfo", NULL },
	{ 0x0436, 0x0004, "Onion Skins", NULL },
	{ 0x0438, 0x0004, "Count Information", NULL },
	{ 0x043a, 0x0004, "Print Information", NULL },
	{ 0x043b, 0x0004, "Print Style", NULL },
	{ 0x043c, 0, "Macintosh NSPrintInfo", NULL },
	{ 0x043d, 0, "Windows DEVMODE", NULL },
	{ 0x043e, 0, "Auto Save File Path", hrsrc_unicodestring },
	{ 0x043f, 0, "Auto Save Format", hrsrc_unicodestring },
	{ 0x0440, 0x0004, "Path Selection State", NULL },
	// 0x07d0 to 0x0bb6: See lookup_rsrc() below
	{ 0x0bb7, 0, "Name of clipping path", hrsrc_pascalstring },
	{ 0x0bb8, 0x0004, "Origin Path Info", NULL },
	// 0x0fa0 to 0x1387: See lookup_rsrc() below
	{ 0x1b58, 0, "Image Ready variables", NULL },
	{ 0x1b59, 0, "Image Ready data sets", NULL },
	{ 0x1b5a, 0x0004, "Image Ready default selected state", NULL },
	{ 0x1b5b, 0, "Image Ready 7 rollover expanded state", NULL },
	{ 0x1b5c, 0, "Image Ready rollover expanded state", NULL },
	{ 0x1b5d, 0x0004, "Image Ready save layer settings", NULL },
	{ 0x1b5e, 0, "Image Ready version", NULL },
	{ 0x1f40, 0, "Lightroom workflow", NULL },
	{ 0x2710, 0, "Print flags info", hrsrc_printflagsinfo }
};

// Forward declarations
static int read_descriptor(deark *c, lctx *d, zztype *zz, int has_version, const char *dscrname);
static void do_tagged_blocks(deark *c, lctx *d, zztype *zz, int tbnamespace);
static int do_descriptor_item_ostype_and_data(deark *c, lctx *d,
	const struct flexible_id *key_flid, zztype *zz, i64 itempos);

#define psd_getu16(p) dbuf_getu16x(c->infile,p,d->is_le)
#define psd_geti16(p) dbuf_geti16x(c->infile,p,d->is_le)
#define psd_getu32(p) dbuf_getu32x(c->infile,p,d->is_le)
#define psd_geti32(p) dbuf_geti32x(c->infile,p,d->is_le)
#define psd_geti64(p) dbuf_geti64x(c->infile,p,d->is_le)

// Initialize a zz, from known start and end positions.
static void zz_init_absolute(zztype *zz, i64 startpos, i64 endpos)
{
	zz->startpos = startpos;
	zz->pos = startpos;
	zz->endpos = endpos;
}

// Initialize zz such that its startpos is parentzz's *current* pos,
// and its endpos is the same as parentzz's.
static void zz_init(zztype *zz, const zztype *parentzz)
{
	zz_init_absolute(zz, parentzz->pos, parentzz->endpos);
}

// Initialize zz such that its startpos is parentzz's *current* pos.
static void zz_init_with_len(zztype *zz, const zztype *parentzz, i64 len)
{
	i64 startpos, endpos;

	if(len<0) len=0;
	startpos = parentzz->pos;
	endpos = startpos + len;
	if(endpos > parentzz->endpos) endpos = parentzz->endpos;

	zz_init_absolute(zz, startpos, endpos);
}

// Number of bytes consumed so far.
// I.e. number of bytes from startpos to the current position.
static i64 zz_used(zztype *zz)
{
	if(zz->endpos <= zz->startpos) return 0;
	if(zz->pos <= zz->endpos) return zz->pos - zz->startpos;
	return zz->endpos - zz->startpos;
}

// Number of bytes remaining / still available.
// I.e. number of bytes from the current position to endpos.
static i64 zz_avail(zztype *zz)
{
	if(zz->pos >= zz->endpos) return 0;
	if(zz->pos >= zz->startpos) return zz->endpos - zz->pos;
	return zz->endpos - zz->startpos;
}

// Functions that modify a shared "current file position" variable are
// discouraged in Deark, but PSD format practically forces us to use them
// in many cases.
// May as well go all the way, and even do it for simple get_int functions.

static u8 psd_dbuf_getbyte_zz(dbuf *f, zztype *zz)
{
	u8 val = dbuf_getbyte(f, zz->pos);
	zz->pos++;
	return val;
}

static i64 psd_dbuf_getu16_zz(dbuf *f, zztype *zz, int is_le)
{
	i64 val = dbuf_getu16x(f, zz->pos, is_le);
	zz->pos += 2;
	return val;
}

static i64 psd_dbuf_geti16_zz(dbuf *f, zztype *zz, int is_le)
{
	i64 val = dbuf_geti16x(f, zz->pos, is_le);
	zz->pos += 2;
	return val;
}

static i64 psd_dbuf_getu32_zz(dbuf *f, zztype *zz, int is_le)
{
	i64 val = dbuf_getu32x(f, zz->pos, is_le);
	zz->pos += 4;
	return val;
}

static i64 psd_dbuf_geti32_zz(dbuf *f, zztype *zz, int is_le)
{
	i64 val = dbuf_geti32x(f, zz->pos, is_le);
	zz->pos += 4;
	return val;
}

static i64 psd_dbuf_geti64_zz(dbuf *f, zztype *zz, int is_le)
{
	i64 val = dbuf_geti64x(f, zz->pos, is_le);
	zz->pos += 8;
	return val;
}

#define psd_getbytezz(z) psd_dbuf_getbyte_zz(c->infile,z)
#define psd_getu16zz(z) psd_dbuf_getu16_zz(c->infile,z,d->is_le)
#define psd_geti16zz(z) psd_dbuf_geti16_zz(c->infile,z,d->is_le)
#define psd_getu32zz(z) psd_dbuf_getu32_zz(c->infile,z,d->is_le)
#define psd_geti32zz(z) psd_dbuf_geti32_zz(c->infile,z,d->is_le)
#define psd_geti64zz(z) psd_dbuf_geti64_zz(c->infile,z,d->is_le)

// Read a 32-bit (if d->intsize_4or8==4) or 64-bit int from c->infile.
// This function is used to help support PSB format.
static i64 psd_getu32or64zz(deark *c, lctx *d, zztype *zz)
{
	if(d->intsize_4or8>4)
		return psd_geti64zz(zz);
	return psd_getu32zz(zz);
}

static const char *get_colormode_name(i64 n)
{
	const char *name = "?";
	switch(n) {
	case PSD_CM_BITMAP: name="bitmap"; break;
	case PSD_CM_GRAY: name="grayscale"; break;
	case PSD_CM_PALETTE: name="indexed"; break;
	case PSD_CM_RGB: name="RGB"; break;
	case 4: name="CMYK"; break;
	case 7: name="multichannel"; break;
	case 8: name="duotone"; break;
	case 9: name="Lab"; break;
	}
	return name;
}

static void dbg_print_compression_method(deark *c, lctx *d, i64 cmpr)
{
	const char *name = "?";

	switch(cmpr) {
	case 0: name="uncompressed"; break;
		// (At one point the PSD spec says that "1 is zip", but I think that's a
		// clerical error. My best guess is that all the compression fields use
		// the same compression codes.)
	case 1: name="PackBits"; break;
	case 2: name="ZIP without prediction"; break;
	case 3: name="ZIP with prediction"; break;
	}
	de_dbg(c, "compression method: %d (%s)", (int)cmpr, name);
}

// The PSD module's version of dbuf_read_fourcc()
static void psd_read_fourcc_zz(deark *c, lctx *d, zztype *zz, struct de_fourcc *fourcc)
{
	dbuf_read_fourcc(c->infile, zz->pos, fourcc, 4, d->is_le ? DE_4CCFLAG_REVERSED : 0);
	zz->pos += 4;
}

// For rectangles in top-left-bottom-right order
static void read_rectangle_tlbr(deark *c, lctx *d, zztype *zz, const char *name)
{
	i64 n[4];
	i64 k;
	for(k=0; k<4; k++) {
		n[k] = psd_geti32zz(zz);
	}
	de_dbg(c, "%s: (%d,%d)-(%d,%d)", name, (int)n[1], (int)n[0], (int)n[3], (int)n[2]);
}

// For rectangles in left-top-right-bottom order
static void read_rectangle_ltrb(deark *c, lctx *d, zztype *zz, const char *name)
{
	i64 n[4];
	i64 k;
	for(k=0; k<4; k++) {
		n[k] = psd_geti32zz(zz);
	}
	de_dbg(c, "%s: (%d,%d)-(%d,%d)", name, (int)n[0], (int)n[1], (int)n[2], (int)n[3]);
}

// (Okay to use a shared zz.)
static void read_pascal_string_to_ucstring(deark *c, lctx *d, de_ucstring *s, zztype *zz)
{
	i64 dlen;

	if(zz_avail(zz)<1) return;

	// First byte is the string length
	dlen = (i64)psd_getbytezz(zz);

	if(zz->pos + dlen > zz->endpos) { // error
		zz->pos = zz->endpos;
		return;
	}

	dbuf_read_to_ucstring(c->infile, zz->pos, dlen, s, 0, d->input_encoding);
	zz->pos += dlen;
}

// Like a Pascal string, but with a 4-byte prefix
// (Okay to use a shared zz.)
static void read_prefixed_string_to_ucstring(deark *c, lctx *d, de_ucstring *s, zztype *zz)
{
	i64 dlen;

	if(zz_avail(zz)<4) {
		zz->pos = zz->endpos;
		return;
	}

	dlen = psd_getu32zz(zz);

	if(zz->pos + dlen > zz->endpos) { // error
		zz->pos = zz->endpos;
		return;
	}

	dbuf_read_to_ucstring(c->infile, zz->pos, dlen, s, 0, d->input_encoding);
	zz->pos += dlen;
}

// Caller supplies ri_dst. This function will set its fields.
static int lookup_rsrc(u32 sig_id, u16 n, struct rsrc_info *ri_dst)
{
	i64 i;
	int found = 0;

	de_zeromem(ri_dst, sizeof(struct rsrc_info));

	if(sig_id==CODE_PHUT) { // PhotoDeluxe resources seem to use incompatible formats.
		ri_dst->id = n;
		ri_dst->idname = "?";
		return 0;
	}

	for(i=0; i<(i64)DE_ARRAYCOUNT(rsrc_info_arr); i++) {
		if(rsrc_info_arr[i].id == n) {
			*ri_dst = rsrc_info_arr[i]; // struct copy
			if(!ri_dst->idname) ri_dst->idname = "?";
			return 1;
		}
	}

	ri_dst->id = n;
	ri_dst->idname = "?";

	// Handle pattern-based resources that don't fit nicely in our table.

	if(n>=0x07d0 && n<=0x0bb6) {
		found = 1;
		ri_dst->idname = "Path Information";
		ri_dst->hfn = hrsrc_pathinfo;
	}
	else if(n>=0x0fa0 && n<=0x1387) {
		found = 1;
		ri_dst->idname = "Plug-In resource";
		ri_dst->hfn = hrsrc_pluginresource;
	}

	return found;
}

static const char* units_name(i64 u)
{
	switch(u) {
	case 1: return "pixels/inch";
	case 2: return "pixels/cm";
	}
	return "?";
}

static void hrsrc_resolutioninfo(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 xres_int, yres_int;
	double xres, yres;
	i64 xres_unit, yres_unit;

	if(zz_avail(zz)!=16) return;
	xres_int = psd_getu32(zz->pos);
	xres = ((double)xres_int)/65536.0;
	de_dbg(c, "xres=%.2f dpi", xres);
	xres_unit = psd_getu16(zz->pos+4);
	de_dbg(c, "xres display unit: %d (%s)", (int)xres_unit, units_name(xres_unit));
	//width_unit = psd_getu16(pos+6);

	yres_int = psd_getu32(zz->pos+8);
	yres = ((double)yres_int)/65536.0;
	de_dbg(c, "yres=%.2f dpi", yres);
	yres_unit = psd_getu16(zz->pos+12);
	de_dbg(c, "yres display unit: %d (%s)", (int)yres_unit, units_name(yres_unit));
	//height_unit = psd_getu16(pos+14);

	d->density.code = DE_DENSITY_DPI;
	d->density.xdens = xres;
	d->density.ydens = yres;
}

static void hrsrc_namesofalphachannels(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;
	int idx = 0;

	// This is a "series of Pascal strings", whatever that is.

	s = ucstring_create(c);
	while(zz->pos < (zz->endpos-1)) {
		ucstring_empty(s);
		read_pascal_string_to_ucstring(c, d, s, zz);
		de_dbg(c, "%s[%d]: \"%s\"", ri->idname, idx, ucstring_getpsz_d(s));
		idx++;
	}
	ucstring_destroy(s);
}

static void hrsrc_printflags(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	u8 fl[9];
	if(zz_avail(zz)!=9) return;
	de_read(fl, zz->pos, 9);
	de_dbg(c, "%s: labels=%d, crop marks=%d, color bars=%d, registration marks=%d, "
		"negative=%d, flip=%d, interpolate=%d, caption=%d, print flags=%d",
		ri->idname, (int)fl[0], (int)fl[1], (int)fl[2], (int)fl[3],
		(int)fl[4], (int)fl[5], (int)fl[6], (int)fl[7], (int)fl[8]);
}

static void do_pathinfo(deark *c, lctx *d, zztype *zz)
{
	i64 num_records;
	i64 i;

	num_records = zz_avail(zz) / 26;
	de_dbg(c, "calculated number of records: %d", (int)num_records);
	for(i=0; i<num_records; i++) {
		zztype czz;
		i64 t;
		i64 x;
		const char *name;

		de_dbg(c, "path data record[%d] at %d", (int)i, (int)zz->pos);
		zz_init_with_len(&czz, zz, 26);
		de_dbg_indent(c, 1);

		t = psd_getu16zz(&czz);
		switch(t) {
		case 0: name="Closed subpath length"; break;
		case 1: name="Closed subpath Bezier knot, linked"; break;
		case 2: name="Closed subpath Bezier knot, unlinked"; break;
		case 3: name="Open subpath length"; break;
		case 4: name="Open subpath Bezier knot, linked"; break;
		case 5: name="Open subpath Bezier knot, unlinked"; break;
		case 6: name="Path fill rule"; break;
		case 7: name="Clipboard"; break;
		case 8: name="Initial fill rule"; break;
		default: name="?"; break;
		}
		de_dbg(c, "path record type: %d (%s)", (int)t, name);

		switch(t) {
		case 0: case 3:
			x = psd_getu16zz(&czz);
			de_dbg(c, "number of Bezier knot records: %d", (int)x);
			break;
		case 8:
			x = psd_getu16zz(&czz);
			de_dbg(c, "value: %d", (int)x);
			break;
		}

		zz->pos += 26;
		de_dbg_indent(c, -1);
	}
}

static void hrsrc_pathinfo(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	do_pathinfo(c, d, zz);
}

static void hrsrc_printflagsinfo(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 version, bleed_width_value, bleed_width_scale;
	u8 crop_marks;

	if(zz_avail(zz)!=10) return;
	version = psd_getu16zz(zz);
	crop_marks = psd_getbytezz(zz);
	zz->pos++;
	bleed_width_value = psd_getu32zz(zz);
	bleed_width_scale = psd_getu16zz(zz);
	de_dbg(c, "%s: version=%d, crop marks=%d, bleed width value=%d, bleed width scale=%d",
		ri->idname, (int)version, (int)crop_marks,
		(int)bleed_width_value, (int)bleed_width_scale);
}

static void hrsrc_exif(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_fmtutil_handle_exif(c, zz->pos, zz_avail(zz));
}

static void hrsrc_iptc(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	d->has_iptc = 1;
	de_fmtutil_handle_iptc(c, c->infile, zz->pos, zz_avail(zz), 0x0);
}

static void hrsrc_xmp(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	dbuf_create_file_from_slice(c->infile, zz->pos, zz_avail(zz), "xmp", NULL, DE_CREATEFLAG_IS_AUX);
}

static void hrsrc_iccprofile(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	dbuf_create_file_from_slice(c->infile, zz->pos, zz_avail(zz), "icc", NULL, DE_CREATEFLAG_IS_AUX);
}

static void do_pluginrsrc_mani(deark *c, lctx *d, zztype *zz)
{
	struct de_fourcc fourcc;
	i64 len;
	zztype czz;

	// This function is based on reverse engineering, and may not be correct.

	if(zz_avail(zz)<4) goto done;
	psd_read_fourcc_zz(c, d, zz, &fourcc);
	de_dbg(c, "id: '%s'", fourcc.id_dbgstr);

	if(fourcc.id==CODE_IRFR) { // Most likely related to Image Ready
		if(zz_avail(zz)<4) goto done;
		len = psd_getu32zz(zz);
		de_dbg(c, "length: %d", (int)len);
		if(zz_avail(zz)<12) goto done;
		zz_init_with_len(&czz, zz, len);
		// This data seems to have the same structure as a "series of tagged
		// blocks", but with different "keys". I don't know whether the keys are
		// in a different namespace, or what.
		do_tagged_blocks(c, d, zz, 1);
	}

done:
	;
}

static void do_pluginrsrc_mopt(deark *c, lctx *d, zztype *zz)
{
	i64 x;
	i64 num_items;
	i64 i;
	int saved_indent_level;
	zztype czz;

	// This function is based on reverse engineering, and may not be correct.

	de_dbg_indent_save(c, &saved_indent_level);

	x = psd_getu32zz(zz);
	de_dbg(c, "unknown int: %d", (int)x);
	num_items = psd_getu32zz(zz);
	de_dbg(c, "number of mopt items: %d", (int)num_items);

	for(i=0; i<num_items; i++) {
		i64 dlen;
		i64 something_len;

		something_len = 1138;
		if(zz_avail(zz)<something_len) break;
		de_dbg(c, "mopt item[%d] at %d", (int)i, (int)zz->pos);
		de_dbg_indent(c, 1);

		de_dbg(c, "[%d bytes of data at %d]", (int)something_len, (int)zz->pos);
		if(c->debug_level>=2) {
			de_dbg_indent(c, 1);
			de_dbg_hexdump(c, c->infile, zz->pos, something_len, 256, NULL, 0x1);
			de_dbg_indent(c, -1);
		}
		zz->pos += something_len;

		if(zz_avail(zz)<4) break;

		dlen = psd_getu32zz(zz);
		de_dbg(c, "descriptor length: %d", (int)dlen);

		if(dlen>0 && zz_avail(zz)>0) {
			zz_init_with_len(&czz, zz, dlen);
			read_descriptor(c, d, &czz, 1, "");
			zz->pos += dlen;
		}

		de_dbg_indent(c, -1);
	}

	de_dbg_indent_restore(c, saved_indent_level);
}

// Any plugin resource containing just a descriptor (after the ID code)
static void do_pluginrsrc_descriptor(deark *c, lctx *d, zztype *zz)
{
	zztype czz;
	zz_init(&czz, zz);
	read_descriptor(c, d, &czz, 1, "");
}

static void hrsrc_pluginresource(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	struct de_fourcc fourcc;
	zztype czz;

	// Plug-in resources seem to start with a fourcc.
	if(zz_avail(zz)<4) return;
	psd_read_fourcc_zz(c, d, zz, &fourcc);
	de_dbg(c, "id: '%s'", fourcc.id_dbgstr);
	zz_init(&czz, zz);
	switch(fourcc.id) {
	case CODE_mani:
		do_pluginrsrc_mani(c, d, &czz);
		break;
	case CODE_mopt:
		do_pluginrsrc_mopt(c, d, &czz);
		break;
	case CODE_mset:
		do_pluginrsrc_descriptor(c, d, &czz);
		break;
	default:
		if(zz_avail(&czz)>0) {
			de_dbg(c, "[%d more bytes of plug-in resource data at %d]",
				(int)zz_avail(&czz), (int)czz.startpos);
			if(c->debug_level>=2) {
				de_dbg_indent(c, 1);
				de_dbg_hexdump(c, c->infile, czz.startpos, zz_avail(&czz), 256, NULL, 0x1);
				de_dbg_indent(c, -1);
			}
		}
	}
}

// Read a Photoshop-style "Unicode string" structure, and append it to s.
// (Okay to use a shared zz.)
static void read_unicode_string(deark *c, lctx *d, de_ucstring *s, zztype *zz)
{
	i64 num_code_units;

	if(zz_avail(zz)<4) { // error
		zz->pos = zz->endpos;
		return;
	}

	num_code_units = psd_getu32zz(zz);
	if(zz->pos + num_code_units*2 > zz->endpos) { // error
		zz->pos = zz->endpos;
		return;
	}

	// Use DE_DBG_MAX_STRLEN, because we assume the string is being read for
	// the purposes of printing it in the debug info.
	dbuf_read_to_ucstring_n(c->infile, zz->pos, num_code_units*2, DE_DBG_MAX_STRLEN*2, s, 0,
		d->is_le ? DE_ENCODING_UTF16LE : DE_ENCODING_UTF16BE);
	zz->pos += num_code_units*2;

	// For no apparent reason, a fair number of these strings have been observed
	// to end with an extraneous U+0000 character.
	ucstring_strip_trailing_NUL(s);
}

static void flexible_id_free_contents(deark *c, struct flexible_id *flid)
{
	if(flid->s) {
		ucstring_destroy(flid->s);
		flid->s = NULL;
	}
	if(flid->sz) {
		de_free(c, flid->sz);
		flid->sz = NULL;
	}
}

// Caller allocates flid, and must free flid->s
static void read_flexible_id(deark *c, lctx *d, i64 pos,
	struct flexible_id *flid)
{
	i64 length;

	de_zeromem(flid, sizeof(struct flexible_id));

	length = psd_getu32(pos);
	if(length==0) {
		flid->is_fourcc = 1;
		dbuf_read_fourcc(c->infile, pos+4, &flid->fourcc, 4, d->is_le ? DE_4CCFLAG_REVERSED : 0);
		flid->bytes_consumed = 4 + 4;
	}
	else {
		i64 adjusted_length;

		// I don't know what the maximum length of an identifier is.
		// I'll pretend it's 100 bytes.
		adjusted_length = length;
		if(adjusted_length>100) adjusted_length=100;
		flid->sz = de_malloc(c, adjusted_length+1);
		dbuf_read(c->infile, (unsigned char*)flid->sz, pos+4, adjusted_length);
		flid->sz[adjusted_length] = '\0';

		flid->s = ucstring_create(c);
		ucstring_append_bytes(flid->s, (unsigned char*)flid->sz, adjusted_length, 0, DE_ENCODING_ASCII);

		flid->bytes_consumed = 4 + length;
	}
}

static void read_flexible_id_zz(deark *c, lctx *d, zztype *zz, struct flexible_id *flid)
{
	read_flexible_id(c, d, zz->pos, flid);
	zz->pos += flid->bytes_consumed;
}

static void dbg_print_flexible_id(deark *c, lctx *d,
	const struct flexible_id *flid, const char *name)
{
	if(flid->is_fourcc) {
		de_dbg(c, "%s: fourcc('%s')", name, flid->fourcc.id_dbgstr);
	}
	else {
		de_dbg(c, "%s: string(\"%s\")", name, ucstring_getpsz(flid->s));
	}
}
// The PSD spec calls this type "Boolean" (or "Boolean structure").
static void do_item_type_bool(deark *c, lctx *d, zztype *zz)
{
	u8 b;
	b = psd_getbytezz(zz);
	de_dbg(c, "value: %d", (int)b);
}

// The PSD spec calls this type "Integer".
static void do_item_type_long(deark *c, lctx *d, zztype *zz)
{
	i64 n;
	// No idea if this is signed or unsigned.
	n = psd_geti32zz(zz);
	de_dbg(c, "value: %d", (int)n);
}

// "Double"
static void do_item_type_doub(deark *c, lctx *d, zztype *zz)
{
	double v;
	v = dbuf_getfloat64x(c->infile, zz->pos, d->is_le);
	de_dbg(c, "value: %f", v);
	zz->pos += 8;
}

// "Unit float"
static void do_item_type_UntF(deark *c, lctx *d, zztype *zz)
{
	double v;
	struct de_fourcc unit4cc;

	psd_read_fourcc_zz(c, d, zz, &unit4cc);
	de_dbg(c, "units code: '%s'", unit4cc.id_dbgstr);

	v = dbuf_getfloat64x(c->infile, zz->pos, d->is_le);
	de_dbg(c, "value: %f", v);
	zz->pos += 8;
}

static int do_item_type_class(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;

	tmps = ucstring_create(c);
	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "classID");
	flexible_id_free_contents(c, &flid);

	ucstring_destroy(tmps);
	return 1;
}

static int do_item_type_alis(deark *c, lctx *d, zztype *zz)
{
	i64 x;

	x = psd_getu32zz(zz);
	de_dbg(c, "alias length: %d", (int)x);
	zz->pos += x;
	return 1;
}

// Undocumented UnFl descriptor item type
static void do_item_type_UnFl(deark *c, lctx *d, zztype *zz)
{
	i64 count;
	struct de_fourcc unit4cc;

	psd_read_fourcc_zz(c, d, zz, &unit4cc);
	de_dbg(c, "units code: '%s'", unit4cc.id_dbgstr);

	count = psd_getu32zz(zz);
	de_dbg(c, "count: %d", (int)count);

	zz->pos += count*8; // TODO: [what we assume is a] float array
}

static void do_text_engine_data(deark *c, lctx *d, i64 pos, i64 len)
{
	if(len<1) return;
	de_dbg(c, "text engine data at %d, len=%d", (int)pos, (int)len);
	if(c->extract_level<2) return;
	dbuf_create_file_from_slice(c->infile, pos, len, "enginedata", NULL, DE_CREATEFLAG_IS_AUX);
}

// The PSD spec calls this type "String" (or "String structure").
static void do_item_type_TEXT(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "value: \"%s\"", ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

// "tdta" / "Raw Data"
static int do_item_type_tdta(deark *c, lctx *d,
	const struct flexible_id *key_flid, zztype *zz)
{
	i64 dlen;

	// The public PSD spec does not reveal how to calculate the length of a 'tdata'
	// item. Evidence suggests it starts with a 4-byte length field.
	dlen = psd_getu32zz(zz);
	de_dbg(c, "raw data at %d, dlen=%d", (int)zz->pos, (int)dlen);
	if(zz->pos+dlen > zz->endpos) {
		return 0;
	}

	if(key_flid->sz) {
		if(!de_strcmp(key_flid->sz, "EngineData")) {
			do_text_engine_data(c, d, zz->pos, dlen);
		}
	}

	zz->pos += dlen;
	return 1;
}

// The PSD spec calls this type "Enumerated", and also "Enumerated descriptor"
// (but not "Enumerated reference"!)
static void do_item_type_enum(deark *c, lctx *d, zztype *zz)
{
	struct flexible_id flid;

	read_flexible_id_zz(c, d, zz, &flid); // "type"
	dbg_print_flexible_id(c, d, &flid, "enum type");
	flexible_id_free_contents(c, &flid);

	read_flexible_id_zz(c, d, zz, &flid); // "enum"
	dbg_print_flexible_id(c, d, &flid, "enum value");
	flexible_id_free_contents(c, &flid);
}

// "List"
static int do_item_type_VlLs(deark *c, lctx *d,
	const struct flexible_id *key_flid, zztype *zz, i64 outer_itempos)
{
	i64 num_items;
	i64 i;
	int ret;
	int retval = 0;
	zztype czz;

	num_items = psd_getu32zz(zz);
	de_dbg(c, "number of items in list: %d", (int)num_items);
	if(num_items>5000) {
		de_warn(c, "Excessively large VlLs item (%d)", (int)num_items);
		goto done;
	}

	if(d->nesting_level>MAX_NESTING_LEVEL) goto done;

	for(i=0; i<num_items; i++) {
		i64 inner_itempos;
		inner_itempos = zz->pos;
		de_dbg(c, "item[%d] at %d (for list@%d)", (int)i,
			(int)inner_itempos, (int)outer_itempos);
		de_dbg_indent(c, 1);
		d->nesting_level++;
		zz_init(&czz, zz);
		ret = do_descriptor_item_ostype_and_data(c, d, key_flid, &czz, inner_itempos);
		d->nesting_level--;
		de_dbg_indent(c, -1);
		if(!ret) goto done;
		zz->pos += zz_used(&czz);
	}

	retval = 1;
done:
	return retval;
}

static int do_item_type_descriptor(deark *c, lctx *d, zztype *zz, int has_version)
{
	int retval = 0;

	d->nesting_level++;
	if(d->nesting_level>MAX_NESTING_LEVEL) goto done;

	// This descriptor contains a descriptor. We have to go deeper.
	retval = read_descriptor(c, d, zz, has_version, "");

done:
	d->nesting_level--;
	return retval;
}

static int do_Enmr_reference(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;

	tmps = ucstring_create(c);
	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "classID");
	flexible_id_free_contents(c, &flid);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "typeID");
	flexible_id_free_contents(c, &flid);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "enum");
	flexible_id_free_contents(c, &flid);

	ucstring_destroy(tmps);
	return 1;
}

static int do_prop_reference(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;

	tmps = ucstring_create(c);
	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "classID");
	flexible_id_free_contents(c, &flid);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "keyID");
	flexible_id_free_contents(c, &flid);

	ucstring_destroy(tmps);
	return 1;
}

static int do_Clss_reference(deark *c, lctx *d, zztype *zz)
{
	return do_item_type_class(c, d, zz);
}

static int do_name_reference(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;

	// I can't find any credible documentation of the 'name' reference format.
	// This code is based on reverse engineering, and may not be correct.

	tmps = ucstring_create(c);

	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));
	ucstring_empty(tmps);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "undocumented id");
	flexible_id_free_contents(c, &flid);

	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "undocumented unicode string: \"%s\"", ucstring_getpsz_d(tmps));

	ucstring_destroy(tmps);
	return 1;
}

static int do_rele_reference(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;
	i64 offs;

	tmps = ucstring_create(c);

	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));
	ucstring_empty(tmps);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "classID");
	flexible_id_free_contents(c, &flid);

	offs = psd_geti32zz(zz);
	de_dbg(c, "offset: %d", (int)offs);

	ucstring_destroy(tmps);
	return 1;
}

static int do_indx_reference(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *tmps = NULL;
	struct flexible_id flid;
	i64 x;

	// I can't find any official documentation of the 'indx' reference format.
	// This code may not be correct.

	tmps = ucstring_create(c);

	read_unicode_string(c, d, tmps, zz);
	de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(tmps));
	ucstring_empty(tmps);

	read_flexible_id_zz(c, d, zz, &flid);
	dbg_print_flexible_id(c, d, &flid, "undocumented id");
	flexible_id_free_contents(c, &flid);

	x = psd_geti32zz(zz);
	de_dbg(c, "undocumented int: %d", (int)x);

	ucstring_destroy(tmps);
	return 1;
}

// "Reference structure"
static int do_item_type_obj(deark *c, lctx *d, zztype *zz)
{
	i64 num_items;
	i64 i;
	int retval = 0;
	int saved_indent_level;
	zztype czz;

	de_dbg_indent_save(c, &saved_indent_level);

	num_items = psd_getu32zz(zz);
	de_dbg(c, "number of items in reference: %d", (int)num_items);

	for(i=0; i<num_items; i++) {
		struct de_fourcc type4cc;
		i64 itempos;

		itempos = zz->pos;
		if(itempos >= zz->endpos) goto done;
		psd_read_fourcc_zz(c, d, zz, &type4cc);
		de_dbg(c, "reference item[%d] '%s' at %d", (int)i, type4cc.id_dbgstr, (int)itempos);

		de_dbg_indent(c, 1);

		zz_init(&czz, zz);
		switch(type4cc.id) {
		case CODE_Enmr:
			if(!do_Enmr_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		case CODE_prop:
			if(!do_prop_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		case CODE_name:
			if(!do_name_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		case CODE_Clss:
			if(!do_Clss_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		case CODE_rele:
			if(!do_rele_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		case CODE_indx:
			if(!do_indx_reference(c, d, &czz)) goto done;
			zz->pos += zz_used(&czz);
			break;
		default:
			// TODO: 'Idnt'
			goto done;
		}

		de_dbg_indent(c, -1);
	}

	retval = 1;
done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

// key_flid is relevant "key" identifier.
static int do_descriptor_item_ostype_and_data(deark *c, lctx *d,
	const struct flexible_id *key_flid, zztype *zz, i64 itempos)
{
	int ret;
	int retval = 0;
	struct de_fourcc type4cc;
	zztype czz;

	psd_read_fourcc_zz(c, d, zz, &type4cc);
	de_dbg(c, "item OSType: '%s'", type4cc.id_dbgstr);

	zz_init(&czz, zz);

	switch(type4cc.id) {
	case CODE_bool:
		do_item_type_bool(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_long:
		do_item_type_long(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_doub:
		do_item_type_doub(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_comp:
		// TODO
		zz->pos += 8;
		break;
	case CODE_UntF:
		do_item_type_UntF(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_UnFl:
		do_item_type_UnFl(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_TEXT:
		do_item_type_TEXT(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_enum:
		do_item_type_enum(c, d, &czz);
		zz->pos += zz_used(&czz);
		break;
	case CODE_VlLs:
		ret = do_item_type_VlLs(c, d, key_flid, &czz, itempos);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_Objc:
	case CODE_GlbO:
		ret = do_item_type_descriptor(c, d, &czz, 0);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_ObAr:
		// Undocumented type. Appears to contain a versioned descriptor.
		ret = do_item_type_descriptor(c, d, zz, 1);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_obj:
		ret = do_item_type_obj(c, d, &czz);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_tdta:
		ret = do_item_type_tdta(c, d, key_flid, &czz);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_type:
	case CODE_GlbC:
		ret = do_item_type_class(c, d, &czz);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
	case CODE_alis:
		ret = do_item_type_alis(c, d, &czz);
		zz->pos += zz_used(&czz);
		if(!ret) goto done;
		break;
		// TODO: 'Pth ' (undocumented type)
	default:
		goto done;
	}

	retval = 1;
done:
	return retval;
}

static int do_descriptor_item(deark *c, lctx *d, zztype *zz)
{
	struct flexible_id key;
	zztype czz;
	i64 itempos;
	int ret;

	itempos = zz->pos;

	read_flexible_id_zz(c, d, zz, &key);
	dbg_print_flexible_id(c, d, &key, "key");

	zz_init(&czz, zz);
	ret = do_descriptor_item_ostype_and_data(c, d, &key, &czz, itempos);
	flexible_id_free_contents(c, &key);
	if(!ret) return 0;
	zz->pos += zz_used(&czz);

	return 1;
}

// Read a "Descriptor" structure.
// If has_version==1, the data begins with a 4-byte Descriptor Version field.
// dscrname is extra debug text that will appear after the word "descriptor".
// (Okay to use a shared zz, but use caution.)
static int read_descriptor(deark *c, lctx *d, zztype *zz, int has_version, const char *dscrname)
{
	de_ucstring *name_from_classid = NULL;
	struct flexible_id classid;
	i64 ver_pos = 0;
	i64 dscr_pos;
	i64 num_items;
	i64 i;
	int ret;
	int retval = 0;
	i64 dv = 16;
	zztype czz;
	int saved_indent_level;

	de_dbg_indent_save(c, &saved_indent_level);

	if(has_version) {
		ver_pos = zz->pos;
		dv = psd_getu32zz(zz);
	}

	dscr_pos = zz->pos;

	if(has_version) {
		de_dbg(c, "descriptor%s at %d (version# at %d)", dscrname, (int)dscr_pos, (int)ver_pos);
	}
	else {
		de_dbg(c, "descriptor%s at %d", dscrname, (int)dscr_pos);
	}

	if(dv!=16) {
		de_warn(c, "Unsupported descriptor version: %d", (int)dv);
		goto done;
	}

	de_dbg_indent(c, 1);

	name_from_classid = ucstring_create(c);
	read_unicode_string(c, d, name_from_classid, zz);
	if(name_from_classid->len > 0) {
		de_dbg(c, "name from classID: \"%s\"", ucstring_getpsz_d(name_from_classid));
	}

	read_flexible_id_zz(c, d, zz, &classid);
	dbg_print_flexible_id(c, d, &classid, "classID");
	flexible_id_free_contents(c, &classid);

	num_items = psd_getu32zz(zz);
	de_dbg(c, "number of items in descriptor: %d", (int)num_items);

	// Descriptor items
	for(i=0; i<num_items; i++) {
		if(zz->pos >= zz->endpos) {
			de_dbg(c, "[Expected %d descriptor items, only found %d.]", (int)num_items, (int)i);
			goto done;
		}
		de_dbg(c, "item[%d] at %d (for descriptor@%d)", (int)i, (int)zz->pos, (int)dscr_pos);
		de_dbg_indent(c, 1);
		zz_init(&czz, zz);
		ret = do_descriptor_item(c, d, &czz);
		if(!ret) {
			de_dbg(c, "[Failed to fully decode descriptor item.]");
		}
		de_dbg_indent(c, -1);
		if(!ret) goto done;
		zz->pos += zz_used(&czz);
	}

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(name_from_classid);
	return retval;
}

static void hrsrc_descriptor_with_version(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	read_descriptor(c, d, zz, 1, "");
}

static int do_slices_resource_block(deark *c, lctx *d, i64 slice_idx, zztype *zz)
{
	de_ucstring *s = NULL;
	i64 id, group_id, origin, slice_type;
	int retval = 0;

	s = ucstring_create(c);

	id = psd_getu32zz(zz);
	de_dbg(c, "id: %d", (int)id);

	group_id = psd_getu32zz(zz);
	de_dbg(c, "group id: %d", (int)group_id);

	origin = psd_getu32zz(zz);
	de_dbg(c, "origin: %d", (int)origin);

	if(origin==1) {
		i64 layer_id;
		layer_id = psd_getu32zz(zz);
		de_dbg(c, "associated layer id: %d", (int)layer_id);
	}

	read_unicode_string(c, d, s, zz); // Name
	if(s->len>0) {
		de_dbg(c, "name: \"%s\"", ucstring_getpsz(s));
	}
	ucstring_empty(s);

	slice_type = psd_getu32zz(zz);
	de_dbg(c, "type: %d", (int)slice_type);

	read_rectangle_ltrb(c, d, zz, "position");

	read_unicode_string(c, d, s, zz); // URL
	ucstring_empty(s);

	read_unicode_string(c, d, s, zz); // Target
	ucstring_empty(s);

	read_unicode_string(c, d, s, zz); // Message
	ucstring_empty(s);

	read_unicode_string(c, d, s, zz); // Alt Tag
	ucstring_empty(s);

	zz->pos += 1; // Flag: Cell text is HTML

	read_unicode_string(c, d, s, zz); // Cell text
	ucstring_empty(s);

	zz->pos += 4; // Horizontal alignment
	zz->pos += 4; // Horizontal alignment
	zz->pos += 4; // Alpha color, Red, Green, Blue

	if(zz->pos > zz->endpos) goto done;
	retval = 1;

done:
	ucstring_destroy(s);
	return retval;
}

static void do_slices_v6(deark *c, lctx *d, zztype *zz)
{
	i64 num_slices;
	i64 i;
	de_ucstring *name_of_group_of_slices = NULL;
	zztype czz;
	int ret;

	zz->pos += 4; // version (already read)
	read_rectangle_tlbr(c, d, zz, "bounding rectangle");
	if(zz->pos >= zz->endpos) goto done;

	name_of_group_of_slices = ucstring_create(c);
	read_unicode_string(c, d, name_of_group_of_slices, zz);
	de_dbg(c, "name of group of slices: \"%s\"",
		ucstring_getpsz_d(name_of_group_of_slices));
	if(zz->pos >= zz->endpos) goto done;

	num_slices = psd_getu32zz(zz);
	de_dbg(c, "number of slices: %d", (int)num_slices);

	for(i=0; i<num_slices; i++) {
		if(zz->pos >= zz->endpos) {
			de_dbg(c, "[Expected %d slices, only found %d]", (int)num_slices, (int)i);
			goto done;
		}
		de_dbg(c, "slice[%d] at %d", (int)i, (int)zz->pos);
		de_dbg_indent(c, 1);
		zz_init(&czz, zz);
		do_slices_resource_block(c, d, i, &czz);
		de_dbg_indent(c, -1);
		zz->pos += zz_used(&czz);
	}

	// The PSD spec seems to show that a Descriptor can (optionally) appear after
	// every slice resource block.
	// But if that were true, there would seem to be no way to tell whether a slice
	// is followed by a descriptor, or immediately by the next slice.
	// Fortunately, evidence suggests that a Descriptor can only appear after the
	// last slice in the array.

	if(zz->pos >= zz->endpos) goto done;

	ret = read_descriptor(c, d, zz, 1, " (for slices)");
	if(!ret) goto done;

done:
	ucstring_destroy(name_of_group_of_slices);
}

static void do_slices_v7_8(deark *c, lctx *d, zztype *zz)
{
	zz->pos += 4; // Skip version number (7 or 8), already read.
	read_descriptor(c, d, zz, 1, "");
}

static void hrsrc_slices(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 sver;

	if(zz_avail(zz)<4) return;
	sver = psd_getu32(zz->pos);
	de_dbg(c, "slices resource format version: %d", (int)sver);

	if(sver==6) {
		do_slices_v6(c, d, zz);
	}
	else if(sver==7 || sver==8) {
		do_slices_v7_8(c, d, zz);
	}
}

static void hrsrc_thumbnail(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 fmt;
	const char *ext;
	dbuf *outf = NULL;
	i64 dpos;
	i64 dlen;

	if(zz_avail(zz)<=28) goto done;

	fmt = psd_getu32(zz->pos);
	if(fmt != 1) {
		// fmt != kJpegRGB
		de_dbg(c, "thumbnail in unsupported format (%d) found", (int)fmt);
		goto done;
	}

	zz->pos += 28;
	dpos = zz->pos;
	dlen = zz_avail(zz);

	if(ri->id==0x0409) {
		ext = "psdthumb_rbswap.jpg";
		if(c->extract_policy!=DE_EXTRACTPOLICY_MAINONLY) {
			de_info(c, "Note: This Photoshop thumbnail uses nonstandard colors, "
				"and may not look right.");
		}
	}
	else {
		ext = "psdthumb.jpg";
	}

	outf = dbuf_create_output_file(c, ext, NULL, DE_CREATEFLAG_IS_AUX);

	if(ri->id==0x0409 && d->jpeg_rbswap_mode && dlen>=11 &&
		!dbuf_memcmp(c->infile, dpos, "\xff\xd8\xff\xe0\x00\x10" "JFIF" "\x00", 11))
	{
		// If we were to extract this image as-is, there will be no way to tell
		// later that the red/blue channels are swapped. So, we have this feature
		// to mark it by inserting a custom segment (after the JFIF segment).
		dbuf_copy(c->infile, dpos, 20, outf);
		dbuf_write(outf, (const u8*)"\xff\xe1\x00\x10" "Deark_RB_swap\0", 18);
		dbuf_copy(c->infile, dpos+20, dlen-20, outf);
	}
	else {
		dbuf_copy(c->infile, dpos, dlen, outf);
	}

done:
	dbuf_close(outf);
}

// Handler for any resource that consists of a 1-byte numeric value
static void hrsrc_byte(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	u8 b;
	if(zz_avail(zz)!=1) return;
	b = psd_getbytezz(zz);
	de_dbg(c, "%s: %d", ri->idname, (int)b);
}

static void hrsrc_uint16(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 n;
	if(zz_avail(zz)!=2) return;
	n = psd_getu16zz(zz);
	de_dbg(c, "%s: %d", ri->idname, (int)n);
}

static void hrsrc_uint32(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 n;
	if(zz_avail(zz)!=4) return;
	n = psd_getu32zz(zz);
	de_dbg(c, "%s: %d", ri->idname, (int)n);
}

// Handler for any resource that consists of a single "Unicode string".
static void hrsrc_unicodestring(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "%s: \"%s\"", ri->idname, ucstring_getpsz_d(s));
	ucstring_destroy(s);
}

// Handler for the "Unicode Alpha Names" resource, which the documentation
// incorrectly says is a single Unicode string.
static void hrsrc_unicodestring_multi(deark *c, lctx *d, zztype *zz,
	const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;
	int idx = 0;

	s = ucstring_create(c);
	while(zz_avail(zz)>=4) {
		ucstring_empty(s);
		read_unicode_string(c, d, s, zz);
		de_dbg(c, "%s[%d]: \"%s\"", ri->idname, idx, ucstring_getpsz_d(s));
		idx++;
	}
	ucstring_destroy(s);
}

// Handler for any resource that consists of a single "Pascal string".
static void hrsrc_pascalstring(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	read_pascal_string_to_ucstring(c, d, s, zz);
	de_dbg(c, "%s: \"%s\"", ri->idname, ucstring_getpsz(s));
	ucstring_destroy(s);
}

// Raw byte-oriented text
static void hrsrc_plaintext(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	dbuf_read_to_ucstring_n(c->infile, zz->pos, zz_avail(zz), DE_DBG_MAX_STRLEN,
		s, 0, d->input_encoding);
	de_dbg(c, "%s: \"%s\"", ri->idname, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void hrsrc_urllist(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	de_ucstring *s = NULL;
	i64 count;
	i64 i;

	count = psd_getu32zz(zz);
	de_dbg(c, "URL count: %d", (int)count);

	s = ucstring_create(c);

	for(i=0; i<count; i++) {
		struct de_fourcc url4cc;
		i64 id;

		// undocumented field, seems to be a fourcc
		psd_read_fourcc_zz(c, d, zz, &url4cc);

		id = psd_getu32zz(zz);

		read_unicode_string(c, d, s, zz);
		de_dbg(c, "URL[%d]: '%s', id=%d, value=\"%s\"", (int)i,
			url4cc.id_dbgstr, (int)id, ucstring_getpsz(s));
		ucstring_empty(s);
	}

	ucstring_destroy(s);
}

static void hrsrc_versioninfo(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 ver, file_ver;
	u8 b;
	de_ucstring *s = NULL;

	ver = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver);

	b = psd_getbytezz(zz);
	de_dbg(c, "hasRealMergedData: %d", (int)b);

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "writer name: \"%s\"", ucstring_getpsz(s));

	ucstring_empty(s);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "reader name: \"%s\"", ucstring_getpsz(s));

	file_ver = psd_getu32zz(zz);
	de_dbg(c, "file version: %d", (int)file_ver);

	ucstring_destroy(s);
}

static void hrsrc_printscale(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 style;
	double xloc, yloc, scale;
	if(zz_avail(zz)!=14) return;
	style = psd_getu16zz(zz);
	de_dbg(c, "style: %d", (int)style);
	xloc = dbuf_getfloat32x(c->infile, zz->pos, d->is_le);
	zz->pos += 4;
	yloc = dbuf_getfloat32x(c->infile, zz->pos, d->is_le);
	zz->pos += 4;
	de_dbg(c, "location: (%f,%f)", xloc, yloc);
	scale = dbuf_getfloat32x(c->infile, zz->pos, d->is_le);
	zz->pos += 4;
	de_dbg(c, "scale: %f", scale);
}

static void hrsrc_pixelaspectratio(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 version;
	double ratio;
	if(zz_avail(zz)!=12) return;
	version = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)version);
	ratio = dbuf_getfloat64x(c->infile, zz->pos, d->is_le);
	zz->pos += 8;
	de_dbg(c, "x/y: %f", ratio);
}

static void hrsrc_layerselectionids(deark *c, lctx *d, zztype *zz, const struct rsrc_info *ri)
{
	i64 count;
	int i;

	if(zz_avail(zz)<2) return;
	count = psd_getu16zz(zz);
	de_dbg(c, "count: %d", (int)count);
	if(zz_avail(zz)<4*count) return;
	for(i=0; i<count; i++) {
		i64 lyid;
		lyid = psd_getu32zz(zz);
		de_dbg(c, "layer id[%d]: %u", (int)i, (unsigned int)lyid);
	}
}

static int do_image_resource(deark *c, lctx *d, zztype *zz)
{
	i64 resource_id;
	i64 block_data_len;
	struct rsrc_info ri;
	de_ucstring *blkname = NULL;
	struct de_fourcc sig4cc;
	const char *signame = "Photoshop";
	zztype czz;
	int retval = 0;

	// Check the "8BIM" (etc.) signature.
	// TODO: Maybe we should allow arbitrary signatures, but restricting it to
	// known signatures lets us know if the parser has gone off the rails.
	psd_read_fourcc_zz(c, d, zz, &sig4cc);
	if(sig4cc.id==CODE_8BIM) {
		;
	}
	else if(sig4cc.id==CODE_AgHg) { // Seen in Photoshop Elements files
		signame = "AgHg";
	}
	else if(sig4cc.id==CODE_DCSR) { // ExifTool says this exists
		signame = "DCSR";
	}
	else if(sig4cc.id==CODE_MeSa) { // Image Ready resource?
		signame = "MeSa";
	}
	else if(sig4cc.id==CODE_PHUT) { // PhotoDeluxe resource?
		signame = "PHUT";
	}
	else {
		de_warn(c, "Bad Photoshop resource block signature '%s' at %d",
			sig4cc.id_sanitized_sz, (int)zz->startpos);
		goto done;
	}

	resource_id = psd_getu16zz(zz);

	// Read resource block name. A "Pascal string" padded to an even number of bytes.
	blkname = ucstring_create(c);
	zz_init(&czz, zz);
	read_pascal_string_to_ucstring(c, d, blkname, &czz);
	zz->pos += de_pad_to_2(zz_used(&czz));

	block_data_len = psd_getu32zz(zz);

	// TODO: Are resource_ids "namespaced" based on the block signature?
	lookup_rsrc(sig4cc.id, (u16)resource_id, &ri);

	de_dbg(c, "%s rsrc 0x%04x (%s) pos=%d blkname=\"%s\" dpos=%d dlen=%d",
		signame, (int)resource_id, ri.idname, (int)zz->startpos,
		ucstring_getpsz(blkname), (int)zz->pos, (int)block_data_len);

	if(zz->pos+block_data_len > zz->endpos) {
		de_warn(c, "PSD rsrc exceeds its parent's bounds. Ends at %"I64_FMT
			", parent ends at %"I64_FMT".", zz->pos+block_data_len, zz->endpos);
	}

	de_dbg_indent(c, 1);
	if(ri.hfn) {
		zz_init_with_len(&czz, zz, block_data_len);
		ri.hfn(c, d, &czz, &ri);
	}
	else if(ri.flags&0x0004) {
		zz_init_with_len(&czz, zz, block_data_len);
		hrsrc_descriptor_with_version(c, d, &czz, &ri);
	}
	else if(c->debug_level>=2) {
		de_dbg_hexdump(c, c->infile, zz->pos, block_data_len, 256, NULL,
			(ri.flags&0x0010)?0x0:0x1);
	}
	de_dbg_indent(c, -1);

	zz->pos += de_pad_to_2(block_data_len);

	retval = 1;

done:
	if(blkname) ucstring_destroy(blkname);
	return retval;
}

static void do_image_resource_blocks(deark *c, lctx *d, zztype *zz)
{
	zztype czz;

	while(1) {
		if(zz->pos>=zz->endpos) break;
		zz_init(&czz, zz);
		if(!do_image_resource(c, d, &czz)) break;
		zz->pos += zz_used(&czz);
	}
}

// Layer mask / adjustment layer data
static void do_layer_mask_data(deark *c, lctx *d, zztype *zz)
{
	i64 dlen;
	dlen = psd_getu32zz(zz);
	de_dbg(c, "layer mask data size: %d", (int)dlen);
	zz->pos += dlen;
}

static void do_layer_blending_ranges(deark *c, lctx *d, zztype *zz)
{
	i64 dlen;
	dlen = psd_getu32zz(zz);
	de_dbg(c, "layer blending ranges data size: %d", (int)dlen);
	zz->pos += dlen;
}

static void do_layer_name(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *s = NULL;

	// "Pascal string, padded to a multiple of 4 bytes"
	s = ucstring_create(c);
	read_pascal_string_to_ucstring(c, d, s, zz);
	de_dbg(c, "layer name: \"%s\"", ucstring_getpsz(s));
	zz->pos = zz->startpos + de_pad_to_4(zz_used(zz));
	ucstring_destroy(s);
}

struct channel_data {
	i64 num_channels;
	i64 total_len;
};

static int do_layer_record(deark *c, lctx *d, zztype *zz, struct channel_data *cd)
{
	i64 nchannels;
	i64 extra_data_len;
	struct de_fourcc tmp4cc;
	i64 ch_id, ch_dlen;
	u8 b;
	int i;
	zztype czz;
	zztype extradatazz;
	int retval = 0;

	read_rectangle_tlbr(c, d, zz, "bounding rectangle");

	nchannels = psd_getu16zz(zz);
	de_dbg(c, "number of channels: %d", (int)nchannels);

	for(i=0; i<nchannels; i++) {
		ch_id = psd_geti16zz(zz);
		ch_dlen = psd_getu32or64zz(c, d, zz);
		de_dbg(c, "channel[%d] id=%d, data len=%"I64_FMT"", (int)i, (int)ch_id, ch_dlen);
		cd->num_channels++;
		cd->total_len += ch_dlen;
	}

	psd_read_fourcc_zz(c, d, zz, &tmp4cc);
	if(tmp4cc.id != CODE_8BIM) {
		de_warn(c, "Expected blend mode signature not found at %d", (int)(zz->pos-4));
		goto done;
	}

	psd_read_fourcc_zz(c, d, zz, &tmp4cc);
	de_dbg(c, "blend mode: '%s'", tmp4cc.id_dbgstr);

	b = psd_getbytezz(zz);
	de_dbg(c, "opacity: %d", (int)b);

	b = psd_getbytezz(zz);
	de_dbg(c, "clipping: %d", (int)b);

	b = psd_getbytezz(zz);
	de_dbg(c, "flags: 0x%02x", (unsigned int)b);

	zz->pos += 1; // filler

	extra_data_len = psd_getu32zz(zz);

	if(zz->pos + extra_data_len > zz->endpos) {
		de_warn(c, "Malformed layer record at %d", (int)zz->startpos);
		goto done;
	}

	zz_init_with_len(&extradatazz, zz, extra_data_len);
	zz->pos = extradatazz.endpos;

	zz_init(&czz, &extradatazz);
	do_layer_mask_data(c, d, &czz);
	extradatazz.pos += zz_used(&czz);

	zz_init(&czz, &extradatazz);
	do_layer_blending_ranges(c, d, &czz);
	extradatazz.pos += zz_used(&czz);

	zz_init(&czz, &extradatazz);
	do_layer_name(c, d, &czz);
	extradatazz.pos += zz_used(&czz);

	if(extradatazz.pos < extradatazz.endpos) {
		// The rest of the layer record data seems to be undocumented,
		// or unclearly documented.
		de_dbg(c, "layer record tagged blocks at %d, len=%d",
			(int)extradatazz.pos, (int)(extradatazz.endpos-extradatazz.pos));
		de_dbg_indent(c, 1);
		zz_init(&czz, &extradatazz);
		do_tagged_blocks(c, d, &czz, 0);
		de_dbg_indent(c, -1);
	}

	retval = 1;
done:
	return retval;
}

static int do_layer_info_section(deark *c, lctx *d, zztype *zz, int has_len_field)
{
	int retval = 0;
	i64 layer_info_len;
	i64 layer_count_raw, layer_count;
	int saved_indent_level;
	int merged_result_flag;
	i64 layer_idx;
	zztype datazz;
	zztype czz;
	struct channel_data *cd = NULL;

	de_dbg_indent_save(c, &saved_indent_level);
	if(zz_avail(zz)<4) goto done;

	de_dbg(c, "layer info section at %d", (int)zz->pos);
	de_dbg_indent(c, 1);

	if(has_len_field) {
		layer_info_len = psd_getu32or64zz(c, d, zz);
		de_dbg(c, "length of layer info section: %d", (int)layer_info_len);
	}
	else {
		layer_info_len = zz_avail(zz);
	}
	zz_init_with_len(&datazz, zz, layer_info_len);
	zz->pos += layer_info_len;
	retval = 1;

	if(datazz.pos>=datazz.endpos) {
		// If the length field is 0, it's legal for this section to end here.
		goto done;
	}

	layer_count_raw = psd_geti16zz(&datazz);
	if(layer_count_raw<0) {
		merged_result_flag = 1;
		layer_count = -layer_count_raw;
	}
	else {
		merged_result_flag = 0;
		layer_count = layer_count_raw;
	}
	de_dbg(c, "layer count: %d", (int)layer_count);
	de_dbg(c, "merged result flag: %d", (int)merged_result_flag);

	// Due to the recursive possibilities of PSD format, it would probably
	// be a bad idea to store this channel information in the 'd' struct.
	// Instead, we'll use a local variable.
	cd = de_malloc(c, sizeof(struct channel_data));
	cd->num_channels = 0;
	cd->total_len = 0;

	for(layer_idx=0; layer_idx<layer_count; layer_idx++) {
		de_dbg(c, "layer record[%d] at %d", (int)layer_idx, (int)datazz.pos);
		de_dbg_indent(c, 1);
		zz_init(&czz, &datazz);
		if(!do_layer_record(c, d, &czz, cd))
			goto done;
		datazz.pos += zz_used(&czz);
		de_dbg_indent(c, -1);
	}

	de_dbg(c, "channel image data records at %d, count=%d, total len=%"I64_FMT"",
		(int)datazz.pos, (int)cd->num_channels, cd->total_len);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	de_free(c, cd);
	return retval;
}

static void do_uint32_block(deark *c, lctx *d, zztype *zz,
	const struct de_fourcc *blk4cc, const char *name)
{
	i64 value;

	if(zz_avail(zz)!=4) return;
	value = psd_getu32zz(zz);
	de_dbg(c, "%s: %d", name, (int)value);
}

static void do_boolean_block(deark *c, lctx *d, zztype *zz,
	const struct de_fourcc *blk4cc, const char *name)
{
	u8 value;
	i64 len;

	len = zz_avail(zz);
	if(len<1 || len>4) return;
	value = psd_getbytezz(zz);
	de_dbg(c, "%s: %d", name, (int)value);
}

static void do_fourcc_block(deark *c, lctx *d, zztype *zz,
	const struct de_fourcc *blk4cc, const char *name)
{
	struct de_fourcc fourcc;

	if(zz_avail(zz)!=4) return;
	psd_read_fourcc_zz(c, d, zz, &fourcc);
	de_dbg(c, "%s: '%s'", name, fourcc.id_dbgstr);
}

static void do_Layr_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	// "Layer info" section, but starting with the "Layer count" field
	do_layer_info_section(c, d, zz, 0);
}

static void extract_linked_layer_blob(deark *c, lctx *d, i64 pos, i64 len)
{
	const char *ext = "layer.bin";
	u8 buf[8];

	if(len<1) return;

	// Sniff the file type.
	// (The "File Type" FourCC is not reliable.)
	de_read(buf, pos, sizeof(buf));
	if(!de_memcmp(buf, "8BPS\x00\x01", 6)) {
		ext = "layer.psd";
	}
	else if(!de_memcmp(buf, "8BPS\x00\x02", 6)) {
		ext = "layer.psb";
	}
	else if(!de_memcmp(buf, "\x89\x50\x4e\x47", 4)) {
		ext = "layer.png";
	}
	else if(!de_memcmp(buf, "\xff\xd8\xff", 3)) {
		ext = "layer.jpg";
	}
	else if(!de_memcmp(buf, "%PDF", 4)) {
		ext = "layer.pdf";
	}

	// TODO: Maybe we should try to use the "original filename" field, somehow,
	// to construct our filename.
	dbuf_create_file_from_slice(c->infile, pos, len, ext,
		NULL, DE_CREATEFLAG_IS_AUX);
}

static int do_one_linked_layer(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	int retval = 0;
	i64 dlen, dlen2=0;
	i64 ver;
	u8 file_open_descr_flag;
	struct de_fourcc type4cc;
	struct de_fourcc tmp4cc;
	de_ucstring *s = NULL;
	zztype datazz;

	dlen = psd_geti64zz(zz);
	de_dbg(c, "length: %"I64_FMT"", dlen);
	if(dlen<8 || zz->pos+dlen>zz->endpos) {
		de_warn(c, "Bad linked layer size %"I64_FMT" at %"I64_FMT"", dlen, zz->startpos);
		goto done;
	}

	zz_init_with_len(&datazz, zz, dlen);

	// Seems to be padded to a multiple of 4 bytes. (The spec says nothing
	// about this.)
	zz->pos += de_pad_to_4(dlen);
	retval = 1;

	psd_read_fourcc_zz(c, d, &datazz, &type4cc);
	de_dbg(c, "type: '%s'", type4cc.id_dbgstr);

	ver = psd_getu32zz(&datazz);
	de_dbg(c, "version: %d", (int)ver);

	s = ucstring_create(c);
	read_pascal_string_to_ucstring(c, d, s, &datazz);
	de_dbg(c, "unique id: \"%s\"", ucstring_getpsz(s));

	ucstring_empty(s);
	read_unicode_string(c, d, s, &datazz);
	de_dbg(c, "original file name: \"%s\"", ucstring_getpsz(s));

	psd_read_fourcc_zz(c, d, &datazz, &tmp4cc);
	de_dbg(c, "file type: '%s'", tmp4cc.id_dbgstr);

	psd_read_fourcc_zz(c, d, &datazz, &tmp4cc);
	de_dbg(c, "file creator: '%s'", tmp4cc.id_dbgstr);

	dlen2 = psd_geti64zz(&datazz);
	de_dbg(c, "length2: %"I64_FMT"", dlen2);
	if(dlen2<0) goto done;

	file_open_descr_flag = psd_getbytezz(&datazz);
	de_dbg(c, "has file open descriptor: %d", (int)file_open_descr_flag);

	if(file_open_descr_flag) {
		if(!read_descriptor(c, d, &datazz, 1, " (of open parameters)")) {
			goto done;
		}
	}

	if(type4cc.id!=CODE_liFD) {
		// TODO: liFA and liFE need special handling.
		de_dbg(c, "[this linked layer type is not supported]");
		goto done;
	}

	de_dbg(c, "raw file bytes at %"I64_FMT", len=%"I64_FMT"", datazz.pos, dlen2);
	extract_linked_layer_blob(c, d, datazz.pos, dlen2);

	// TODO: There may be more fields after this, depending on the version.

done:
	ucstring_destroy(s);
	return retval;
}

static void do_lnk2_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	int ret;
	zztype czz;

	while(zz->pos<zz->endpos) {
		de_dbg(c, "linked layer data at %"I64_FMT"", zz->pos);
		de_dbg_indent(c, 1);
		zz_init(&czz, zz);
		ret = do_one_linked_layer(c, d, &czz, blk4cc);
		de_dbg_indent(c, -1);
		if(!ret) break;
		zz->pos += zz_used(&czz);
	}
}

static void do_vm_array(deark *c, lctx *d, zztype *zz)
{
	i64 n;
	i64 dlen, idata_len;
	i64 saved_pos;

	zz->pos += 4; // Skip array-is-written flag (already processed)

	dlen = psd_getu32zz(zz);
	de_dbg(c, "length: %d", (int)dlen);
	if(dlen==0) goto done;

	saved_pos = zz->pos;

	n = psd_getu32zz(zz);
	de_dbg(c, "depth: %d", (int)n);

	read_rectangle_tlbr(c, d, zz, "rectangle");

	n = psd_getu16zz(zz);
	de_dbg(c, "depth: %d", (int)n);

	n = (i64)psd_getbytezz(zz);
	dbg_print_compression_method(c, d, n);

	idata_len = saved_pos + dlen - zz->pos;
	de_dbg(c, "[%d bytes of data at %d]", (int)idata_len, (int)zz->pos);

	zz->pos = saved_pos + dlen;
done:
	;
}

static void do_vm_array_list(deark *c, lctx *d, zztype *zz)
{
	i64 ver;
	i64 dlen;
	i64 num_channels;
	zztype czz;
	i64 i;

	de_dbg(c, "virtual memory array list at %d, len=%"I64_FMT"", (int)zz->pos,
		zz_avail(zz));
	de_dbg_indent(c, 1);

	ver = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver);

	dlen = psd_getu32zz(zz);
	de_dbg(c, "length: %d", (int)dlen);

	read_rectangle_tlbr(c, d, zz, "rectangle");

	num_channels = psd_getu32zz(zz);
	de_dbg(c, "number of channels: %d", (int)num_channels);

	for(i=0; i<num_channels+2; i++) {
		i64 is_written;

		// Look ahead at the array-is-written flag.
		is_written = psd_getu32(zz->pos);

		de_dbg(c, "virtual memory array[%d] at %d%s", (int)i, (int)zz->pos,
			is_written?"":" (empty)");
		if(is_written) {
			zz_init(&czz, zz);
			de_dbg_indent(c, 1);
			do_vm_array(c, d, &czz);
			de_dbg_indent(c, -1);
			zz->pos += zz_used(&czz);
		}
		else {
			zz->pos += 4;
		}
	}

	de_dbg_indent(c, -1);
}

// The main part of a "pattern" object, starting with the version and
// color_mode[l] fields.
static int do_pattern_internal(deark *c, lctx *d, zztype *zz)
{
	i64 pat_color_mode;
	i64 ver;
	i64 w, h;
	de_ucstring *s = NULL;
	zztype vmalzz; // for virtual memory array list
	int retval = 0;

	ver = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=1) goto done;

	pat_color_mode = psd_getu32zz(zz);
	de_dbg(c, "color mode: %d (%s)", (int)pat_color_mode, get_colormode_name(pat_color_mode));

	h = psd_getu16zz(zz);
	w = psd_getu16zz(zz);
	de_dbg_dimensions(c, w, h);

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(s));

	ucstring_empty(s);
	read_pascal_string_to_ucstring(c, d, s, zz);
	de_dbg(c, "id: \"%s\"", ucstring_getpsz_d(s));

	if(pat_color_mode==PSD_CM_PALETTE) {
		de_dbg(c, "palette at %d", (int)zz->pos);
		zz->pos += 3*256;
	}

	zz_init(&vmalzz, zz);
	do_vm_array_list(c, d, &vmalzz);
	zz->pos += zz_used(&vmalzz);
	retval = 1;
done:
	ucstring_destroy(s);
	return retval;
}

// Decode a single "pattern" object, starting with the "length" field for this
// pattern.
static int do_pattern(deark *c, lctx *d, zztype *zz, i64 pattern_idx)
{
	i64 pat_dlen;
	zztype datazz; // zz for the pattern data (minus the length field)
	int retval = 0;

	if(zz_avail(zz)<16) goto done;

	de_dbg(c, "pattern[%d] at %d", (int)pattern_idx, (int)zz->pos);
	de_dbg_indent(c, 1);

	pat_dlen = psd_getu32zz(zz);
	de_dbg(c, "length: %d", (int)pat_dlen);

	zz_init_with_len(&datazz, zz, pat_dlen);

	do_pattern_internal(c, d, &datazz);

	zz->pos += de_pad_to_4(pat_dlen);

	de_dbg_indent(c, -1);

	retval = 1;
done:
	return retval;
}

static void do_pattern_sequence(deark *c, lctx *d, zztype *zz)
{
	i64 pattern_idx;
	zztype czz;

	pattern_idx = 0;
	while(1) {
		if(zz_avail(zz)<16) break;
		zz_init(&czz, zz);
		if(!do_pattern(c, d, &czz, pattern_idx)) {
			break;
		}
		zz->pos += zz_used(&czz);
		pattern_idx++;
	}
}

static void do_Patt_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *xblk4cc)
{
	do_pattern_sequence(c, d, zz);
}

// Process a v6.1 'samp' block, starting right after the ID.
static void do_samp_block_v61stuff(deark *c, lctx *d, zztype *zz)
{
	i64 n;
	i64 idata_len;

	// This code is based on guesswork, and may not be correct.

	zz->pos += 8; // 8 unknown bytes

	// Note the similarity to vm_array.

	n = psd_getu16zz(zz);
	de_dbg(c, "depth: %d", (int)n);

	read_rectangle_tlbr(c, d, zz, "rectangle");

	n = psd_getu16zz(zz);
	de_dbg(c, "depth: %d", (int)n);

	n = (i64)psd_getbytezz(zz);
	dbg_print_compression_method(c, d, n);

	idata_len = zz_avail(zz);
	de_dbg(c, "[%d bytes of data at %d]", (int)idata_len, (int)zz->pos);

}

// Process a v6.2 'samp' block, starting right after the ID.
static void do_samp_block_v62stuff(deark *c, lctx *d, zztype *zz)
{
	i64 x;
	zztype czz;

	// This code is based on guesswork, and may not be correct.

	// I don't know what the first 4 bytes are for. Observed to be 00 01 00 00.
	x = psd_getu32zz(zz);
	if(x != 0x00010000) {
		return;
	}

	zz_init(&czz, zz);
	do_vm_array_list(c, d, &czz);
}

static void do_samp_block(deark *c, lctx *d, zztype *zz)
{
	i64 item_idx;
	int saved_indent_level;
	de_ucstring *tmps = NULL;
	zztype czz;

	// Note: This code is based on guesswork, and may be incorrect.

	de_dbg_indent_save(c, &saved_indent_level);
	tmps = ucstring_create(c);

	item_idx = 0;
	while(1) {
		i64 item_data_len2;
		zztype datazz; // zz for the item data (minus the length field)

		if(zz->pos+16 > zz->endpos) break;

		de_dbg(c, "item[%d] at %d", (int)item_idx, (int)zz->pos);
		de_dbg_indent(c, 1);

		item_data_len2 = psd_getu32zz(zz);
		de_dbg(c, "length: %d", (int)item_data_len2);

		zz_init_with_len(&datazz, zz, item_data_len2);

		ucstring_empty(tmps);
		read_pascal_string_to_ucstring(c, d, tmps, &datazz);
		de_dbg(c, "id: \"%s\"", ucstring_getpsz_d(tmps));

		if(d->abr_major_ver==6 && d->abr_minor_ver<=1) {
			zz_init(&czz, &datazz);
			do_samp_block_v61stuff(c, d, &czz);
		}
		else if(d->abr_major_ver>6 || (d->abr_major_ver==6 && d->abr_minor_ver>=2)) {
			zz_init(&czz, &datazz);
			do_samp_block_v62stuff(c, d, &czz);
		}

		zz->pos += de_pad_to_4(item_data_len2);

		de_dbg_indent(c, -1);
		item_idx++;
	}

	ucstring_destroy(tmps);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_lrFX_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	i64 ver;
	i64 count;
	i64 i;
	u32 sig;
	struct de_fourcc sig4cc;

	ver = psd_getu16zz(zz);
	if(ver!=0) goto done;

	count = psd_getu16zz(zz);
	de_dbg(c, "effects count: %d", (int)count);

	for(i=0; i<count; i++) {
		i64 epos;
		i64 dlen;

		if(zz->pos>=zz->endpos) goto done;
		epos = zz->pos;

		sig = (u32)psd_getu32zz(zz);
		if(sig!=CODE_8BIM) {
			de_warn(c, "Bad 'effects' block signature at %d", (int)zz->pos);
			goto done;
		}

		psd_read_fourcc_zz(c, d, zz, &sig4cc);

		dlen = psd_getu32zz(zz);

		de_dbg(c, "effects[%d] '%s' at %d, dpos=%d, dlen=%d", (int)i, sig4cc.id_dbgstr,
			(int)epos, (int)zz->pos, (int)dlen);
		zz->pos += dlen;
	}

done:
	;
}

static void do_fxrp_block(deark *c, lctx *d, zztype *zz)
{
	double v[2];

	if(zz_avail(zz)!=16) return;
	v[0] = dbuf_getfloat64x(c->infile, zz->pos, d->is_le);
	zz->pos += 8;
	v[1] = dbuf_getfloat64x(c->infile, zz->pos, d->is_le);
	zz->pos += 8;
	de_dbg(c, "reference point: %f, %f", v[0], v[1]);
}

static void do_lsct_block(deark *c, lctx *d, zztype *zz)
{
	i64 x;
	struct de_fourcc tmp4cc;

	if(zz_avail(zz)<4) return;
	x = psd_getu32zz(zz);
	de_dbg(c, "section divider setting type: %d", (int)x);

	zz->pos += 4; // skip '8BIM' signature

	if(zz_avail(zz)<4) return;
	psd_read_fourcc_zz(c, d, zz, &tmp4cc);
	de_dbg(c, "blend mode key: '%s'", tmp4cc.id_dbgstr);

	if(zz_avail(zz)<4) return;
	x = psd_getu32zz(zz);
	de_dbg(c, "sub type: %d", (int)x);
}

static void do_lspf_block(deark *c, lctx *d, zztype *zz)
{
	unsigned int x;
	if(zz_avail(zz)!=4) return;
	x = (unsigned int)psd_getu32zz(zz);
	de_dbg(c, "protection flags: transparency=%u, composite=%u, position=%u",
		(x&0x1), (x&0x2)>>1, (x&0x4)>>2);
}

static void do_vmsk_block(deark *c, lctx *d, zztype *zz)
{
	i64 ver;
	i64 flags;
	zztype czz;

	ver = psd_getu32zz(zz);
	if(ver!=3) return;
	flags = psd_getu32zz(zz);
	de_dbg(c, "flags: 0x%08x", (unsigned int)flags);

	de_dbg(c, "path components at %d", (int)zz->pos);
	de_dbg_indent(c, 1);
	zz_init(&czz, zz);
	do_pathinfo(c, d, &czz);
	de_dbg_indent(c, -1);
}

static void do_vscg_block(deark *c, lctx *d, zztype *zz)
{
	struct de_fourcc key4cc;

	psd_read_fourcc_zz(c, d, zz, &key4cc);
	de_dbg(c, "key: '%s'", key4cc.id_dbgstr);
	read_descriptor(c, d, zz, 1, " (for Vector Stroke Content Data)");
}

static void do_vogk_block(deark *c, lctx *d, zztype *zz)
{
	i64 ver;

	ver = psd_getu32zz(zz);
	if(ver!=1) return;
	read_descriptor(c, d, zz, 1, " (for Vector Origination Data)");
}

static void do_unicodestring_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc,
	const char *name)
{
	de_ucstring *s = NULL;

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "%s: \"%s\"", name, ucstring_getpsz(s));
	ucstring_destroy(s);
}

static void do_descriptor_block(deark *c, lctx *d, zztype *zz,
	const struct de_fourcc *blk4cc, const char *name)
{
	char dscrname[100];

	if(name[0])
		de_snprintf(dscrname, sizeof(dscrname), " (for %s)", name);
	else
		de_strlcpy(dscrname, "", sizeof(dscrname));

	read_descriptor(c, d, zz, 1, dscrname);
}

static void do_lfx2_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	i64 oe_ver;
	zztype czz;

	if(zz_avail(zz)<8) return;
	oe_ver = psd_getu32zz(zz);
	de_dbg(c, "object effects version: %d", (int)oe_ver);
	if(oe_ver!=0) return;

	zz_init(&czz, zz);
	do_descriptor_block(c, d, &czz, blk4cc, "object-based effects layer info");
}

// Handles 'TySh' and 'tySh'
static void do_TySh_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	i64 ver, textver;

	ver = psd_getu16zz(zz);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=1) goto done;

	zz->pos += 6*8; // transform

	textver = psd_getu16zz(zz);
	de_dbg(c, "text version: %d", (int)textver);
	// For 'tySh', textver should be 6 -- TODO
	// For 'TySh', textver should be 50
	if(textver!=50) goto done;

	if(!read_descriptor(c, d, zz, 1, " (for type tool object setting - text)")) {
		goto done;
	}

	zz->pos += 2; // warp version
	if(!read_descriptor(c, d, zz, 1, " (for type tool object setting - warp)")) {
		goto done;
	}

	// TODO: "left, top, right, bottom" (field purpose and data type are undocumented)
	zz->pos += 4*8;

done:
	;
}

static void do_SoLd_block(deark *c, lctx *d, zztype *zz)
{
	struct de_fourcc id4cc;
	i64 ver;

	psd_read_fourcc_zz(c, d, zz, &id4cc);
	de_dbg(c, "identifier: '%s'", id4cc.id_dbgstr);
	ver = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver);

	read_descriptor(c, d, zz, 1, " (of placed layer information)");
}

static void do_filter_effect_channel(deark *c, lctx *d, zztype *zz)
{
	i64 dlen;
	i64 saved_pos;
	i64 cmpr_mode;

	zz->pos += 4; // Skip array-is-written flag (already processed)

	dlen = psd_geti64zz(zz);
	de_dbg(c, "length: %"I64_FMT"", dlen);
	saved_pos = zz->pos;
	if(dlen<=0) goto done;

	cmpr_mode = psd_getu16zz(zz);
	dbg_print_compression_method(c, d, cmpr_mode);

	de_dbg(c, "[%d bytes at %d]", (int)(saved_pos + dlen - zz->pos), (int)zz->pos);
	zz->pos = saved_pos + dlen;
done:
	;
}

static void do_filter_effect(deark *c, lctx *d, zztype *zz)
{
	i64 ver2;
	i64 dlen2;
	de_ucstring *s = NULL;
	i64 x;
	i64 ch;
	i64 max_channels;
	u8 b;
	zztype czz;
	int saved_indent_level;
	i64 filter_effects_savedpos;

	de_dbg_indent_save(c, &saved_indent_level);

	s = ucstring_create(c);

	ucstring_empty(s);
	read_pascal_string_to_ucstring(c, d, s, zz);
	de_dbg(c, "identifier: \"%s\"", ucstring_getpsz(s));

	// Note the clear similarites to the "virtual memory array lists" used in
	// Pattern data. But it is not the same. Maybe some of the code should be
	// consolidated.

	ver2 = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver2);
	if(ver2 != 1) goto done;

	dlen2 = psd_geti64zz(zz);
	de_dbg(c, "length: %"I64_FMT"", dlen2);
	filter_effects_savedpos = zz->pos;

	read_rectangle_tlbr(c, d, zz, "rectangle");

	x = psd_getu32zz(zz);
	de_dbg(c, "depth: %d", (int)x);

	max_channels = psd_getu32zz(zz);
	de_dbg(c, "max channels: %d", (int)max_channels);

	for(ch=0; ch<max_channels+2; ch++) {
		i64 is_written;

		if(zz->pos >= zz->endpos) goto done;

		// Look ahead at the array-is-written flag.
		is_written = psd_getu32(zz->pos);

		de_dbg(c, "channel[%d] at %d%s", (int)ch, (int)zz->pos,
			is_written?"":" (empty)");

		if(is_written) {
			zz_init(&czz, zz);
			de_dbg_indent(c, 1);
			do_filter_effect_channel(c, d, &czz);
			de_dbg_indent(c, -1);
			zz->pos += zz_used(&czz);
		}
		else {
			zz->pos += 4;
		}
	}

	if(zz->pos < (filter_effects_savedpos + dlen2)) {
		de_dbg(c, "[%d unknown bytes at %d]", (int)(filter_effects_savedpos + dlen2 - zz->pos),
			(int)zz->pos);
	}

	zz->pos = filter_effects_savedpos + dlen2;

	b = psd_getbytezz(zz);
	de_dbg(c, "next-items-present: %d", (int)b);

	if(b) {
		x = psd_getu16zz(zz);
		dbg_print_compression_method(c, d, x);
	}

	de_dbg(c, "[%d bytes at %d]", (int)zz_avail(zz), (int)zz->pos);
	zz->pos = zz->endpos;

done:
	ucstring_destroy(s);
	de_dbg_indent_restore(c, saved_indent_level);
}

static void do_FXid_block(deark *c, lctx *d, zztype *zz, const struct de_fourcc *blk4cc)
{
	i64 ver1;
	i64 dlen1;
	i64 idx;
	i64 main_endpos;
	zztype czz;

	ver1 = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver1);
	if(ver1<1 || ver1>3) goto done;

	// TODO: I suspect that this next "length" field is actually part of each
	// individual filter effect, contrary to what the documentation says.
	// That way, there can be multiple "filter effects" in the same block.
	// Sample files needed.

	dlen1 = psd_geti64zz(zz);
	de_dbg(c, "length: %"I64_FMT"", dlen1);
	main_endpos = zz->pos + dlen1;

	idx = 0;

	{
		de_dbg(c, "filter effect[%d] at %d", (int)idx, (int)zz->pos);
		zz_init_with_len(&czz, zz, main_endpos-zz->pos);
		de_dbg_indent(c, 1);
		do_filter_effect(c, d, &czz);
		de_dbg_indent(c, -1);
		zz->pos += zz_used(&czz);
		idx++;
	}

	if(zz->pos < main_endpos) {
		de_dbg(c, "[%d bytes of data at %d]", (int)(main_endpos-zz->pos), (int)zz->pos);
	}

	zz->pos = main_endpos;
done:
	;
}

static void do_shmd_block(deark *c, lctx *d, zztype *zz)
{
	i64 count;
	i64 i;
	zztype czz;

	if(zz_avail(zz)<4) return;

	count = psd_getu32zz(zz);
	de_dbg(c, "number of metadata items: %d", (int)count);

	for(i=0; i<count; i++) {
		i64 itempos, dpos, dlen;
		struct de_fourcc key4cc;

		if(zz->pos >= zz->endpos) break;
		itempos = zz->pos;

		zz->pos += 4; // signature ("8BIM", presumably)

		psd_read_fourcc_zz(c, d, zz, &key4cc);

		zz->pos += 1; // flag
		zz->pos += 3; // padding

		dlen = psd_getu32zz(zz);

		dpos = zz->pos;
		de_dbg(c, "metadata item[%d] '%s' at %d, dpos=%d, dlen=%d",
			(int)i, key4cc.id_dbgstr, (int)itempos, (int)dpos, (int)dlen);

		de_dbg_indent(c, 1);

		switch(key4cc.id) {
		case CODE_cust: // Undocumented, but seems to be a versioned Descriptor
		case CODE_mlst: // Undocumented, but seems to be a versioned Descriptor
			zz_init_with_len(&czz, zz, dlen);
			read_descriptor(c, d, &czz, 1, "");
			break;
		}

		de_dbg_indent(c, -1);

		zz->pos += dlen;
	}
}

static int do_tagged_block(deark *c, lctx *d, zztype *zz, int tbnamespace)
{
	i64 blklen;
	i64 blklen_len = 4; // Length of the block length field
	struct de_fourcc blk4cc;
	u32 sig;
	zztype czz;

	if(zz_avail(zz)<12) return 0;

	sig = (u32)psd_getu32zz(zz);
	if(sig!=CODE_8BIM && sig!=CODE_8B64) {
		de_warn(c, "Expected tagged block signature not found at %d", (int)zz->pos);
		return 0;
	}

	psd_read_fourcc_zz(c, d, zz, &blk4cc);

	// Some blocks types have an 8-byte length in PSD format
	if(d->intsize_4or8==8) {
		switch(blk4cc.id) {
		case CODE_LMsk: case CODE_Lr16: case CODE_Lr32:	case CODE_Layr:
		case CODE_Mt16: case CODE_Mt32: case CODE_Mtrn: case CODE_Alph:
		case CODE_FMsk: case CODE_lnk2: case CODE_FEid: case CODE_FXid:
		case CODE_PxSD:
			blklen_len = 8;
		}
	}

	if(blklen_len==8) {
		blklen = psd_geti64zz(zz);
	}
	else {
		blklen = psd_getu32zz(zz);
	}

	zz_init_with_len(&czz, zz, blklen);

	de_dbg(c, "tagged block '%s' at %d, dpos=%d, dlen=%d", blk4cc.id_dbgstr,
		(int)zz->startpos, (int)czz.startpos, (int)blklen);

	de_dbg_indent(c, 1);
	switch(blk4cc.id) {
	case CODE_clbl:
		do_boolean_block(c, d, &czz, &blk4cc, "blend clipped elements");
		break;
	case CODE_infx:
		do_boolean_block(c, d, &czz, &blk4cc, "blend interior elements");
		break;
	case CODE_knko:
		do_boolean_block(c, d, &czz, &blk4cc, "knockout");
		break;
	case CODE_lyid:
		do_uint32_block(c, d, &czz, &blk4cc, "layer ID");
		break;
	case CODE_lnsr:
		do_fourcc_block(c, d, &czz, &blk4cc, "layer name ID");
		break;
	case CODE_Layr:
	case CODE_Lr16:
		do_Layr_block(c, d, &czz, &blk4cc);
		break;
	case CODE_lnkD:
	case CODE_lnk2:
	case CODE_lnk3:
		do_lnk2_block(c, d, &czz, &blk4cc);
		break;
	case CODE_Patt:
	case CODE_Pat2:
	case CODE_Pat3:
		do_Patt_block(c, d, &czz, &blk4cc);
		break;
	case CODE_lrFX:
		do_lrFX_block(c, d, &czz, &blk4cc);
		break;
	case CODE_luni:
		do_unicodestring_block(c, d, &czz, &blk4cc, "Unicode layer name");
		break;
	case CODE_GdFl:
		do_descriptor_block(c, d, &czz, &blk4cc, "Gradient fill setting");
		break;
	case CODE_PtFl:
		do_descriptor_block(c, d, &czz, &blk4cc, "Pattern fill setting");
		break;
	case CODE_SoCo:
		do_descriptor_block(c, d, &czz, &blk4cc, "Solid color sheet setting");
		break;
	case CODE_vstk:
		do_descriptor_block(c, d, &czz, &blk4cc, "Vector Stroke Data");
		break;
	case CODE_blwh:
		do_descriptor_block(c, d, &czz, &blk4cc, "Black and White");
		break;
	case CODE_CgEd:
		do_descriptor_block(c, d, &czz, &blk4cc, "Content Generator Extra Data");
		break;
	case CODE_vibA:
		do_descriptor_block(c, d, &czz, &blk4cc, "Vibrance");
		break;
	case CODE_pths:
		do_descriptor_block(c, d, &czz, &blk4cc, "Unicode Path Name");
		break;
	case CODE_anFX:
		do_descriptor_block(c, d, &czz, &blk4cc, "Animation Effects");
		break;
	case CODE_PxSc:
		do_descriptor_block(c, d, &czz, &blk4cc, "Pixel Source Data");
		break;
	case CODE_artb:
	case CODE_artd:
	case CODE_abdd:
		do_descriptor_block(c, d, &czz, &blk4cc, "Artboard Data");
		break;
	case CODE_vmsk:
	case CODE_vsms:
		do_vmsk_block(c, d, &czz);
		break;
	case CODE_vscg:
		do_vscg_block(c, d, &czz);
		break;
	case CODE_vogk:
		do_vogk_block(c, d, &czz);
		break;
	case CODE_fxrp:
		do_fxrp_block(c, d, &czz);
		break;
	case CODE_lsct:
		do_lsct_block(c, d, &czz);
		break;
	case CODE_lspf:
		do_lspf_block(c, d, &czz);
		break;
	case CODE_lfx2:
		do_lfx2_block(c, d, &czz, &blk4cc);
		break;
	case CODE_Txt2:
		do_text_engine_data(c, d, czz.startpos, blklen);
		break;
	case CODE_TySh:
	case CODE_tySh:
		do_TySh_block(c, d, &czz, &blk4cc);
		break;
	case CODE_SoLd:
		do_SoLd_block(c, d, &czz);
		break;
	case CODE_FEid:
	case CODE_FXid:
		do_FXid_block(c, d, &czz, &blk4cc);
		break;
	case CODE_shmd:
		do_shmd_block(c, d, &czz);
		break;
	case CODE_AnDs: // Observed in Plug-in Resources/'mani'/'IRFR'
		if(tbnamespace==1) {
			do_descriptor_block(c, d, &czz, &blk4cc, "");
		}
		break;
	case CODE_desc:
		if(tbnamespace==2) { // Observed in ABR (brush) files
			do_descriptor_block(c, d, &czz, &blk4cc, "");
		}
		break;
	case CODE_patt:
		if(tbnamespace==2) {
			do_Patt_block(c, d, &czz, &blk4cc);
		}
		break;
	case CODE_samp:
		if(tbnamespace==2) {
			do_samp_block(c, d, &czz);
		}
		break;
	default:
		if(blklen>0) {
			if(c->debug_level>=2) {
				de_dbg_hexdump(c, c->infile, czz.startpos, blklen, 256, NULL, 0x1);
			}
			else {
				de_dbg(c, "[%d bytes of tagged block data at %d]", (int)blklen, (int)czz.startpos);
			}
		}
	}
	de_dbg_indent(c, -1);

	// Apparently, the data is padded to the next multiple of 4 bytes.
	// (This is not what the PSD spec says.)
	zz->pos += de_pad_to_4(blklen);
	return 1;
}

// A "Series of tagged blocks" - part of the "Layer and Mask Information" section.
// Or, the payload data from a TIFF "ImageSourceData" tag.
// Or, at the end of a "layer record".
static void do_tagged_blocks(deark *c, lctx *d, zztype *zz, int tbnamespace)
{
	zztype czz;

	d->nesting_level++;
	if(d->nesting_level>MAX_NESTING_LEVEL) goto done; // Defend against excessive recursion.

	if(d->tagged_blocks_only && d->nesting_level==1) {
		// If we're reading *only* this data structure (e.g. from a TIFF file), the
		// byte order may be of interest.
		de_dbg(c, "byte order: %s-endian", d->is_le?"little":"big");
	}

	while(1) {
		if(zz->pos+12 > zz->endpos) break;
		zz_init(&czz, zz);
		if(!do_tagged_block(c, d, &czz, tbnamespace)) break;
		zz->pos += zz_used(&czz);
	}

done:
	d->nesting_level--;
}

static int do_layer_and_mask_info_section(deark *c, lctx *d, zztype *zz)
{
	i64 layer_and_mask_info_section_len; // The "Length" field. Whole section is 4 bytes longer.
	i64 gl_layer_mask_info_len;
	zztype lmidataczz;
	zztype czz;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);

	// The "layer and mask section" contains up to 3 sub-sections:
	// 1. layer info
	// 2. global layer mask info
	// 3. tagged blocks

	de_dbg(c, "layer & mask info section at %d", (int)zz->pos);
	de_dbg_indent(c, 1);

	layer_and_mask_info_section_len = psd_getu32or64zz(c, d, zz);
	de_dbg(c, "layer & mask info section total data len: %d", (int)layer_and_mask_info_section_len);
	if(zz->pos + layer_and_mask_info_section_len > zz->endpos) {
		de_err(c, "Unexpected end of PSD file");
		goto done;
	}
	zz_init_with_len(&lmidataczz, zz, layer_and_mask_info_section_len);

	// We won't use zz again (we'll use lmidataczz instead), so we can go ahead and
	// advance its ->pos field.
	zz->pos += layer_and_mask_info_section_len;
	// Now that we know the size of this element, we can treat this function as "successful".
	retval = 1;

	///// 1. layer info /////

	zz_init(&czz, &lmidataczz);
	if(!do_layer_info_section(c, d, &lmidataczz, 1)) {
		goto done;
	}
	if(czz.endpos > lmidataczz.endpos) {
		de_warn(c, "Oversized Layer Info section");
		goto done;
	}
	lmidataczz.pos += zz_used(&czz);

	/////

	if(lmidataczz.pos >= lmidataczz.endpos) {
		goto done;
	}

	///// 2. global layer mask info /////

	de_dbg(c, "global layer mask info at %d", (int)lmidataczz.pos);
	de_dbg_indent(c, 1);
	gl_layer_mask_info_len = psd_getu32zz(&lmidataczz);
	de_dbg(c, "length of global layer mask info section: %"I64_FMT, gl_layer_mask_info_len);
	de_dbg_indent(c, -1);
	if(lmidataczz.pos+gl_layer_mask_info_len > lmidataczz.endpos) {
		de_warn(c, "Oversized Global Layer Mask Info section");
		goto done;
	}
	lmidataczz.pos += gl_layer_mask_info_len;

	/////

	if(lmidataczz.pos >= lmidataczz.endpos) {
		goto done;
	}

	///// 3. tagged blocks /////

	de_dbg(c, "tagged blocks at %d", (int)lmidataczz.pos);
	de_dbg_indent(c, 1);
	de_dbg(c, "expected length of tagged blocks section: %d", (int)(lmidataczz.endpos-lmidataczz.pos));
	zz_init(&czz, &lmidataczz);
	do_tagged_blocks(c, d, &czz, 0);
	de_dbg_indent(c, -1);

done:
	de_dbg_indent_restore(c, saved_indent_level);
	return retval;
}

static int do_action_item(deark *c, lctx *d, zztype *zz)
{
	struct de_fourcc id4cc;
	de_ucstring *s = NULL;
	i64 dscr_flag;
	int retval = 0;

	zz->pos += 1; // action-is-expanded
	zz->pos += 1; // action-is-enabled
	zz->pos += 1; // dialogs-should-be-displayed
	zz->pos += 1; // options for displaying dialogs

	s = ucstring_create(c);

	psd_read_fourcc_zz(c, d, zz, &id4cc);
	de_dbg(c, "identifier type: '%s'", id4cc.id_dbgstr);
	if(id4cc.id==CODE_TEXT) {
		read_prefixed_string_to_ucstring(c, d, s, zz);
		de_dbg(c, "id: \"%s\"", ucstring_getpsz_d(s));
	}
	else if(id4cc.id==CODE_long) {
		i64 id_long;
		id_long = psd_getu32zz(zz);
		de_dbg(c, "itemID: %d", (int)id_long);
	}
	else {
		de_err(c, "Unsupported identifier type: '%s'", id4cc.id_sanitized_sz);
		goto done;
	}

	ucstring_empty(s);
	read_prefixed_string_to_ucstring(c, d, s, zz);
	de_dbg(c, "dictionary name: \"%s\"", ucstring_getpsz_d(s));

	dscr_flag = psd_geti32zz(zz);
	de_dbg(c, "descriptor flag: %d", (int)dscr_flag);

	if(dscr_flag == -1) {
		if(!read_descriptor(c, d, zz, 0, "")) goto done;
	}
	else if(dscr_flag==0) {
		;
	}
	else {
		de_err(c, "Unsupported descriptor flag: %d", (int)dscr_flag);
		goto done;
	}

	retval = 1;

done:
	ucstring_destroy(s);
	return retval;
}

static int do_one_action(deark *c, lctx *d, zztype *zz)
{
	i64 action_pos;
	i64 idx;
	i64 num_items;
	i64 item_idx;
	de_ucstring *s = NULL;
	zztype czz;
	int saved_indent_level;
	int retval = 0;

	de_dbg_indent_save(c, &saved_indent_level);
	action_pos = zz->pos;
	idx = psd_getu16zz(zz);
	de_dbg(c, "index: %d", (int)idx);

	zz->pos += 1; // shift key flag
	zz->pos += 1; // command key flag
	zz->pos += 2; // color index info

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "action name: \"%s\"", ucstring_getpsz_d(s));

	zz->pos += 1; // action-is-expanded

	num_items = psd_getu32zz(zz);
	de_dbg(c, "number of items: %d", (int)num_items);

	for(item_idx=0; item_idx<num_items; item_idx++) {
		if(zz_avail(zz)<1) goto done;
		zz_init(&czz, zz);
		de_dbg(c, "item[%d] at %d (for action @%d)", (int)item_idx, (int)zz->pos, (int)action_pos);
		de_dbg_indent(c, 1);
		if(!do_action_item(c, d, &czz)) goto done;
		zz->pos += zz_used(&czz);
		de_dbg_indent(c, -1);
	}

	retval = 1;

done:
	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(s);
	return retval;
}

static void do_action_set(deark *c, lctx *d, zztype *zz)
{
	i64 ver;
	i64 num_actions;
	i64 action_idx;
	de_ucstring *s = NULL;
	zztype czz;
	int saved_indent_level;
	u8 b;

	de_dbg_indent_save(c, &saved_indent_level);
	ver = psd_getu32zz(zz);
	de_dbg(c, "version: %d", (int)ver);
	if(ver!=16) {
		de_err(c, "Unsupported Action format version: %d", (int)ver);
		goto done;
	}

	s = ucstring_create(c);
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "action set name: \"%s\"", ucstring_getpsz_d(s));

	b = psd_getbytezz(zz);
	de_dbg(c, "set-is-expanded: %d", (int)b);

	num_actions = psd_getu32zz(zz);
	de_dbg(c, "number of actions: %d", (int)num_actions);

	for(action_idx=0; action_idx<num_actions; action_idx++) {
		if(zz_avail(zz)<1) goto done;
		zz_init(&czz, zz);
		de_dbg(c, "action[%d] at %d", (int)action_idx, (int)zz->pos);
		de_dbg_indent(c, 1);
		if(!do_one_action(c, d, &czz)) goto done;
		zz->pos += zz_used(&czz);
		de_dbg_indent(c, -1);
	}

done:
	de_dbg_indent_restore(c, saved_indent_level);
	ucstring_destroy(s);
}

// Call this after setting d->version.
static void init_version_specific_info(deark *c, lctx *d)
{
	if(d->version==2) { // PSB format
		d->intsize_2or4 = 4;
		d->intsize_4or8 = 8;
	}
	else { // Regular PSD format
		d->intsize_2or4 = 2;
		d->intsize_4or8 = 4;
	}

	// The PSD spec does not say what encoding these strings use.
	// Some sources say they use MacRoman, and *some* PSD files do use MacRoman.
	// But other PSD files use other encodings, and I don't know how to know what
	// encoding they use.
	d->input_encoding = de_get_input_encoding(c, NULL, DE_ENCODING_MACROMAN);

	d->jpeg_rbswap_mode = 1;
}

static int do_psd_header(deark *c, lctx *d, i64 pos)
{
	int retval = 0;

	de_dbg(c, "header at %d", (int)pos);
	de_dbg_indent(c, 1);
	d->version = (int)psd_getu16(pos+4);
	de_dbg(c, "PSD version: %d", d->version);
	init_version_specific_info(c, d);

	if(d->version==1) {
		de_declare_fmt(c, "PSD");
	}
	else if(d->version==2) {
		de_declare_fmt(c, "PSB");
	}
	else {
		de_err(c, "Unsupported PSD version: %d", (int)d->version);
		goto done;
	}

	d->main_iinfo->num_channels = psd_getu16(pos+12);
	de_dbg(c, "number of channels: %d", (int)d->main_iinfo->num_channels);

	d->main_iinfo->height = psd_getu32(pos+14);
	d->main_iinfo->width = psd_getu32(pos+18);
	de_dbg_dimensions(c, d->main_iinfo->width, d->main_iinfo->height);

	d->main_iinfo->bits_per_channel = psd_getu16(pos+22);
	de_dbg(c, "bits/channel: %d", (int)d->main_iinfo->bits_per_channel);

	d->main_iinfo->color_mode = psd_getu16(pos+24);
	de_dbg(c, "color mode: %d (%s)", (int)d->main_iinfo->color_mode,
		get_colormode_name(d->main_iinfo->color_mode));

	retval = 1;

done:
	de_dbg_indent(c, -1);
	return retval;
}

static void do_external_tagged_blocks(deark *c, lctx *d, zztype *zz)
{
	u32 code;

	d->tagged_blocks_only = 1;
	if(zz_avail(zz)<4) return;

	// Evidently, it is possible for this to use little-endian byte order. Weird.

	// Peek at the first 4 bytes
	code = (u32)de_getu32le(0);
	if(code==CODE_8BIM || code==CODE_8B64) {
		d->is_le = 1;
	}

	do_tagged_blocks(c, d, zz, 0);
}

static void do_psd_color_mode_data(deark *c, lctx *d, zztype *zz)
{
	i64 len;
	i64 k;
	u8 r, g, b;
	struct image_info *iinfo = d->main_iinfo;

	len = zz_avail(zz);
	de_dbg(c, "color data at %d, len=%d", (int)zz->pos, (int)len);
	iinfo->pal_entries = len/3;
	if(iinfo->pal_entries<1) return;
	if(iinfo->pal_entries>256) iinfo->pal_entries=256;

	de_dbg_indent(c, 1);
	for(k=0; k<iinfo->pal_entries; k++) {
		r = de_getbyte(zz->pos + k);
		g = de_getbyte(zz->pos + iinfo->pal_entries + k);
		b = de_getbyte(zz->pos + 2*iinfo->pal_entries + k);
		iinfo->pal[k] = DE_MAKE_RGB(r, g, b);
		de_dbg_pal_entry(c, k, iinfo->pal[k]);
	}
	de_dbg_indent(c, -1);
}

static u8 scale_float_to_255(double x)
{
	if(x<=0.0) return 0;
	if(x>=1.0) return 255;
	return (u8)(0.5+x*255.0);
}

// Extract the primary image
static void do_bitmap(deark *c, lctx *d, const struct image_info *iinfo, dbuf *f,
	i64 pos, i64 len)
{
	de_bitmap *img = NULL;
	de_finfo *fi = NULL;
	i64 i, j, plane;
	i64 nplanes = 0; // Number of planes to read. May be less than d->num_channels.
	i64 planespan, rowspan, samplespan;
	u8 b;

	if(!de_good_image_dimensions(c, iinfo->width, iinfo->height)) goto done;

	if(iinfo->color_mode==PSD_CM_BITMAP && iinfo->bits_per_channel==1 &&
		iinfo->num_channels==1)
	{
		de_convert_and_write_image_bilevel(f, 0, iinfo->width, iinfo->height,
			(iinfo->width+7)/8, DE_CVTF_WHITEISZERO, NULL, 0);
		goto done;
	}

	if(iinfo->bits_per_channel!=8 && iinfo->bits_per_channel!=16 &&
		iinfo->bits_per_channel!=32)
	{
		de_err(c, "Unsupported bits/channel: %d", (int)iinfo->bits_per_channel);
		goto done;
	}

	if(iinfo->color_mode==PSD_CM_GRAY && iinfo->num_channels>=1) {
		nplanes = 1;
	}
	else if(iinfo->color_mode==PSD_CM_PALETTE && iinfo->num_channels>=1 && iinfo->bits_per_channel==8) {
		nplanes = 1;
	}
	else if(iinfo->color_mode==PSD_CM_RGB && iinfo->num_channels>=3) {
		nplanes = 3;
	}
	else {
		de_err(c, "This type of image is not supported (color=%d, "
			"num channels=%d, bits/channel=%d)",
			(int)iinfo->color_mode, (int)iinfo->num_channels, (int)iinfo->bits_per_channel);
		goto done;
	}

	img = de_bitmap_create(c, iinfo->width, iinfo->height,
		iinfo->color_mode==PSD_CM_GRAY ? 1 : 3);

	fi = de_finfo_create(c);

	if(iinfo->density.code!=DE_DENSITY_UNKNOWN) {
		fi->density = iinfo->density;
	}

	samplespan = iinfo->bits_per_channel/8;
	rowspan = iinfo->width * samplespan;
	planespan = iinfo->height * rowspan;

	for(plane=0; plane<nplanes; plane++) {
		for(j=0; j<iinfo->height; j++) {
			for(i=0; i<iinfo->width; i++) {
				if(iinfo->bits_per_channel==32) {
					// TODO: The format of 32-bit samples does not seem to be documented.
					// This is little more than a guess.
					double tmpd;
					tmpd = dbuf_getfloat32x(f, pos + plane*planespan + j*rowspan + i*samplespan, d->is_le);
					b = scale_float_to_255(tmpd);
				}
				else {
					b = dbuf_getbyte(f, pos + plane*planespan + j*rowspan + i*samplespan);
				}
				if(iinfo->color_mode==PSD_CM_RGB) {
					de_bitmap_setsample(img, i, j, plane, b);
				}
				else if(iinfo->color_mode==PSD_CM_GRAY) {
					de_bitmap_setpixel_gray(img, i, j, b);
				}
				else if(iinfo->color_mode==PSD_CM_PALETTE) {
					de_bitmap_setpixel_rgb(img, i, j, iinfo->pal[(unsigned int)b]);
				}
			}
		}
	}

	de_bitmap_write_to_file_finfo(img, fi, 0);
done:
	de_bitmap_destroy(img);
	de_finfo_destroy(c, fi);
}

static void do_bitmap_packbits(deark *c, lctx *d, zztype *zz, const struct image_info *iinfo)
{
	dbuf *unc_pixels = NULL;
	i64 cmpr_data_size = 0;
	i64 k;

	// Data begins with a table of row byte counts.
	de_dbg(c, "row sizes table at %"I64_FMT", len=%d", zz->pos,
		(int)(iinfo->num_channels * iinfo->height * d->intsize_2or4));

	for(k=0; k < iinfo->num_channels * iinfo->height; k++) {
		if(d->intsize_2or4==4) {
			cmpr_data_size += psd_getu32zz(zz);
		}
		else {
			cmpr_data_size += psd_getu16zz(zz);
		}
	}

	de_dbg(c, "compressed data at %"I64_FMT", len=%"I64_FMT"", zz->pos, cmpr_data_size);
	if(zz->pos + cmpr_data_size>c->infile->len) {
		de_err(c, "Unexpected end of file");
		goto done;
	}

	unc_pixels = dbuf_create_membuf(c, 1024, 0);
	de_fmtutil_decompress_packbits(c->infile, zz->pos, cmpr_data_size, unc_pixels, NULL);
	zz->pos += cmpr_data_size;
	de_dbg_indent(c, 1);
	de_dbg(c, "decompressed %"I64_FMT" bytes to %"I64_FMT"", cmpr_data_size, unc_pixels->len);
	de_dbg_indent(c, -1);
	do_bitmap(c, d, iinfo, unc_pixels, 0, unc_pixels->len);

done:
	dbuf_close(unc_pixels);
}

static void do_image_data(deark *c, lctx *d, zztype *zz)
{
	i64 cmpr;
	i64 len;
	i64 image_data_size;
	zztype czz;

	len = zz_avail(zz);
	if(len<2) return;
	de_dbg(c, "image data section at %d, expected len=%d", (int)zz->pos, (int)len);
	de_dbg_indent(c, 1);
	cmpr = psd_getu16zz(zz);
	dbg_print_compression_method(c, d, cmpr);

	image_data_size = zz_avail(zz);

	if(c->extract_policy == DE_EXTRACTPOLICY_AUXONLY) goto done;

	// Copy the global density info (from Resources section, presumably) to the image info
	d->main_iinfo->density = d->density;

	if(cmpr==0) { // Uncompressed
		do_bitmap(c, d, d->main_iinfo, c->infile, zz->pos, image_data_size);
	}
	else if(cmpr==1) { // PackBits
		zz_init(&czz, zz);
		do_bitmap_packbits(c, d, &czz, d->main_iinfo);
		zz->pos += zz_used(&czz);
	}
	else {
		de_err(c, "Compression method not supported: %d", (int)cmpr);
	}

done:
	de_dbg_indent(c, -1);
}

static void de_run_psd(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 x;
	zztype *zz = NULL;
	zztype czz;
	int whattodo = 0;

	d = de_malloc(c, sizeof(lctx));
	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	if(de_havemodcode(c, mparams, 'R')) {
		whattodo = 'R';
	}
	else if(de_havemodcode(c, mparams, 'T')) {
		whattodo = 'T';
	}
	else if(de_havemodcode(c, mparams, 'B')) {
		whattodo = 'B';
	}
	else if(!dbuf_memcmp(c->infile, 0, "8BIM", 4)) {
		// Assume this is a raw resources file (maybe extracted from an
		// .8bimtiff file)
		whattodo = 'R';
	}

	if(whattodo=='R') { // Image resources
		de_declare_fmt(c, "Photoshop resources");
		d->version = 1;
		init_version_specific_info(c, d);
		do_image_resource_blocks(c, d, zz);
		if(mparams) {
			// .out_params.flags: 0x02: has_iptc
			mparams->out_params.flags = 0;
			if(d->has_iptc) mparams->out_params.flags |= 0x02;
		}
		goto done;
	}
	else if(whattodo=='T') { // Tagged blocks
		d->version = 1;
		init_version_specific_info(c, d);
		do_external_tagged_blocks(c, d, zz);
		goto done;
	}
	else if(whattodo=='B') { // Tagged blocks, PSB-format
		d->version = 2;
		init_version_specific_info(c, d);
		do_external_tagged_blocks(c, d, zz);
		goto done;
	}

	d->main_iinfo = de_malloc(c, sizeof(struct image_info));

	if(!do_psd_header(c, d, zz->pos)) goto done;
	zz->pos += 26;

	de_dbg(c, "color mode data section at %d", (int)zz->pos);
	de_dbg_indent(c, 1);
	x = psd_getu32zz(zz);
	zz_init_with_len(&czz, zz, x);
	do_psd_color_mode_data(c, d, &czz);
	zz->pos += x;
	de_dbg_indent(c, -1);

	de_dbg(c, "image resources section at %d", (int)zz->pos);
	de_dbg_indent(c, 1);
	x = psd_getu32zz(zz); // Length of Image Resources
	// The PSD spec is ambiguous, but in practice the "length" field's value
	// does not include the size of the "length" field itself.
	de_dbg(c, "image resources data at %d, len=%d", (int)zz->pos, (int)x);

	if(x>0) {
		if(de_get_ext_option_bool(c, "extract8bim", 0)) {
			de_fmtutil_handle_photoshop_rsrc(c, c->infile, zz->pos, x, 0x1);
		}
		else {
			de_dbg_indent(c, 1);
			zz_init_with_len(&czz, zz, x);
			do_image_resource_blocks(c, d, &czz);
			de_dbg_indent(c, -1);
		}
	}
	zz->pos += x;
	de_dbg_indent(c, -1);

	zz_init(&czz, zz);
	if(!do_layer_and_mask_info_section(c, d, &czz)) goto done;
	zz->pos += zz_used(&czz);

	zz_init(&czz, zz);
	do_image_data(c, d, &czz);

done:
	de_free(c, zz);
	if(d) {
		de_free(c, d->main_iinfo);
		de_free(c, d);
	}
}

static void de_run_ps_action(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;

	de_declare_fmt(c, "Photoshop Action");

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	do_action_set(c, d, zz);

	de_free(c, zz);
	de_free(c, d);
}

static void de_run_ps_gradient(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;
	i64 grd_ver;

	de_declare_fmt(c, "Photoshop Gradient");

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	zz->pos += 4; // 8BGR signature
	grd_ver = psd_getu16zz(zz);
	de_dbg(c, "file version: %d", (int)grd_ver);

	if(grd_ver==5) {
		read_descriptor(c, d, zz, 1, "");
	}
	else {
		de_err(c, "Unsupported Photoshop Gradient file version: %d", (int)grd_ver);
	}

	de_free(c, zz);
	de_free(c, d);
}

// .asl format, "Patterns" object
static void do_asl_patterns(deark *c, lctx *d, zztype *zz)
{
	i64 pat_ver;
	i64 patseq_len;
	zztype czz_patseq;

	de_dbg(c, "patterns at %d", (int)zz->pos);
	de_dbg_indent(c, 1);
	pat_ver = psd_getu16zz(zz);
	de_dbg(c, "patterns version: %d", (int)pat_ver);
	patseq_len = psd_getu32zz(zz);
	de_dbg(c, "patterns total length: %d", (int)patseq_len);

	// Sequence of patterns
	zz_init_with_len(&czz_patseq, zz, patseq_len);

	do_pattern_sequence(c, d, &czz_patseq);

	zz->pos += patseq_len;

	de_dbg_indent(c, -1);
}

// .asl format, "Styles" object
static void do_asl_patterns_and_styles(deark *c, lctx *d, zztype *zz)
{
	zztype czz;
	i64 num_styles;
	i64 style_idx;
	i64 style_len;

	zz->pos += 4; // 8BSL signature

	zz_init(&czz, zz);
	do_asl_patterns(c, d, &czz);
	zz->pos += zz_used(&czz);

	de_dbg(c, "styles at %d", (int)zz->pos);
	de_dbg_indent(c, 1);

	num_styles = psd_getu32zz(zz);
	de_dbg(c, "number of styles: %d", (int)num_styles);

	for(style_idx=0; style_idx<=num_styles; style_idx++) {
		if(zz_avail(zz)<4) break;

		de_dbg(c, "style[%d] at %d", (int)style_idx, (int)zz->pos);
		de_dbg_indent(c, 1);

		style_len = psd_getu32zz(zz);
		de_dbg(c, "style length: %d", (int)style_len);

		zz_init_with_len(&czz, zz, style_len);
		read_descriptor(c, d, &czz, 1, " (for style identification)");
		read_descriptor(c, d, &czz, 1, " (for style information)");

		zz->pos += style_len;
		de_dbg_indent(c, -1);
	}

	de_dbg_indent(c, -1);
}

static void de_run_ps_styles(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;
	i64 asl_ver;

	de_declare_fmt(c, "Photoshop Styles");

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	asl_ver = psd_getu16zz(zz);
	de_dbg(c, "file version: %d", (int)asl_ver);
	if(asl_ver!=2) {
		de_err(c, "Unsupported Photoshop Styles file version: %d", (int)asl_ver);
		goto done;
	}

	do_asl_patterns_and_styles(c, d, zz);

done:
	de_free(c, zz);
	de_free(c, d);
}

static void do_abr_v1(deark *c, lctx *d, zztype *zz)
{
	i64 num_brushes;
	i64 i;

	zz->pos += 2;
	num_brushes = psd_getu16zz(zz);
	de_dbg(c, "number of brushes: %d", (int)num_brushes);

	for(i=0; i<num_brushes; i++) {
		i64 brushtype;
		i64 bdeflen;

		if(zz->pos >= zz->endpos) break;

		de_dbg(c, "brush definition[%d] at %d", (int)i, (int)zz->pos);
		de_dbg_indent(c, 1);

		brushtype = psd_getu16zz(zz);
		de_dbg(c, "brush type: %d", (int)brushtype);
		bdeflen = psd_getu32zz(zz);
		de_dbg(c, "brush definition data dpos=%d, dlen=%d", (int)zz->pos, (int)bdeflen);

		zz->pos += bdeflen;

		de_dbg_indent(c, -1);
	}

}

static void do_abr_v6(deark *c, lctx *d, zztype *zz)
{
	u32 sig;
	zztype czz;

	zz->pos += 4; // Version numbers(?), already read
	sig = (u32)psd_getu32(zz->pos);
	if(sig!=CODE_8BIM) {
		de_err(c, "Bad signature or unsupported Brush format");
		goto done;
	}

	zz_init(&czz, zz);
	do_tagged_blocks(c, d, &czz, 2);

done:
	;
}

static void de_run_ps_brush(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;
	int has_8bim_sig;

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	d->abr_major_ver = (int)psd_getu16(0);
	de_dbg(c, "file version: %d", (int)d->abr_major_ver);

	has_8bim_sig = (psd_getu32(4) == CODE_8BIM);

	if(has_8bim_sig && d->abr_major_ver>=3) {
		d->abr_minor_ver = (int)psd_getu16(2);
		de_declare_fmt(c, "Photoshop Brush (new format)");
		do_abr_v6(c, d, zz);
	}
	else if(d->abr_major_ver<=5) {
		de_declare_fmt(c, "Photoshop Brush (old format)");
		do_abr_v1(c, d, zz);
	}
	else {
		de_err(c, "Unsupported Photoshop Brush format (version=%d)", (int)d->abr_major_ver);
		goto done;
	}

done:
	de_free(c, zz);
	de_free(c, d);
}

static void do_custom_shape(deark *c, lctx *d, zztype *zz)
{
	de_ucstring *s = NULL;
	i64 dlen;
	i64 saved_pos;
	zztype datazz;
	zztype pathinfozz;

	s = ucstring_create(c);
	saved_pos = zz->pos;
	read_unicode_string(c, d, s, zz);
	de_dbg(c, "name: \"%s\"", ucstring_getpsz_d(s));
	// This Unicode String is padded to a multiple of 4 bytes, unlike pretty much
	// every other Unicode String in every Photoshop format.
	zz->pos = saved_pos + de_pad_to_4(zz->pos - saved_pos);

	zz->pos += 4; // Unknown field

	dlen = psd_getu32zz(zz);
	de_dbg(c, "shape data length: %d", (int)dlen);

	zz_init_with_len(&datazz, zz, dlen);
	// We expect this length to be a multiple of 4. I don't know what to do if
	// it's not.
	zz->pos += dlen;

	ucstring_empty(s);
	read_pascal_string_to_ucstring(c, d, s, &datazz);
	de_dbg(c, "id: \"%s\"", ucstring_getpsz(s));

	read_rectangle_tlbr(c, d, &datazz, "bounds");

	de_dbg(c, "path records at %d", (int)datazz.pos);
	zz_init(&pathinfozz, &datazz);
	de_dbg_indent(c, 1);
	do_pathinfo(c, d, &pathinfozz);
	de_dbg_indent(c, -1);

	ucstring_destroy(s);
}

static void de_run_ps_csh(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;
	i64 csh_ver;
	i64 num_shapes;
	i64 i;
	zztype czz;

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	zz->pos += 4; // Skip over 'cush' signature

	csh_ver = psd_getu32zz(zz);
	de_dbg(c, "file version: %d", (int)csh_ver);

	if(csh_ver!=2) {
		de_warn(c, "CSH v%d format might not be supported correctly", (int)csh_ver);
	}

	num_shapes = psd_getu32zz(zz);
	de_dbg(c, "number of shapes: %d", (int)num_shapes);

	for(i=0; i<num_shapes; i++) {
		if(zz_avail(zz)<28) break;
		de_dbg(c, "shape[%d] at %d", (int)i, (int)zz->pos);
		zz_init(&czz, zz);
		de_dbg_indent(c, 1);
		do_custom_shape(c, d, &czz);
		de_dbg_indent(c, -1);
		zz->pos += zz_used(&czz);
	}

	de_free(c, zz);
	de_free(c, d);
}

static void de_run_ps_pattern(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	zztype *zz = NULL;
	i64 pat_ver;
	i64 num_patterns;
	i64 i;
	zztype czz;

	d = de_malloc(c, sizeof(lctx));
	d->version = 1;
	init_version_specific_info(c, d);

	zz = de_malloc(c, sizeof(zztype));
	zz_init_absolute(zz, 0, c->infile->len);

	zz->pos += 4; // Skip over '8BPT' signature

	pat_ver = psd_getu16zz(zz);
	de_dbg(c, "file version: %d", (int)pat_ver);

	if(pat_ver!=1) {
		de_warn(c, "PAT v%d format might not be supported correctly", (int)pat_ver);
	}

	num_patterns = psd_getu32zz(zz);
	de_dbg(c, "number of patterns: %d", (int)num_patterns);

	for(i=0; i<num_patterns; i++) {
		if(zz_avail(zz)<4) break;
		de_dbg(c, "pattern[%d] at %d", (int)i, (int)zz->pos);
		zz_init(&czz, zz);
		de_dbg_indent(c, 1);
		if(!do_pattern_internal(c, d, &czz)) break;
		de_dbg_indent(c, -1);
		zz->pos += zz_used(&czz);
	}

	de_free(c, zz);
	de_free(c, d);
}

static int de_identify_psd(deark *c)
{
	u8 buf[4];

	de_read(buf, 0, 4);
	if(!de_memcmp(buf, "8BPS", 4)) return 100;
	if(!de_memcmp(buf, "8BIM", 4)) {
		// We sometimes write .8bim files, so we want to identify them.
		// This is not necessarily a standard file format.
		if(de_input_file_has_ext(c, "8bim")) return 100;
		return 75;
	}
	return 0;
}

void de_module_psd(deark *c, struct deark_module_info *mi)
{
	mi->id = "psd";
	mi->desc = "Photoshop PSD";
	mi->run_fn = de_run_psd;
	mi->identify_fn = de_identify_psd;
}

static int de_identify_ps_action(deark *c)
{
	int ver=0;

	if(!dbuf_memcmp(c->infile, 0, "\x00\x00\x00\x10\x00\x00", 6)) {
		ver = 16;
	}
	else if(!dbuf_memcmp(c->infile, 0, "\x00\x00\x00\x0c", 4)) {
		ver = 12;
	}
	if(ver==0) return 0;
	if(!de_input_file_has_ext(c, "atn")) return 0;
	if(ver==16) return 100;
	return 5; // A version we don't support
}

void de_module_ps_action(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_action";
	mi->desc = "Photoshop Action";
	mi->run_fn = de_run_ps_action;
	mi->identify_fn = de_identify_ps_action;
}

static int de_identify_ps_gradient(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "8BGR", 4)) {
		if(de_input_file_has_ext(c, "grd")) return 100;
		return 90;
	}
	return 0;
}

void de_module_ps_gradient(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_gradient";
	mi->desc = "Photoshop Gradient";
	mi->run_fn = de_run_ps_gradient;
	mi->identify_fn = de_identify_ps_gradient;
}

static int de_identify_ps_styles(deark *c)
{
	if(!dbuf_memcmp(c->infile, 2, "8BSL", 4)) {
		if(de_input_file_has_ext(c, "asl")) return 100;
		return 90;
	}
	return 0;
}

void de_module_ps_styles(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_styles";
	mi->desc = "Photoshop Styles";
	mi->run_fn = de_run_ps_styles;
	mi->identify_fn = de_identify_ps_styles;
}

static int de_identify_ps_brush(deark *c)
{
	i64 ver;

	ver = de_getu16be(0);
	if(ver==1 || ver==2 || ver==6 || ver==7) {
		if(de_input_file_has_ext(c, "abr")) return 80;
	}
	return 0;
}

void de_module_ps_brush(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_brush";
	mi->desc = "Photoshop Brush";
	mi->run_fn = de_run_ps_brush;
	mi->identify_fn = de_identify_ps_brush;
}

static int de_identify_ps_csh(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "cush", 4)) {
		if(de_input_file_has_ext(c, "csh")) return 100;
		return 80;
	}
	return 0;
}

void de_module_ps_csh(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_csh";
	mi->desc = "Photoshop Custom Shape";
	mi->run_fn = de_run_ps_csh;
	mi->identify_fn = de_identify_ps_csh;
}

static int de_identify_ps_pattern(deark *c)
{
	if(!dbuf_memcmp(c->infile, 0, "8BPT", 4)) {
		if(de_input_file_has_ext(c, "pat")) return 100;
		return 90;
	}
	return 0;
}

void de_module_ps_pattern(deark *c, struct deark_module_info *mi)
{
	mi->id = "ps_pattern";
	mi->desc = "Photoshop Pattern";
	mi->run_fn = de_run_ps_pattern;
	mi->identify_fn = de_identify_ps_pattern;
}
