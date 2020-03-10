// This file is part of Deark.
// Copyright (C) 2019-2020 Jason Summers
// See the file COPYING for terms of use.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-fmtutil.h"

#define DE_MACFORMAT_RAW          0
#define DE_MACFORMAT_APPLESINGLE  1
#define DE_MACFORMAT_APPLEDOUBLE  2
#define DE_MACFORMAT_MACBINARY    3

// advfile is a uniform way to handle multi-fork files (e.g. classic Mac files
// with a resource fork), and files with platform-specific metadata that we
// might want to do something special with (e.g. Mac type/creator codes).
// It is essentially a wrapper around dbuf/finfo.

// de_advfile_create creates a new object.
// Then, before calling de_advfile_run, caller must:
//  - Set advf->filename if possible, e.g. using ucstring_append_*().
//  - Set advf->original_filename_flag, if appropriate. Note that this annotates the
//    ->filename field, and is not related to de_advfile_set_orig_filename().
//  - Set advf->snflags, if needed.
//  - Set advf->createflags, if needed (unlikely to be).
//  - Set advf->mainfork.fork_exists, if there is a main fork.
//  - Set advf->mainfork.fork_len, if there is a main fork. advfile cannot be
//    used if the fork lengths are not known in advance.
//  - Set advf->rsrcfork.fork_exists, if there is an rsrc fork.
//  - Set advf->rsrcfork.fork_len, if there is an rsrc fork.
//  - Set advf->mainfork.mod_time, if known, even if there is no main fork. Mac
//    files do not use advf->rsrcfork.mod_time.
//  - (Same for advf->mainfork.create_time, etc.)
//  - If appropriate, set other fields potentially advf->mainfork.fi and/or
//    advf->rsrcfork.fi, such as ->is_directory. But verify that they work
//    as expected.
struct de_advfile *de_advfile_create(deark *c)
{
	struct de_advfile *advf = NULL;

	advf = de_malloc(c, sizeof(struct de_advfile));
	advf->c = c;
	advf->filename = ucstring_create(c);
	advf->mainfork.fi = de_finfo_create(c);
	advf->rsrcfork.fi = de_finfo_create(c);
	return advf;
}

void de_advfile_destroy(struct de_advfile *advf)
{
	deark *c;

	if(!advf) return;
	c = advf->c;
	ucstring_destroy(advf->filename);
	de_finfo_destroy(c, advf->mainfork.fi);
	de_finfo_destroy(c, advf->rsrcfork.fi);
	de_free(c, advf->orig_filename);
	de_free(c, advf);
}

// Set the original untranslated filename, as an array of bytes of indeterminate
// encoding (most likely MacRoman).
// We can't necessarily decode this filename correctly, but we can copy it
// unchanged to AppleSingle/AppleDouble's "Real Name" field.
void de_advfile_set_orig_filename(struct de_advfile *advf, const char *fn, size_t fnlen)
{
	deark *c = advf->c;

	if(advf->orig_filename) {
		de_free(c, advf->orig_filename);
		advf->orig_filename = NULL;
	}

	if(fnlen<1) return;
	advf->orig_filename_len = fnlen;
	if(advf->orig_filename_len>1024)
		advf->orig_filename_len = 1024;
	advf->orig_filename = de_malloc(c, advf->orig_filename_len);
	de_memcpy(advf->orig_filename, fn, advf->orig_filename_len);

	if(advf->orig_filename[0]<32) {
		// This is to ensure that our applesd module won't incorrectly guess that
		// this is a Pascal string.
		advf->orig_filename[0] = '_';
	}
}

static void setup_rsrc_finfo(struct de_advfile *advf)
{
	deark *c = advf->c;
	de_ucstring *fname_rsrc = NULL;

	fname_rsrc = ucstring_create(c);
	ucstring_append_ucstring(fname_rsrc, advf->filename);
	if(fname_rsrc->len<1) {
		ucstring_append_sz(fname_rsrc, "_", DE_ENCODING_LATIN1);
	}
	ucstring_append_sz(fname_rsrc, ".rsrc", DE_ENCODING_LATIN1);
	de_finfo_set_name_from_ucstring(c, advf->rsrcfork.fi, fname_rsrc, advf->snflags);
	advf->rsrcfork.fi->original_filename_flag = advf->original_filename_flag;

	ucstring_destroy(fname_rsrc);
}

// If is_appledouble is set, do not write the resource fork (it will be handled
// in another way), and *always* write a main fork (even if we have to write a
// 0-length file).
static void de_advfile_run_rawfiles(deark *c, struct de_advfile *advf, int is_appledouble)
{
	struct de_advfile_cbparams *afp_main = NULL;
	struct de_advfile_cbparams *afp_rsrc = NULL;

	if(advf->mainfork.fork_exists || is_appledouble) {
		if(!advf->mainfork.fork_exists) {
			advf->mainfork.fork_len = 0;
		}
		afp_main = de_malloc(c, sizeof(struct de_advfile_cbparams));
		afp_main->whattodo = DE_ADVFILE_WRITEMAIN;
		de_finfo_set_name_from_ucstring(c, advf->mainfork.fi, advf->filename, advf->snflags);
		advf->mainfork.fi->original_filename_flag = advf->original_filename_flag;
		afp_main->outf = dbuf_create_output_file(c, NULL, advf->mainfork.fi, advf->createflags);
		dbuf_set_writelistener(afp_main->outf, advf->mainfork.writelistener_cb,
			advf->mainfork.userdata_for_writelistener);
		if(advf->writefork_cbfn && advf->mainfork.fork_len>0) {
			advf->writefork_cbfn(c, advf, afp_main);
		}
		dbuf_close(afp_main->outf);
		afp_main->outf = NULL;
	}
	if(!is_appledouble && advf->rsrcfork.fork_exists && advf->rsrcfork.fork_len>0) {
		afp_rsrc = de_malloc(c, sizeof(struct de_advfile_cbparams));
		setup_rsrc_finfo(advf);
		afp_rsrc->whattodo = DE_ADVFILE_WRITERSRC;
		// Note: It is intentional to use mainfork in the next line.
		advf->rsrcfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY] = advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY];
		afp_rsrc->outf = dbuf_create_output_file(c, NULL, advf->rsrcfork.fi, advf->createflags);
		dbuf_set_writelistener(afp_rsrc->outf, advf->rsrcfork.writelistener_cb,
			advf->rsrcfork.userdata_for_writelistener);
		if(advf->writefork_cbfn) {
			advf->writefork_cbfn(c, advf, afp_rsrc);
		}
		dbuf_close(afp_rsrc->outf);
		afp_rsrc->outf = NULL;
	}

	de_free(c, afp_main);
	de_free(c, afp_rsrc);
}

struct applesd_entry {
	unsigned int id;
	i64 offset;
	i64 len;
};

#define SDID_DATAFORK 1
#define SDID_RESOURCEFORK 2
#define SDID_REALNAME 3
#define SDID_COMMENT 4
#define SDID_FILEDATES 8
#define SDID_FINDERINFO 9

#define INVALID_APPLESD_DATE ((i64)(-0x80000000LL))

static i64 timestamp_to_applesd_date(deark *c, struct de_timestamp *ts)
{
	i64 t;

	if(!ts->is_valid) return INVALID_APPLESD_DATE;
	t = de_timestamp_to_unix_time(ts);
	t -= (365*30 + 7)*86400;
	if(t>0x7fffffffLL || t<-0x7fffffffLL) return INVALID_APPLESD_DATE;
	return t;
}

// If is_appledouble is set, do not write the data fork (it will be handled
// in another way).
static void de_advfile_run_applesd(deark *c, struct de_advfile *advf, int is_appledouble)
{
	de_ucstring *fname = NULL;
	struct de_advfile_cbparams *afp_main = NULL;
	struct de_advfile_cbparams *afp_rsrc = NULL;
	dbuf *outf = NULL;
	i64 cur_data_pos;
	size_t num_entries = 0;
	size_t k;
	char commentstr[80];
	size_t comment_strlen;
	struct applesd_entry entry_info[16];

	fname = ucstring_create(c);
	ucstring_append_ucstring(fname, advf->filename);
	if(fname->len<1) {
		ucstring_append_sz(fname, "_", DE_ENCODING_LATIN1);
	}
	if(is_appledouble) {
		// TODO: Consider using "._" prefix when writing to ZIP/tar
		ucstring_append_sz(fname, ".adf", DE_ENCODING_LATIN1);
	}
	else {
		ucstring_append_sz(fname, ".as", DE_ENCODING_LATIN1);
	}
	de_finfo_set_name_from_ucstring(c, advf->mainfork.fi, fname, advf->snflags);
	advf->mainfork.fi->original_filename_flag = advf->original_filename_flag;
	outf = dbuf_create_output_file(c, NULL, advf->mainfork.fi, advf->createflags);

	if(is_appledouble) { // signature
		dbuf_writeu32be(outf, 0x00051607U);
	}
	else {
		dbuf_writeu32be(outf, 0x00051600U);
	}
	dbuf_writeu32be(outf, 0x00020000U); // version
	dbuf_write_zeroes(outf, 16); // filler

	// Decide what entries we will write, and in what order, and their data length.

	de_snprintf(commentstr, sizeof(commentstr), "Apple%s container generated by Deark",
		is_appledouble?"Double":"Single");
	comment_strlen = de_strlen(commentstr);

	if(advf->orig_filename) {
		entry_info[num_entries].id = SDID_REALNAME;
		entry_info[num_entries].len = (i64)advf->orig_filename_len;
		num_entries++;
	}

	entry_info[num_entries].id = SDID_COMMENT;
	entry_info[num_entries].len = (i64)comment_strlen;
	num_entries++;

	if(advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY].is_valid) {
		entry_info[num_entries].id = SDID_FILEDATES;
		entry_info[num_entries].len = 16;
		num_entries++;
	}
	if((advf->has_typecode || advf->has_creatorcode || advf->has_finderflags) &&
		!advf->mainfork.fi->is_directory)
	{
		entry_info[num_entries].id = SDID_FINDERINFO;
		entry_info[num_entries].len = 32;
		num_entries++;
	}
	if(advf->rsrcfork.fork_exists) {
		entry_info[num_entries].id = SDID_RESOURCEFORK;
		entry_info[num_entries].len = advf->rsrcfork.fork_len;
		num_entries++;
	};
	if(advf->mainfork.fork_exists && !is_appledouble) {
		entry_info[num_entries].id = SDID_DATAFORK;
		entry_info[num_entries].len = advf->mainfork.fork_len;
		num_entries++;
	};

	dbuf_writeu16be(outf, (i64)num_entries);

	// Figure out where the each data element will be written.
	cur_data_pos = 26 + 12*(i64)num_entries;
	for(k=0; k<num_entries; k++) {
		entry_info[k].offset = cur_data_pos;
		cur_data_pos += entry_info[k].len;
	};

	// Write the element table
	for(k=0; k<num_entries; k++) {
		dbuf_writeu32be(outf, (i64)entry_info[k].id);
		if(entry_info[k].offset>0xffffffffLL || entry_info[k].len>0xffffffffLL) {
			de_err(c, "File too large to write to AppleSingle/AppleDouble format");
			goto done;
		}
		dbuf_writeu32be(outf, entry_info[k].offset);
		dbuf_writeu32be(outf, entry_info[k].len);
	}

	// Write the elements' data
	for(k=0; k<num_entries; k++) {
		switch(entry_info[k].id) {
		case SDID_DATAFORK:
			afp_main = de_malloc(c, sizeof(struct de_advfile_cbparams));
			afp_main->whattodo = DE_ADVFILE_WRITEMAIN;
			dbuf_set_writelistener(outf, advf->mainfork.writelistener_cb,
				advf->mainfork.userdata_for_writelistener);
			afp_main->outf = outf;
			if(advf->writefork_cbfn && advf->mainfork.fork_len>0) {
				advf->writefork_cbfn(c, advf, afp_main);
			}
			dbuf_set_writelistener(outf, NULL, NULL);
			break;

		case SDID_RESOURCEFORK:
			afp_rsrc = de_malloc(c, sizeof(struct de_advfile_cbparams));
			afp_rsrc->whattodo = DE_ADVFILE_WRITERSRC;
			dbuf_set_writelistener(outf, advf->rsrcfork.writelistener_cb,
				advf->rsrcfork.userdata_for_writelistener);
			afp_rsrc->outf = outf;
			if(advf->writefork_cbfn && advf->rsrcfork.fork_len>0) {
				advf->writefork_cbfn(c, advf, afp_rsrc);
			}
			dbuf_set_writelistener(outf, NULL, NULL);
			break;

		case SDID_REALNAME:
			// If you think this code might be wrong, first review the comments
			// in applesd.c regarding Pascal strings.
			dbuf_write(outf, advf->orig_filename, (i64)advf->orig_filename_len);
			break;

		case SDID_COMMENT:
			dbuf_write(outf, (const u8*)commentstr, (i64)comment_strlen);
			break;

		case SDID_FILEDATES:
			// We could try to maintain dates other than the modification date, but
			// Deark doesn't generally care about them.
			dbuf_writei32be(outf, timestamp_to_applesd_date(c, &advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE]));
			dbuf_writei32be(outf, timestamp_to_applesd_date(c, &advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY]));
			dbuf_writei32be(outf, timestamp_to_applesd_date(c, &advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_BACKUP]));
			dbuf_writei32be(outf, timestamp_to_applesd_date(c, &advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_ACCESS]));
			break;

		case SDID_FINDERINFO:
			if(advf->has_typecode)
				dbuf_write(outf, advf->typecode, 4);
			else
				dbuf_write_zeroes(outf, 4);
			if(advf->has_creatorcode)
				dbuf_write(outf, advf->creatorcode, 4);
			else
				dbuf_write_zeroes(outf, 4);
			dbuf_writeu16be(outf, advf->has_finderflags?((i64)advf->finderflags):0);
			dbuf_write_zeroes(outf, 6 + 16);
			break;
		}

		// In case something went wrong, try to make sure we're at the expected
		// file position.
		// Note: This might not compensate for all failures, as dbuf_truncate
		// might not be fully implemented for this output type.
		dbuf_truncate(outf, entry_info[k].offset + entry_info[k].len);
	}

done:
	dbuf_close(outf);
	de_free(c, afp_main);
	de_free(c, afp_rsrc);
	ucstring_destroy(fname);
}

static i64 timestamp_to_mac_time(const struct de_timestamp *ts)
{
	i64 t;

	if(!ts->is_valid) return 0;
	t = de_timestamp_to_unix_time(ts);
	return t + 2082844800;
}

static void de_advfile_run_macbinary(deark *c, struct de_advfile *advf)
{
	struct de_advfile_cbparams *afp_main = NULL;
	struct de_advfile_cbparams *afp_rsrc = NULL;
	dbuf *outf = NULL;
	de_ucstring *fname = NULL;
	i64 main_amt_padding, rsrc_amt_padding;
	i64 main_fork_len, rsrc_fork_len;
	dbuf *hdr = NULL;
	struct de_crcobj *crco = NULL;
	u32 crc_calc;

	if(advf->mainfork.fork_exists) {
		main_fork_len = advf->mainfork.fork_len;
	}
	else {
		main_fork_len = 0;
	}
	if(advf->rsrcfork.fork_exists) {
		rsrc_fork_len = advf->rsrcfork.fork_len;
	}
	else {
		rsrc_fork_len = 0;
	}

	if(main_fork_len>0xffffffffLL || rsrc_fork_len>0xffffffffLL) {
		de_err(c, "File too large to write to MacBinary format");
		goto done;
	}

	main_amt_padding = advf->mainfork.fork_len % 128;
	if(main_amt_padding > 0) main_amt_padding = 128-main_amt_padding;
	rsrc_amt_padding = advf->rsrcfork.fork_len % 128;
	if(rsrc_amt_padding > 0) rsrc_amt_padding = 128-rsrc_amt_padding;

	fname = ucstring_create(c);
	ucstring_append_ucstring(fname, advf->filename);
	if(fname->len<1) {
		ucstring_append_sz(fname, "_", DE_ENCODING_LATIN1);
	}
	ucstring_append_sz(fname, ".bin", DE_ENCODING_LATIN1);
	de_finfo_set_name_from_ucstring(c, advf->mainfork.fi, fname, advf->snflags);
	advf->mainfork.fi->original_filename_flag = advf->original_filename_flag;

	// Construct 128-byte header
	hdr = dbuf_create_membuf(c, 128, 0);
	dbuf_writebyte(hdr, 0);

	// Filename
	if(advf->orig_filename && advf->orig_filename_len>0) {
		i64 fnlen = advf->orig_filename_len;

		if(fnlen>63) fnlen=63;
		dbuf_writebyte(hdr, (u8)fnlen);
		dbuf_write(hdr, advf->orig_filename, fnlen);
	}
	else {
		// TODO: Get the name from elsewhere?
		dbuf_writebyte(hdr, 7);
		dbuf_puts(hdr, "Unnamed");
	}
	dbuf_truncate(hdr, 65);

	// type/creator
	if(advf->has_typecode) {
		dbuf_write(hdr, advf->typecode, 4);
	}
	dbuf_truncate(hdr, 69);
	if(advf->has_creatorcode) {
		dbuf_write(hdr, advf->creatorcode, 4);
	}

	dbuf_truncate(hdr, 73); // high byte of finder flags
	if(advf->has_finderflags) {
		dbuf_writebyte(hdr, (u8)(advf->finderflags >> 8));
	}

	dbuf_truncate(hdr, 83);
	dbuf_writeu32be(hdr, main_fork_len);
	dbuf_writeu32be(hdr, rsrc_fork_len);

	dbuf_truncate(hdr, 91);
	dbuf_writeu32be(hdr, timestamp_to_mac_time(&advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_CREATE]));
	dbuf_writeu32be(hdr, timestamp_to_mac_time(&advf->mainfork.fi->timestamp[DE_TIMESTAMPIDX_MODIFY]));

	dbuf_truncate(hdr, 101); // low byte of finder flags
	if(advf->has_finderflags) {
		dbuf_writebyte(hdr, (u8)(advf->finderflags & 0xff));
	}

	dbuf_truncate(hdr, 102);
	dbuf_write(hdr, (const u8*)"mBIN", 4);

	dbuf_truncate(hdr, 122);
	dbuf_writebyte(hdr, 130); // version (III)
	dbuf_writebyte(hdr, 129); // compatible version (II)

	crco = de_crcobj_create(c, DE_CRCOBJ_CRC16_CCITT);
	de_crcobj_addslice(crco, hdr, 0, 124);
	crc_calc = de_crcobj_getval(crco);
	dbuf_writeu16be(hdr, (i64)crc_calc);

	dbuf_truncate(hdr, 128);
	outf = dbuf_create_output_file(c, NULL, advf->mainfork.fi, advf->createflags);
	dbuf_copy(hdr, 0, 128, outf);

	afp_main = de_malloc(c, sizeof(struct de_advfile_cbparams));
	afp_rsrc = de_malloc(c, sizeof(struct de_advfile_cbparams));
	afp_main->whattodo = DE_ADVFILE_WRITEMAIN;
	afp_rsrc->whattodo = DE_ADVFILE_WRITERSRC;

	dbuf_set_writelistener(outf, advf->mainfork.writelistener_cb,
		advf->mainfork.userdata_for_writelistener);
	afp_main->outf = outf;
	if(advf->writefork_cbfn && main_fork_len>0) {
		advf->writefork_cbfn(c, advf, afp_main);
	}
	dbuf_set_writelistener(outf, NULL, NULL);
	dbuf_write_zeroes(outf, main_amt_padding);

	dbuf_set_writelistener(outf, advf->rsrcfork.writelistener_cb,
		advf->rsrcfork.userdata_for_writelistener);
	afp_rsrc->outf = outf;
	if(advf->writefork_cbfn && rsrc_fork_len>0) {
		advf->writefork_cbfn(c, advf, afp_rsrc);
	}
	dbuf_set_writelistener(outf, NULL, NULL);

done:
	dbuf_close(hdr);
	dbuf_close(outf);
	de_free(c, afp_main);
	de_free(c, afp_rsrc);
	ucstring_destroy(fname);
	de_crcobj_destroy(crco);
}

void de_advfile_run(struct de_advfile *advf)
{
	deark *c = advf->c;
	int is_mac_file;
	int fmt;

	is_mac_file = (advf->rsrcfork.fork_exists && advf->rsrcfork.fork_len>0);

	if(is_mac_file && !c->macformat_known) {
		const char *mfmt;

		c->macformat_known = 1;
		c->macformat = DE_MACFORMAT_APPLEDOUBLE;

		// [I know there is a module named "macrsrc", so this could lead to confusion,
		// but I can't think of a better name.]
		mfmt = de_get_ext_option(c, "macrsrc");
		if(mfmt) {
			if(!de_strcmp(mfmt, "raw")) {
				c->macformat = DE_MACFORMAT_RAW; // Raw resource file
			}
			else if(!de_strcmp(mfmt, "as")) {
				c->macformat = DE_MACFORMAT_APPLESINGLE;
			}
			else if(!de_strcmp(mfmt, "ad")) {
				c->macformat = DE_MACFORMAT_APPLEDOUBLE;
			}
			else if(!de_strcmp(mfmt, "mbin")) {
				c->macformat = DE_MACFORMAT_MACBINARY;
			}
		}
	}

	fmt = c->macformat; // Default to the default Mac format.
	if(fmt==DE_MACFORMAT_APPLESINGLE && advf->no_applesingle) fmt = DE_MACFORMAT_APPLEDOUBLE;
	if(fmt==DE_MACFORMAT_APPLEDOUBLE && advf->no_appledouble) fmt = DE_MACFORMAT_RAW;

	if(is_mac_file && fmt==DE_MACFORMAT_APPLESINGLE) {
		de_advfile_run_applesd(c, advf, 0);
	}
	else if(is_mac_file && fmt==DE_MACFORMAT_APPLEDOUBLE) {
		int extract_dfork = 0;
		int extract_rfork = 0;

		if(advf->mainfork.fork_exists && advf->mainfork.fork_len>0) {
			extract_dfork = 1;
		}
		if(advf->rsrcfork.fork_exists && advf->rsrcfork.fork_len>0) {
			extract_rfork = 1;
		}
		if(!extract_dfork && !extract_rfork) {
			extract_dfork = 1;
		}

		if(extract_dfork) {
			de_advfile_run_rawfiles(c, advf, 1); // For the data/main fork
		}
		if(extract_rfork) {
			de_advfile_run_applesd(c, advf, 1); // For the rsrc fork
		}
	}
	else if(is_mac_file && fmt==DE_MACFORMAT_MACBINARY) {
		de_advfile_run_macbinary(c, advf);
	}
	else {
		de_advfile_run_rawfiles(c, advf, 0);
	}
}
