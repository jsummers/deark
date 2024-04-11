// See readme-dskdcmps.txt for more information about this file.
// Modifications for Deark are Copyright (C) 2021 Jason Summers, and have the
// same terms of use as the main part of Deark.
// Alternatively, at your option, the modifications for Deark may be treated
// as public domain.

// Intro from the original software:

//*******************************************************************
//
// program - dskdcmps.c
// purpose - test decompression of dsk files
//
//
// LZW decompression - no warranties expressed or implied
// Note that this code was mainly a test to see if it could
// be done, and to understand how dsk files were compressed
// and if in turn they could be decompressed without creating
// diskettes (the entire reason for dskxtrct).
//
// Also note that there is some of confusion over the status of the
// patent for the LZW decompression algorithm. You use this code
// at your own risk.
//
//*******************************************************************

//#define PgmTitle "dskdcmps"
//#define PgmVersion "1.0 (08/01/2000)"

//#define DD_EXTRADBG
#define DD_MAXSTRLEN 4096
#define DD_MAXTABLE 4096

struct dd_codet {
	u16 hold;
	int j;
	u16 oldcode, oldest, newest;
	u16 older[DD_MAXTABLE], newer[DD_MAXTABLE];
	u16 charlink[DD_MAXTABLE]; // parent?
	int usecount[DD_MAXTABLE]; // How many other codes depend on this code?
	UI size[DD_MAXTABLE];
	u8 valfirst[DD_MAXTABLE];
	u8 value[DD_MAXTABLE];
};

struct dd_Ctl {
	deark *c;
	const char *modname;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	i64 code_counter;
	i64 inf_pos;
	i64 inf_endpos;
	i64 nbytes_written;
	int eof_flag;
	int err_flag;
	u8 valbuf[DD_MAXTABLE];
	char msg[DD_MAXSTRLEN];
};

//*******************************************************************
static void dd_tmsg(struct dd_Ctl *Ctl, const char *fmt, ...)
	de_gnuc_attribute ((format (printf, 2, 3)));

static void dd_tmsg(struct dd_Ctl *Ctl, const char *fmt, ...)
{
	va_list ap;

	if (Ctl->c->debug_level<3) return;

	va_start(ap, fmt);
	de_vsnprintf(Ctl->msg, sizeof(Ctl->msg), fmt, ap);
	va_end(ap);

	de_dbg(Ctl->c, "%s", Ctl->msg);
}

//*******************************************************************

#ifdef DD_EXTRADBG

static void dd_dumpstate(struct dd_Ctl *Ctl, struct dd_codet * ct)
{
	size_t i;
	dbuf *dmpf = NULL;
	FILE *f; // copy of dmpf->fp; do not close
	char filename[100];

	de_snprintf(filename, sizeof(filename), "ddump%07"I64_FMT".tmp", Ctl->code_counter);
	dmpf = dbuf_create_unmanaged_file(Ctl->c, filename, DE_OVERWRITEMODE_DEFAULT, 0);
	f = dmpf->fp;

	fprintf(f, "codes processed: %u\n", (UI)Ctl->code_counter);
	fprintf(f, "code olde newe clin uc siz\n");
	for(i=0; i<4096; i++) {
		fprintf(f, "%4u %4u %4u %4u %2u %4u", (UI)i,
			(UI)ct->older[i], (UI)ct->newer[i],
			(UI)ct->charlink[i],
			(UI)ct->usecount[i],
			(UI)ct->size[i]);

		if(ct->size[i]==1) {
			fprintf(f, " %02x", (UI)ct->value[i]);
		}
		else if(ct->size[i]==2) {
			fprintf(f, " %02x %02x", (UI)ct->valfirst[i], (UI)ct->value[i]);
		}
		else if(ct->size[i]>2) {
			fprintf(f, " %02x...%02x", (UI)ct->valfirst[i], (UI)ct->value[i]);
		}

		if(i==(size_t)ct->oldcode) fprintf(f, " OLDCODE");
		if(i==(size_t)ct->oldest) fprintf(f, " oldest");
		if(i==(size_t)ct->newest) fprintf(f, " newest");

		fprintf(f, "\n");
	}

	dbuf_close(dmpf);
}

#endif

//*******************************************************************
static void dd_ValidateLinkChains (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	u16 tnewer, tolder;
	UI errcode = 0;

	if(Ctl->c->debug_level<3) return;
	tnewer = ct->newer[tcode];
	tolder = ct->older[tcode];
	if (tcode == ct->newest) {
		if (tnewer != 0) {
			errcode += 1;
		}
	}
	else {
		if (ct->older[tnewer] != tcode) {
			errcode += 2;
		}
	}
	if (tcode == ct->oldest) {
		if (tolder != 0) {
			errcode += 4;
		}
	}
	else {
		if (ct->newer[tolder] != tcode) {
			errcode += 8;
		}
	}

	if(errcode) {
		dd_tmsg(Ctl, "Link validation error (%u). tcode: %4x, older: %4x, newer: %4x",
			errcode, tcode, tolder, ct->newer[tolder]);
	}
}

//*******************************************************************
static void dd_OutputString(struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	size_t i;
	size_t valbuf_pos = DD_MAXTABLE;
	u16 curcode = tcode;

	if(ct->size[tcode]<1 || ct->size[tcode]>DD_MAXTABLE-256) {
		Ctl->err_flag = 1;
		goto done;
	}

	for(i=0; i<(size_t)ct->size[tcode]; i++) {
		if(curcode>=DD_MAXTABLE || curcode<1) {
			Ctl->err_flag = 1;
			goto done;
		}

		if(ct->size[curcode] != ct->size[tcode]-i) {
			Ctl->err_flag = 1;
			goto done;
		}

		valbuf_pos--;
		Ctl->valbuf[valbuf_pos] = ct->value[curcode];

		// Traverse the tree, back toward the root codes.
		curcode = ct->charlink[curcode];
	}

	dbuf_write(Ctl->dcmpro->f, &Ctl->valbuf[valbuf_pos], ct->size[tcode]);
	Ctl->nbytes_written += (i64)ct->size[tcode];

done:
	;
}

//*******************************************************************
static u16 dd_GetNextcode (struct dd_Ctl *Ctl, struct dd_codet * ct)
{
	u16 code;

	if(Ctl->inf_pos >= Ctl->inf_endpos) {
		Ctl->eof_flag = 1;
		return 0;
	}

	if (ct->j) {
		code = (u16)dbuf_getbyte_p(Ctl->dcmpri->f, &Ctl->inf_pos) << 4;
		ct->hold = (u16)dbuf_getbyte_p(Ctl->dcmpri->f, &Ctl->inf_pos);
		code |= (ct->hold >> 4);
	}
	else {
		code = (ct->hold & 0x0f) << 8;
		code |= (u16)dbuf_getbyte_p(Ctl->dcmpri->f, &Ctl->inf_pos);
		ct->hold = 0;
	}
	ct->j = !ct->j;
	return (code);
}

//*******************************************************************
static struct dd_codet * dd_DInit (struct dd_Ctl *Ctl)
{
	struct dd_codet * ct;
	u16 code;

	ct = (struct dd_codet *) de_malloc(Ctl->c, sizeof(struct dd_codet));
	for (code = 1; code <= 256; code++) {
		ct->valfirst[code] = (u8)(code-1);
		ct->value[code] = (u8)(code-1);
		ct->size[code] = 1;
		// Maybe this is set to 1 just to prevent it from ever getting down
		// to 0. So it doesn't get re-used.
		ct->usecount[code] = 1;
	}
	for (code = 257; code <= 4095; code++) {
		if(code<4095) {
			ct->newer[code] = code + 1;
		}
		if(code>257) {
			ct->older[code] = code - 1;
		}
	}
	ct->oldest = 257;
	ct->newest = 4095;
	ct->j = 1;
	ct->oldcode = 0;
	ct->hold = 0;
	return (ct);
}

static void dd_DFree(struct dd_Ctl *Ctl, struct dd_codet *ct)
{
	if(!ct) return;
	de_free(Ctl->c, ct);
}

//*******************************************************************
static void dd_AddMRU (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	if (ct->usecount[tcode] != 0) {
		dd_tmsg(Ctl, "Usecount not zero in AddMRU, code: %4x", tcode);
	}
	ct->newer[ct->newest] = tcode;
	ct->older[tcode] = ct->newest;
	ct->newer[tcode] = 0;
	ct->newest = tcode;
}

//*******************************************************************
static void dd_UnlinkCode (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	u16 tnewer, tolder;

	dd_ValidateLinkChains(Ctl, ct, ct->oldest);
	tnewer = ct->newer[tcode];
	tolder = ct->older[tcode];
	if (tcode == ct->newest)
		ct->newest = tolder;
	else
		ct->older[tnewer] = tolder;
	if (tcode == ct->oldest)
		ct->oldest = tnewer;
	else
		ct->newer[tolder] = tnewer;
	ct->older[tcode] = ct->newer[tcode] = 0;
}

//*******************************************************************
static u16 dd_GetLRU (struct dd_Ctl *Ctl, struct dd_codet * ct)
{
	u16 tcode, xcode;

	dd_ValidateLinkChains(Ctl, ct, ct->oldest);
	tcode = ct->oldest;
	if (ct->usecount[tcode] != 0) {
		dd_tmsg(Ctl, "Usecount not zero in GetLRU, code: %4x", tcode);
	}
	xcode = ct->charlink[tcode];
	dd_UnlinkCode (Ctl, ct, tcode);

	if (xcode != 0) {
		ct->usecount[xcode] --;
		if (ct->usecount[xcode] == 0) {
			dd_AddMRU (Ctl, ct, xcode);
		}
	}

	return (tcode);
}

//*******************************************************************
static void dd_ReserveEntry (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	if (ct->usecount[tcode] > 0) {
		ct->usecount[tcode] ++;
	}
	else {
		dd_UnlinkCode(Ctl, ct, tcode);
		ct->usecount[tcode] = 1;
	}
}

//*******************************************************************
static void dd_BuildEntry (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 newcode)
{
	u16 lruentry, tcode;
	int old_codesize;
	int new_codesize;
	u8 *codestr = NULL;

	lruentry = dd_GetLRU(Ctl, ct);
	old_codesize = ct->size[ct->oldcode];
	if(old_codesize<1) {
		Ctl->err_flag = 1;
		goto done;
	}
	new_codesize = old_codesize + 1;
	if(new_codesize > DD_MAXTABLE) {
		Ctl->err_flag = 1;
		goto done;
	}

	if (newcode != lruentry) {
		tcode = newcode;
	}
	else {
		tcode = ct->oldcode;
	}

	ct->valfirst[lruentry] = ct->valfirst[ct->oldcode];
	ct->value[lruentry] = ct->valfirst[tcode];

	ct->size[lruentry] = new_codesize;
	ct->charlink[lruentry] = ct->oldcode;
	dd_ReserveEntry(Ctl, ct, ct->oldcode);
	ct->usecount[lruentry] = 0;
	dd_AddMRU (Ctl, ct, lruentry);

done:
	if(codestr) {
		de_free(Ctl->c, codestr);
	}
}

//*******************************************************************
static void dd_Decompress (struct dd_Ctl *Ctl)
{
	struct dd_codet * ct;
	u16 newcode;

	ct = dd_DInit(Ctl);

	while(1) {
		newcode = dd_GetNextcode(Ctl, ct);
		if(Ctl->c->debug_level>=3) {
			de_dbg(Ctl->c, "%"I64_FMT" [i%"I64_FMT"/o%"I64_FMT"] code=%u oc=%u",
				Ctl->code_counter,
				Ctl->inf_pos, Ctl->nbytes_written,
				(UI)newcode, (UI)ct->oldcode);
		}
		if(newcode==0 || Ctl->eof_flag || Ctl->err_flag) break;
		if (ct->oldcode > 0)
			dd_BuildEntry(Ctl, ct, newcode);
		if(Ctl->err_flag) break;
		dd_OutputString(Ctl, ct, newcode);
		ct->oldcode = newcode;
		Ctl->code_counter++;
	}

	if(Ctl->err_flag) {
		de_dfilter_set_errorf(Ctl->c, Ctl->dres, Ctl->modname, "Bad compressed data");
	}
	dd_DFree(Ctl, ct);
}

static void dskdcmps_run(deark *c, struct de_dfilter_in_params *dcmpri,
	struct de_dfilter_out_params *dcmpro, struct de_dfilter_results *dres)
{
	struct dd_Ctl *Ctl = NULL;

	Ctl = de_malloc(c, sizeof(struct dd_Ctl));
	Ctl->c = c;
	Ctl->modname = "ibmlzw";
	Ctl->dcmpri = dcmpri;
	Ctl->dcmpro = dcmpro;
	Ctl->dres = dres;
	Ctl->inf_pos = dcmpri->pos;
	Ctl->inf_endpos = dcmpri->pos + dcmpri->len;

	dd_Decompress(Ctl);

	de_free(c, Ctl);
}
