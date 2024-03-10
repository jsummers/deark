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
#define dd_max(a,b) (((a) > (b)) ? (a) : (b))
#define dd_strlen(a) ((int)de_strlen(a))
#define DD_MAXSTRLEN 4096
#define DD_MAXTABLE 4096

struct dd_codet {
	u16 hold;
	int j;
	u16 oldcode, oldest, newest;
	u16 older[DD_MAXTABLE], newer[DD_MAXTABLE];
	u16 charlink[DD_MAXTABLE], charlast[DD_MAXTABLE], charfirst[DD_MAXTABLE];
	int used[DD_MAXTABLE], usecount[DD_MAXTABLE];
	int size[DD_MAXTABLE];
	u8 *code[DD_MAXTABLE]; // Points to .size[] malloc'd bytes
};

struct dd_Ctl {
	deark *c;
	const char *modname;
	struct de_dfilter_in_params *dcmpri;
	struct de_dfilter_out_params *dcmpro;
	struct de_dfilter_results *dres;
	i64 inf_pos;
	i64 inf_endpos;
	i64 nbytes_written;
	int eof_flag;
	int err_flag;
	char msg[DD_MAXSTRLEN];
#ifdef DD_EXTRADBG
	char work [DD_MAXSTRLEN], work2[DD_MAXSTRLEN], work3[DD_MAXSTRLEN];
#endif
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
static char *dd_right (char *target, char *source, int len)
{
	int i, tpos, slen;

	if (target == NULL)
		return NULL;
	if (source == NULL)
		target[0] = '\0';
	else {
		slen = dd_strlen(source);
		for (i = dd_max(0, slen - len), tpos = 0; i < slen; i++)
			target [tpos++] = source [i];
		target[tpos] = '\0';
	}
	return target;
}
#endif

//*******************************************************************
static void dd_PrintEntry (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	if (Ctl->c->debug_level<3) return;
	dd_tmsg(Ctl, "Entry code: %4x, usecount: %4x, clink: %4x, clast: %4x, cfirst: %4x",
			tcode, ct->usecount[tcode], ct->charlink[tcode], ct->charlast[tcode],
			ct->charfirst[tcode]);
	dd_tmsg(Ctl, "older: %4x, newer: %4x, used: %4d, size: %4d",
			ct->older[tcode], ct->newer[tcode], ct->used[tcode], ct->size[tcode]);
}

//*******************************************************************
static void dd_ValidateLinkChains (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	u16 tnewer, tolder;

	if(Ctl->c->debug_level<3) return;
	tnewer = ct->newer[tcode];
	tolder = ct->older[tcode];
	if (tcode == ct->newest) {
		if (tnewer != 0) {
			dd_tmsg(Ctl, "Newer code not zero. tcode: %4x, newer: %4x, older: %4x",
				tcode, tnewer, ct->older[tnewer]);
		}
	}
	else {
		if (ct->older[tnewer] != tcode) {
			dd_tmsg(Ctl, "Older code not linked. tcode: %4x, newer: %4x, older: %4x",
				tcode, tnewer, ct->older[tnewer]);
		}
	}
	if (tcode == ct->oldest) {
		if (tolder != 0) {
			dd_tmsg(Ctl, "Older code not zero. tcode: %4x, older: %4x, newer: %4x",
				tcode, tolder, ct->newer[tolder]);
		}
	}
	else {
		if (ct->newer[tolder] != tcode) {
			dd_tmsg(Ctl, "Newer code not linked. tcode: %4x, older: %4x, newer: %4x",
				tcode, tolder, ct->newer[tolder]);
		}
	}
}

//*******************************************************************
static void dd_OutputString(struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	dbuf_write(Ctl->dcmpro->f, (const u8*)ct->code[tcode], ct->size[tcode]);
	Ctl->nbytes_written += (i64)ct->size[tcode];
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
		ct->charlast[code] = code;
		ct->charfirst[code] = code;
		ct->code[code] = (u8 *) de_malloc(Ctl->c, 1);
		ct->code[code][0] = (u8)(code-1);
		ct->size[code] = 1;
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
	UI i;

	if(!ct) return;
	for(i=0; i<DD_MAXTABLE; i++) {
		if (ct->code[i] != NULL) {
			de_free(Ctl->c, ct->code[i]);
			ct->code[i] = NULL;
			ct->size[i] = 0;
		}
	}
	de_free(Ctl->c, ct);
}

//*******************************************************************
static void dd_AddMRU (struct dd_Ctl *Ctl, struct dd_codet * ct, u16 tcode)
{
	if (ct->usecount[tcode] != 0) {
		dd_tmsg(Ctl, "Usecount not zero in AddMRU, code: %4x", tcode);
		dd_PrintEntry(Ctl, ct, tcode);
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
		dd_PrintEntry(Ctl, ct, tcode);
	}
	xcode = ct->charlink[tcode];
	dd_UnlinkCode (Ctl, ct, tcode);

	if (xcode != 0) {
		ct->usecount[xcode] --;
		if (ct->usecount[xcode] == 0) {
			dd_AddMRU (Ctl, ct, xcode);
		}
	}

	if (ct->code[tcode] != NULL) {
		de_free(Ctl->c, ct->code[tcode]);
		ct->code[tcode] = NULL;
		ct->size[tcode] = 0;
	}

	ct->used[tcode] ++;
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
	if(old_codesize<1 || !ct->code[ct->oldcode]) {
		Ctl->err_flag = 1;
		goto done;
	}
	new_codesize = old_codesize + 1;
	if(new_codesize > DD_MAXTABLE) {
		Ctl->err_flag = 1;
		goto done;
	}
	// TODO?: This makes a huge total number of memory allocations (though only
	// about 4096 will be active at any given time). Maybe it should be rewritten
	// to not do that.
	codestr = (u8 *) de_malloc(Ctl->c, new_codesize);
	de_memcpy(codestr, ct->code[ct->oldcode], (size_t)old_codesize);
	if (newcode != lruentry) {
		tcode = newcode;
	}
	else {
		tcode = ct->oldcode;
	}
	if(!ct->code[tcode]) {
		Ctl->err_flag = 1;
		goto done;
	}
	codestr[new_codesize - 1] = ct->code[tcode][0];
	ct->code[lruentry] = codestr;
	codestr = NULL;
	ct->size[lruentry] = new_codesize;
	ct->charlink[lruentry] = ct->oldcode;
	ct->charfirst[lruentry] = ct->charfirst[ct->charlink[lruentry]];
	ct->charlast[lruentry] = tcode;
	dd_ReserveEntry(Ctl, ct, ct->oldcode);
	dd_AddMRU (Ctl, ct, lruentry);

#ifdef DD_EXTRADBG
	if(Ctl->c->debug_level<3) goto done;
	int test;
	de_strlcpy(Ctl->work, "", sizeof(Ctl->work));
	for (test = 0; test < new_codesize; test++) {
		de_snprintf(Ctl->work2, sizeof(Ctl->work2), "%2x", ct->code[lruentry][test]);
		dd_right(Ctl->work3, Ctl->work2, 2);
		strcat(Ctl->work, Ctl->work3);
	}
	dd_tmsg(Ctl, "offset: %4x, newcode: %4x. nused: %4x, lru: %4x, lused: %4x, size: %4d, str: %s",
		(UI)Ctl->inf_pos, newcode, ct->used[newcode], lruentry, ct->used[lruentry], new_codesize, Ctl->work);
#endif

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
			de_dbg(Ctl->c, "[i%"I64_FMT"/o%"I64_FMT"] code=%u oc=%u",
				Ctl->inf_pos, Ctl->nbytes_written,
				(UI)newcode, (UI)ct->oldcode);
		}
		if(newcode==0 || Ctl->eof_flag || Ctl->err_flag) break;
		if (ct->oldcode > 0)
			dd_BuildEntry(Ctl, ct, newcode);
		if(Ctl->err_flag) break;
		dd_OutputString(Ctl, ct, newcode);
		ct->oldcode = newcode;
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
