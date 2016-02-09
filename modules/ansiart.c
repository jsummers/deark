// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// ANSI art
// (very incomplete)

#include <deark-config.h>
#include <deark-modules.h>
#include "fmtutil.h"

static const de_uint32 ansi_palette[16] = {
	0x000000,0xaa0000,0x00aa00,0xaa5500,0x0000aa,0xaa00aa,0x00aaaa,0xaaaaaa,
	0x555555,0xff5555,0x55ff55,0xffff55,0x5555ff,0xff55ff,0x55ffff,0xffffff
};

#define MAX_ROWS       5000
#define DEFAULT_BGCOL  0
#define DEFAULT_FGCOL  7

struct parse_results_struct {
	int num_params;
#define MAX_ESC_PARAMS 16
	de_int64 params[MAX_ESC_PARAMS];
};

typedef struct localctx_struct {
	de_byte always_disable_blink;

	struct de_char_screen *screen;

	de_int64 effective_file_size;
	de_int64 xpos, ypos; // 0-based
	de_int64 saved_xpos, saved_ypos;

	de_byte curr_fgcol;
	de_byte curr_bgcol;
	de_byte curr_bold;
	de_byte curr_underline;
	de_byte curr_blink;

#define ANSIART_MAX_WARNINGS 10
	de_int64 num_warnings;
	de_byte disable_blink_attr;
	de_byte support_9b_csi;

	de_byte param_string_buf[100];

	struct parse_results_struct parse_results;

	de_byte control_seq_seen[128];
} lctx;

static void init_cell(deark *c, struct de_char_cell *cell)
{
	cell->codepoint = 0x20;
	cell->codepoint_unicode = 0x20;
	cell->bgcol = DEFAULT_BGCOL;
	cell->fgcol = DEFAULT_FGCOL;
}

static void erase_cell(deark *c, struct de_char_cell *cell)
{
	if(!cell) return;
	de_memset(cell, 0, sizeof(struct de_char_cell));
	init_cell(c, cell);
}

static struct de_char_cell *get_cell_at(deark *c, struct de_char_screen *screen,
	de_int64 xpos, de_int64 ypos)
{
	de_int64 i;
	struct de_char_cell *cell;

	if(xpos<0 || ypos<0) return NULL;
	if(xpos>=screen->width || ypos>=MAX_ROWS) return NULL;
	if(!screen->cell_rows[ypos]) {
		screen->cell_rows[ypos] = de_malloc(c, screen->width * sizeof(struct de_char_cell));
		for(i=0; i<screen->width; i++) {
			// Initialize each new cell
			cell = &screen->cell_rows[ypos][i];
			init_cell(c, cell);
		}
	}
	return &(screen->cell_rows[ypos][xpos]);
}

static void do_normal_char(deark *c, lctx *d, de_int64 pos, de_byte ch)
{
	struct de_char_cell *cell;
	de_int32 u;

	if(ch==13) { // CR
		d->xpos = 0;
	}
	else if(ch==10) { // LF
		d->ypos++;
		// Some files aren't rendered correctly unless an LF implies a CR.
		d->xpos = 0;
	}
	else {
		u = de_char_to_unicode(c, (de_int32)ch, DE_ENCODING_CP437_G);

		cell = get_cell_at(c, d->screen, d->xpos, d->ypos);
		if(cell) {
			cell->codepoint = (de_int32)ch;
			cell->codepoint_unicode = u;
			cell->fgcol = d->curr_fgcol;
			cell->bold = d->curr_bold;
			cell->underline = d->curr_underline;
			cell->bgcol = d->curr_bgcol;

			if(d->disable_blink_attr || d->always_disable_blink) {
				// "blink" in this mode means intense-background, instead of blink.
				if(d->curr_blink)
					cell->bgcol |= 0x08;
				cell->blink = 0;
			}
			else {
				cell->blink = d->curr_blink;
			}

			if(d->ypos >= d->screen->height) d->screen->height = d->ypos+1;
		}
		else {
			if(d->num_warnings<ANSIART_MAX_WARNINGS) {
				de_warn(c, "Off-screen write (%d,%d) at %d\n",
					(int)(d->xpos+1), (int)(d->ypos+1), (int)pos);
				d->num_warnings++;
			}
		}

		d->xpos++;

		// Line wrap
		while(d->xpos >= d->screen->width) {
			d->xpos -= d->screen->width;
			d->ypos++;
		}
	}
}

// Convert d->param_string_buf to d->params and d->num_params.
static void parse_params(deark *c, lctx *d, de_int64 default_val, de_int64 offset)
{
	de_int64 buf_len;
	de_int64 ppos;
	de_int64 param_len;
	char *p_ptr;
	int last_param = 0;

	d->parse_results.num_params = 0;

	buf_len = de_strlen((const char*)d->param_string_buf);

	ppos = offset;
	while(1) {
		if(d->parse_results.num_params >= MAX_ESC_PARAMS) {
			break;
		}

		p_ptr = de_strchr((const char*)&d->param_string_buf[ppos], ';');
		if(p_ptr) {
			param_len = p_ptr - (char*)&d->param_string_buf[ppos];
		}
		else {
			param_len = buf_len - ppos;
			last_param = 1;
		}

		if(param_len>=1) {
			d->parse_results.params[d->parse_results.num_params] = de_atoi64((const char*)&d->param_string_buf[ppos]);
		}
		else {
			d->parse_results.params[d->parse_results.num_params] = default_val;
		}
		d->parse_results.num_params++;

		if(last_param) {
			break;
		}

		// Advance past the parameter data and the terminating semicolon.
		ppos += param_len + 1;
	}
}

static void read_one_int(deark *c, lctx *d, const de_byte *buf,
	de_int64 *a, de_int64 a_default)
{
	parse_params(c, d, a_default, 0);

	if(d->parse_results.num_params>=1) {
		*a = d->parse_results.params[0];
	}
	else {
		*a = a_default;
	}
}

// m - Select Graphic Rendition
static void do_code_m(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sgr_code;

	parse_params(c, d, 0, 0);

	for(i=0; i<d->parse_results.num_params; i++) {
		sgr_code = d->parse_results.params[i];

		if(sgr_code==0) {
			// Reset
			d->curr_bold = 0;
			d->curr_underline = 0;
			d->curr_blink = 0;
			d->curr_bgcol = DEFAULT_BGCOL;
			d->curr_fgcol = DEFAULT_FGCOL;
		}
		else if(sgr_code==1) {
			d->curr_bold = 1;
		}
		else if(sgr_code==4) {
			d->curr_underline = 1;
		}
		else if(sgr_code==5 || sgr_code==6) {
			d->curr_blink = 1;
		}
		else if(sgr_code>=30 && sgr_code<=37) {
			// Set foreground color
			d->curr_fgcol = (de_byte)(sgr_code-30);
		}
		else if(sgr_code>=40 && sgr_code<=47) {
			// Set background color
			d->curr_bgcol = (de_byte)(sgr_code-40);
		}
		else {
			de_warn(c, "Unsupported SGR code %d\n", (int)sgr_code);
		}
	}
}

// H: Set cursor position
static void do_code_H(deark *c, lctx *d)
{
	de_int64 row, col;

	parse_params(c, d, 1, 0);

	if(d->parse_results.num_params>=1) row = d->parse_results.params[0];
	else row = 1;

	if(d->parse_results.num_params>=2) col = d->parse_results.params[1];
	else col = 1;

	d->xpos = col-1;
	d->ypos = row-1;
}

// h: Mode settings
static void do_code_h(deark *c, lctx *d, de_int64 param_start)
{
	int ok=0;
	int is_DEC = 0;
	int i;

	if(d->param_string_buf[0]=='?') {
		is_DEC = 1; // "DEC private parameters"
	}

	parse_params(c, d, 0, is_DEC?1:0);

	for(i=0; i<d->parse_results.num_params; i++) {
		ok = 0;

		if(is_DEC) {
			switch(d->parse_results.params[i]) {
			case 7: // Set autowrap (default)
				ok = 1;
				break;
			case 33:
				d->disable_blink_attr = 1;
				ok = 1;
				break;
			}
		}
		else {
			switch(d->parse_results.params[i]) {
			case 7: // Set autowrap (default)
				// Some sources say it's Esc [?7h, and some say it's
				// Esc [7h. I'll assume both are okay.
				ok = 1;
				break;
			}
		}

		if(!ok && d->num_warnings<ANSIART_MAX_WARNINGS) {
			de_warn(c, "Unsupported 'h' control sequence '%s%d' at %d\n",
				is_DEC?"?":"", (int)d->parse_results.params[i], (int)param_start);
			d->num_warnings++;
		}
	}
}

// l: Turn off mode
static void do_code_l(deark *c, lctx *d, de_int64 param_start)
{
	int ok=0;
	int is_DEC = 0;
	int i;

	if(d->param_string_buf[0]=='?') {
		is_DEC = 1; // "DEC private parameters"
	}

	parse_params(c, d, 0, is_DEC?1:0);

	for(i=0; i<d->parse_results.num_params; i++) {
		ok = 0;

		if(is_DEC) {
			switch(d->parse_results.params[i]) {
			case 33:
				d->disable_blink_attr = 0;
				ok = 1;
				break;
			}
		}
		else {
			;
		}

		if(!ok && d->num_warnings<ANSIART_MAX_WARNINGS) {
			de_warn(c, "Unsupported 'l' control sequence '%s%d' at %d\n",
				is_DEC?"?":"", (int)d->parse_results.params[i], (int)param_start);
			d->num_warnings++;
		}
	}
}

// J: Clear screen
static void do_code_J(deark *c, lctx *d)
{
	de_int64 n;
	de_int64 i, j;

	read_one_int(c, d, d->param_string_buf, &n, 0);
	// 0 = clear from cursor to end of screen
	// 1 = clear from cursor to beginning of screen
	// 2 = clear screen

	for(j=0; j<d->screen->height; j++) {
		for(i=0; i<d->screen->width; i++) {
			if(n==0) {
				if(j<d->ypos) continue;
				if(j==d->ypos && i<d->xpos) continue;
			}
			else if(n==1) {
				if(j>d->ypos) continue;
				if(j==d->ypos && i>d->xpos) continue;
			}
			erase_cell(c, get_cell_at(c, d->screen, i, j));
		}
	}

	if(n==2) {
		d->xpos = 0;
		d->ypos = 0;
	}
}

// K: Clear line
static void do_code_K(deark *c, lctx *d)
{
	de_int64 n;
	de_int64 i;

	read_one_int(c, d, d->param_string_buf, &n, 0);
	// 0 = clear cursor to end of line
	// 1 = clear from start of line to cursor
	// 2 = clear entire line

	// TODO: This line clearing logic may not be exactly correct.

	for(i=0; i<d->screen->width; i++) {
		if(n==0) {
			if(i<d->xpos) continue;
		}
		else if(n==1) {
			if(i>d->xpos) continue;
		}
		erase_cell(c, get_cell_at(c, d->screen, i, d->ypos));
	}
}

// A: Up
static void do_code_A(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->ypos -= n;
}

// B: Down
static void do_code_B(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->ypos += n;
}

// C: Forward
static void do_code_C(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->xpos += n;
}

// D: Back
static void do_code_D(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->xpos -= n;
	// Some files begin with a code to move the cursor left by a large amount.
	// So I assume that (by default) this isn't supposed to wrap, and positions
	// left of the first column aren't allowed.
	if(d->xpos<0) d->xpos=0;
}

static void do_control_sequence(deark *c, lctx *d, de_byte code,
	de_int64 param_start, de_int64 param_len)
{
	if(code>=128) return;

	if(c->debug_level>=2) {
		de_dbg2(c, "[(%2d,%d) %c at %d %d]\n", (int)(d->xpos+1), (int)(d->ypos+1),
			(char)code, (int)param_start, (int)param_len);
	}

	if(param_len > (de_int64)(sizeof(d->param_string_buf)-1)) {
		de_warn(c, "Ignoring long escape sequence (len %d at %d)\n",
			(int)param_len, (int)param_start);
		goto done;
	}

	de_read(d->param_string_buf, param_start, param_len);
	d->param_string_buf[param_len] = '\0';

	switch(code) {
	case 'A': do_code_A(c, d); break;
	case 'B': do_code_B(c, d); break;
	case 'C': do_code_C(c, d); break;
	case 'D': do_code_D(c, d); break;
	case 'H': do_code_H(c, d); break;
	case 'h': do_code_h(c, d, param_start); break;
	case 'J': do_code_J(c, d); break;
	case 'K': do_code_K(c, d); break;
	case 'l': do_code_l(c, d, param_start); break;
	case 'm': do_code_m(c, d); break;
	case 's':
		d->saved_xpos = d->xpos;
		d->saved_ypos = d->ypos;
		break;
	case 'u':
		d->xpos = d->saved_xpos;
		d->ypos = d->saved_ypos;
		break;
	default:
		if(!d->control_seq_seen[(unsigned int)code]) {
			if(code>=0x70 && code<=0x7e) {
				// "Bit combinations 07/00 to 07/14 are available as final bytes
				// of control sequences for private use" -- ECMA 48
				de_warn(c, "Unsupported private-use control sequence '%c' at %d\n",
					(char)code, (int)param_start);
			}
			else {
				de_warn(c, "Unsupported control sequence '%c' at %d\n",
					(char)code, (int)param_start);
			}
		}
	}

done:
	d->control_seq_seen[(unsigned int)code] = 1;
}

static void do_main(deark *c, lctx *d)
{
	de_int64 pos;
	de_int64 params_start_pos = 0;
#define STATE_NORMAL 0
#define STATE_GOT_ESC 1
#define STATE_READING_PARAM 2
	int state;
	de_byte ch;

	d->xpos = 0; d->ypos = 0;
	d->curr_bgcol = DEFAULT_BGCOL;
	d->curr_fgcol = DEFAULT_FGCOL;
	state = STATE_NORMAL;

	for(pos=0; pos<d->effective_file_size; pos++) {
		ch = de_getbyte(pos);

		if(pos==0 && ch==0x9b) {
			// 0x9b can sometimes mean the same thing as Esc [, but it could
			// also be a printable character. I don't know how to tell the
			// difference, but I'll assume that if the file starts with 0x9b,
			// it is a control character.
			d->support_9b_csi = 1;
		}

		if(state==STATE_NORMAL) {
			if(ch==0x1b) { // ESC
				state=STATE_GOT_ESC;
				continue;
			}
			else if(ch==0x9b && d->support_9b_csi) {
				state=STATE_READING_PARAM;
				params_start_pos = pos+1;
				continue;
			}
			else { // a non-escape character
				do_normal_char(c, d, pos, ch);
			}
		}
		else if(state==STATE_GOT_ESC) {
			if(ch=='[') {
				state=STATE_READING_PARAM;
				params_start_pos = pos+1;
				continue;
			}
			else if(ch>=64 && ch<=95) {
				// A 2-character escape sequence
				state=STATE_NORMAL;
				continue;
			}
		}
		else if(state==STATE_READING_PARAM) {
			// Control sequences end with a byte from 64-126
			if(ch>=64 && ch<=126) {
				do_control_sequence(c, d, ch, params_start_pos, pos-params_start_pos);
				state=STATE_NORMAL;
				continue;
			}
		}
	}
}

static void de_run_ansiart(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	de_int64 k;
	struct de_SAUCE_detection_data sdd;
	struct de_SAUCE_info *si = NULL;

	d = de_malloc(c, sizeof(lctx));

	d->effective_file_size = c->infile->len;

	charctx = de_malloc(c, sizeof(struct de_char_context));

	// Read SAUCE metadata, if present.
	de_memset(&sdd, 0, sizeof(struct de_SAUCE_detection_data));
	de_detect_SAUCE(c, c->infile, &sdd);

	if(sdd.has_SAUCE) {
		si = de_malloc(c, sizeof(struct de_SAUCE_info));
		if(de_read_SAUCE(c, c->infile, si)) {
			d->effective_file_size = si->original_file_size;

			if(si->tflags & 0x01) {
				d->always_disable_blink = 1;
			}
			if((si->tflags & 0x18)>>3 == 0x02) {
				// Square pixels requested
				charctx->no_density = 1;
			}
			if((si->tflags & 0x06)>>1 == 0x02) {
				charctx->prefer_9col_mode = 1;
			}
		}
	}

	// Ignore any Ctrl-Z at the end of data.
	if(de_getbyte(d->effective_file_size-1) == 0x1a) {
		de_dbg(c, "found Ctrl+Z byte at %d\n", (int)(d->effective_file_size-1));
		d->effective_file_size--;
	}
	if(d->effective_file_size!=c->infile->len) {
		de_dbg(c, "effective file size set to %d\n", (int)d->effective_file_size);
	}

	charctx->nscreens = 1;
	charctx->screens = de_malloc(c, charctx->nscreens*sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));

	d->screen = charctx->screens[0];

	if(si && si->width_in_chars>=40 && si->width_in_chars<=320) {
		// Use the width from SAUCE, if it's available and seems sensible.
		d->screen->width = si->width_in_chars;
	}
	else {
		// Otherwise, assume 80 characters per row.
		d->screen->width = 80;
	}
	// We don't know the height yet. This will be updated as we read the file.
	d->screen->height = 1;

	d->screen->cell_rows = de_malloc(c, MAX_ROWS * sizeof(struct de_char_cell*));

	do_main(c, d);

	for(k=0; k<16; k++) {
		charctx->pal[k] = ansi_palette[k];
	}

	if(si) {
		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
	}

	de_char_output_to_file(c, charctx);

	de_free_charctx(c, charctx);
	de_free_SAUCE(c, si);
	de_free(c, d);
}

static int de_identify_ansiart(deark *c)
{
	if(!c->detection_data.sauce.detection_attempted) {
		de_err(c, "ansiart internal");
		de_fatalerror(c);
	}

	if(!dbuf_memcmp(c->infile, 0, "\x04\x31\x2e\x34", 4)) {
		// Looks like iCEDraw format, which may use the same SAUCE identifiers
		// as ANSI Art, even though it is incompatible.
		return 0;
	}

	if(c->detection_data.sauce.has_SAUCE) {
		if(c->detection_data.sauce.data_type==1 &&
			c->detection_data.sauce.file_type==1)
		{
			// Unfortunately, iCEDraw and possibly other formats may use the
			// same SAUCE identifiers as ANSI Art, so we can't return 100.
			return 91;
		}
	}

	if(de_input_file_has_ext(c, "ans"))
		return 10;
	return 0;
}

void de_module_ansiart(deark *c, struct deark_module_info *mi)
{
	mi->id = "ansiart";
	mi->id_alias[0] = "ansi";
	mi->desc = "ANSI Art character graphics";
	mi->run_fn = de_run_ansiart;
	mi->identify_fn = de_identify_ansiart;
}
