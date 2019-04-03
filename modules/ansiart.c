// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// ANSI art

#include <deark-config.h>
#include <deark-private.h>
#include <deark-fmtutil.h>
DE_DECLARE_MODULE(de_module_ansiart);

static const u32 ansi_palette[16] = {
	0x000000,0xaa0000,0x00aa00,0xaa5500,0x0000aa,0xaa00aa,0x00aaaa,0xaaaaaa,
	0x555555,0xff5555,0x55ff55,0xffff55,0x5555ff,0xff55ff,0x55ffff,0xffffff
};

#define MAX_ROWS       5000
#define DEFAULT_BGCOL  0
#define DEFAULT_FGCOL  7

struct parse_results_struct {
	int num_params;
#define MAX_ESC_PARAMS 16
	i64 params[MAX_ESC_PARAMS];
};

struct row_data_struct {
#define SIZEMODE_DEFAULT     0
#define SIZEMODE_DBLH_TOP    1
#define SIZEMODE_DBLH_BOTTOM 2
#define SIZEMODE_DBLW        3
	u8 size_mode;
};

typedef struct localctx_struct {
	int opt_disable_24bitcolor;
	int opt_disable_blink;

	u8 sauce_disable_blink;

	struct de_char_screen *screen;
	struct row_data_struct *row_data;

	i64 effective_file_size;
	i64 xpos, ypos; // 0-based
	i64 saved_xpos, saved_ypos;

	u32 curr_fgcol;
	u32 curr_bgcol;
	u8 curr_bold;
	u8 curr_underline;
	u8 curr_blink;
	u8 curr_negative;
	u8 curr_conceal;
	u8 curr_strikethru;

#define CHARSET_DEFAULT 0
#define CHARSET_US 1
#define CHARSET_UK 2
#define CHARSET_LINEDRAWING 3
	int curr_g0_charset;
	int curr_g1_charset;

	int curr_charset_index; // 0=use g0, 1=use g1

#define ANSIART_MAX_WARNINGS 10
	i64 num_warnings;
	u8 disable_blink_attr;
	u8 support_9b_csi;
	u8 vt100_mode;

	u8 param_string_buf[100];

	struct parse_results_struct parse_results;

	u8 escape_code_seen[96];
	u8 control_seq_seen[128];
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
	de_zeromem(cell, sizeof(struct de_char_cell));
	init_cell(c, cell);
}

static struct de_char_cell *get_cell_at(deark *c, struct de_char_screen *screen,
	i64 xpos, i64 ypos)
{
	i64 i;
	struct de_char_cell *cell;

	if(xpos<0 || ypos<0) return NULL;
	if(xpos>=screen->width || ypos>=MAX_ROWS) return NULL;
	if(!screen->cell_rows[ypos]) {
		screen->cell_rows[ypos] = de_mallocarray(c, screen->width, sizeof(struct de_char_cell));
		for(i=0; i<screen->width; i++) {
			// Initialize each new cell
			cell = &screen->cell_rows[ypos][i];
			init_cell(c, cell);
		}
	}
	return &(screen->cell_rows[ypos][xpos]);
}

static i32 ansi_char_to_unicode(deark *c, lctx *d, u8 ch)
{
	i32 u;
	int cs;

	if(d->curr_charset_index==0)
		cs = d->curr_g0_charset;
	else
		cs = d->curr_g1_charset;

	if(cs==CHARSET_LINEDRAWING) {
		if(ch>=95 && ch<=126) {
			u = de_char_to_unicode(c, (i32)ch, DE_ENCODING_DEC_SPECIAL_GRAPHICS);
			return u;
		}
	}
	else if(cs==CHARSET_UK) {
		// I think this is the only difference between the US and UK charsets.
		if(ch=='#') return 0x00a3;
	}

	u = de_char_to_unicode(c, (i32)ch, DE_ENCODING_CP437_G);
	return u;
}

static void do_ctrl_char(deark *c, lctx *d, u8 ch)
{
	if(ch==13) { // CR
		d->xpos = 0;
		return;
	}
	if(ch==10) { // LF
		d->ypos++;
		// Some files aren't rendered correctly unless an LF implies a CR.
		d->xpos = 0;
		return;
	}

	// ^N = shift out - selects G1 character set
	// ^O = shift in  - selects G0 character set
	if(ch==0x0e) d->curr_charset_index = 1;
	else if(ch==0x0f) d->curr_charset_index = 0;
}

static void do_normal_char(deark *c, lctx *d, i64 pos, u8 ch)
{
	struct de_char_cell *cell;
	i32 u;

	// TODO: A few more characters, such as tabs, should be treated as
	// control characters.
	if(ch==10 || ch==13 ||
		(d->vt100_mode && ch<32))
	{
		do_ctrl_char(c, d, ch);
		return;
	}

	u = ansi_char_to_unicode(c, d, ch);

	cell = get_cell_at(c, d->screen, d->xpos, d->ypos);
	if(cell) {
		cell->codepoint = (i32)ch;
		cell->codepoint_unicode = u;
		cell->fgcol = d->curr_fgcol;
		cell->bgcol = d->curr_bgcol;
		if(d->curr_bold && DE_IS_PAL_COLOR(cell->fgcol)) {
			cell->fgcol |= 0x08;
		}
		cell->underline = d->curr_underline;
		cell->strikethru = d->curr_strikethru;

		cell->size_flags = 0;

		if(d->disable_blink_attr || d->sauce_disable_blink || d->opt_disable_blink) {
			// "blink" in this mode means intense-background, instead of blink.
			if(d->curr_blink && DE_IS_PAL_COLOR(cell->bgcol))
				cell->bgcol |= 0x08;
			cell->blink = 0;
		}
		else {
			cell->blink = d->curr_blink;
		}

		if(d->curr_negative) {
			u32 tmpcolor;
			tmpcolor = cell->fgcol;
			cell->fgcol = cell->bgcol;
			cell->bgcol = tmpcolor;
		}
		if(d->curr_conceal) {
			cell->fgcol = cell->bgcol;
			cell->blink = 0;
		}

		if(d->ypos >= d->screen->height) d->screen->height = d->ypos+1;
	}
	else {
		if(d->num_warnings<ANSIART_MAX_WARNINGS) {
			de_warn(c, "Off-screen write (%d,%d) at %d",
				(int)(d->xpos+1), (int)(d->ypos+1), (int)pos);
			d->num_warnings++;
		}
	}

	d->xpos++;

	// Line wrap
	while(d->xpos >= d->screen->width && !d->vt100_mode) {
		d->xpos -= d->screen->width;
		d->ypos++;
	}
}

// Convert d->param_string_buf to d->params and d->num_params.
static void parse_params(deark *c, lctx *d, i64 default_val, i64 offset)
{
	i64 buf_len;
	i64 ppos;
	i64 param_len;
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

static void read_one_int(deark *c, lctx *d, const u8 *buf,
	i64 *a, i64 a_default)
{
	parse_params(c, d, a_default, 0);

	if(d->parse_results.num_params>=1) {
		*a = d->parse_results.params[0];
	}
	else {
		*a = a_default;
	}
}

static void do_ext_color(deark *c, lctx *d)
{
	int is_bg;
	const char *name;
	u8 cr, cg, cb;
	u32 clr;

	if(d->parse_results.num_params<2) return;

	if(d->parse_results.params[0]==48) {
		is_bg = 1;
		name = "bg";
	}
	else {
		is_bg = 0;
		name = "fg";
	}

	if(d->parse_results.params[1]!=2) {
		de_warn(c, "Unsupported extended %s color format: %d",
			name, (int)d->parse_results.params[1]);
		return;
	}

	if(d->parse_results.num_params<5) {
		de_warn(c, "Invalid extended %s color code", name);
		return;
	}

	if(d->opt_disable_24bitcolor) return;

	cr = (u8)(d->parse_results.params[2]%256);
	cg = (u8)(d->parse_results.params[3]%256);
	cb = (u8)(d->parse_results.params[4]%256);
	clr = (u32)DE_MAKE_RGB(cr, cg, cb);
	if(is_bg) {
		d->curr_bgcol = clr;
	}
	else {
		d->curr_fgcol = clr;
	}
}

// m - Select Graphic Rendition
static void do_code_m(deark *c, lctx *d)
{
	i64 i;
	i64 sgr_code;

	parse_params(c, d, 0, 0);

	if(d->parse_results.num_params>=1) {
		// SGR 38 and 48 apparently have a special format
		if(d->parse_results.params[0]==38 || d->parse_results.params[0]==48) {
			do_ext_color(c, d);
			return;
		}
	}

	for(i=0; i<d->parse_results.num_params; i++) {
		sgr_code = d->parse_results.params[i];

		if(sgr_code==0) {
			// Reset
			d->curr_bold = 0;
			d->curr_underline = 0;
			d->curr_blink = 0;
			d->curr_negative = 0;
			d->curr_conceal = 0;
			d->curr_strikethru = 0;
			d->curr_bgcol = DEFAULT_BGCOL;
			d->curr_fgcol = DEFAULT_FGCOL;
			// TODO: Do character sets get reset by this?
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
		else if(sgr_code==7) {
			d->curr_negative = 1;
		}
		else if(sgr_code==8) {
			d->curr_conceal = 1;
		}
		else if(sgr_code==9) {
			d->curr_strikethru = 1;
		}
		else if(sgr_code==22) {
			d->curr_bold = 0;
		}
		else if(sgr_code==24) {
			d->curr_underline = 0;
		}
		else if(sgr_code==25) {
			d->curr_blink = 0;
		}
		else if(sgr_code==27) { // positive image
			d->curr_negative = 0;
		}
		else if(sgr_code==28) {
			d->curr_conceal = 0;
		}
		else if(sgr_code==29) {
			d->curr_strikethru = 0;
		}
		else if(sgr_code>=30 && sgr_code<=37) {
			// Set foreground color
			d->curr_fgcol = (u32)(sgr_code-30);
		}
		else if(sgr_code==39) {
			d->curr_fgcol = DEFAULT_FGCOL;
		}
		else if(sgr_code>=40 && sgr_code<=47) {
			// Set background color
			d->curr_bgcol = (u32)(sgr_code-40);
		}
		else if(sgr_code==49) {
			d->curr_bgcol = DEFAULT_BGCOL;
		}
		else if(sgr_code>=90 && sgr_code<=97) {
			d->curr_fgcol = (u32)(8+(sgr_code-90));
		}
		else if(sgr_code>=100 && sgr_code<=107) {
			d->curr_bgcol = (u32)(8+(sgr_code-100));
		}
		else {
			if(d->num_warnings<ANSIART_MAX_WARNINGS) {
				de_warn(c, "Unsupported SGR code %d", (int)sgr_code);
				d->num_warnings++;
			}
		}
	}
}

// H: Set cursor position
static void do_code_H(deark *c, lctx *d)
{
	i64 row, col;

	parse_params(c, d, 1, 0);

	if(d->parse_results.num_params>=1) row = d->parse_results.params[0];
	else row = 1;

	if(d->parse_results.num_params>=2) col = d->parse_results.params[1];
	else col = 1;

	d->xpos = col-1;
	d->ypos = row-1;
}

// h: Mode settings
static void do_code_h(deark *c, lctx *d, i64 param_start)
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
			case 4: // Smooth scrolling
				ok = 1;
				break;
			case 7: // Set autowrap (default)
				ok = 1;
				break;
			case 25: // Display the cursor (VT320)
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
			de_warn(c, "Unsupported 'h' control sequence '%s%d' at %d",
				is_DEC?"?":"", (int)d->parse_results.params[i], (int)param_start);
			d->num_warnings++;
		}
	}
}

// l: Turn off mode
static void do_code_l(deark *c, lctx *d, i64 param_start)
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
			case 4: // Disable smooth scrolling
				ok = 1;
				break;
			case 5: // Disable reverse-video screen
				ok = 1;
				break;
			case 25: // Hide the cursor (VT320)
				ok = 1;
				break;
			case 33:
				d->disable_blink_attr = 0;
				ok = 1;
				break;
			}
		}
		else {
			switch(d->parse_results.params[i]) {
			case 4: // Disable INSERT mode
				ok = 1;
				break;
			case 5: // Disable STATUS REPORT TRANSFER MODE
				ok = 1;
				break;
			}
		}

		if(!ok && d->num_warnings<ANSIART_MAX_WARNINGS) {
			de_warn(c, "Unsupported 'l' control sequence '%s%d' at %d",
				is_DEC?"?":"", (int)d->parse_results.params[i], (int)param_start);
			d->num_warnings++;
		}
	}
}

static void do_code_t(deark *c, lctx *d, i64 param_start)
{
	parse_params(c, d, 0, 0);

	if(d->parse_results.num_params==4 &&
		d->parse_results.params[0]>=0 && d->parse_results.params[0]<=1 &&
		d->parse_results.params[1]>=0 && d->parse_results.params[1]<=255 &&
		d->parse_results.params[2]>=0 && d->parse_results.params[2]<=255 &&
		d->parse_results.params[3]>=0 && d->parse_results.params[3]<=255)
	{
		// 24-bit color definition.
		// Reference: http://picoe.ca/2014/03/07/24-bit-ansi/
		u32 clr;
		if(d->opt_disable_24bitcolor) return;
		clr = (u32)DE_MAKE_RGB(d->parse_results.params[1],
			d->parse_results.params[2], d->parse_results.params[3]);
		if(d->parse_results.params[0]==0)
			d->curr_bgcol = clr;
		else
			d->curr_fgcol = clr;
	}
	else {
		if(d->num_warnings<ANSIART_MAX_WARNINGS) {
			de_warn(c, "Unsupported 't' control sequence at %d", (int)param_start);
			d->num_warnings++;
		}
	}
}

// J: Clear screen
static void do_code_J(deark *c, lctx *d)
{
	i64 n;
	i64 i, j;

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
	i64 n;
	i64 i;

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
	i64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->ypos -= n;
}

// B: Down
static void do_code_B(deark *c, lctx *d)
{
	i64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->ypos += n;
}

// C: Forward
static void do_code_C(deark *c, lctx *d)
{
	i64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->xpos += n;
}

// D: Back
static void do_code_D(deark *c, lctx *d)
{
	i64 n;
	read_one_int(c, d, d->param_string_buf, &n, 1);
	d->xpos -= n;
	// Some files begin with a code to move the cursor left by a large amount.
	// So I assume that (by default) this isn't supposed to wrap, and positions
	// left of the first column aren't allowed.
	if(d->xpos<0) d->xpos=0;
}

static u8 make_printable_char(u8 x)
{
	if(x>=32 && x<=126) return x;
	return '?';
}

static void do_control_sequence(deark *c, lctx *d, u8 code,
	i64 param_start, i64 param_len)
{
	if(code>=128) return;

	if(c->debug_level>=2) {
		de_dbg2(c, "[(%2d,%d) %c at %d %d]", (int)(d->xpos+1), (int)(d->ypos+1),
			(char)code, (int)param_start, (int)param_len);
	}

	if(param_len > (i64)(sizeof(d->param_string_buf)-1)) {
		de_warn(c, "Ignoring long control sequence (len %d at %d)",
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
	case 'f': do_code_H(c, d); break; // f is the same as H
	case 'l': do_code_l(c, d, param_start); break;
	case 'm': do_code_m(c, d); break;
	case 'q': break; // Programmable LED command. Ignore.
	case 's':
		d->saved_xpos = d->xpos;
		d->saved_ypos = d->ypos;
		break;
	case 't': do_code_t(c, d, param_start); break;
	case 'u':
		d->xpos = d->saved_xpos;
		d->ypos = d->saved_ypos;
		break;
	default:
		if(!d->control_seq_seen[(unsigned int)code]) {
			const char *name = NULL;
			switch(code) {
			case 'r': name = "Define scrolling region"; break;
			}

			if(name) {
				de_warn(c, "Unsupported control sequence '%c' (%s) at %d",
					(char)code, name, (int)param_start);
			}
			else if(code>=0x70 && code<=0x7e) {
				// "Bit combinations 07/00 to 07/14 are available as final bytes
				// of control sequences for private use" -- ECMA 48
				de_warn(c, "Unsupported private-use control sequence '%c' at %d",
					(char)code, (int)param_start);
			}
			else {
				de_warn(c, "Unsupported control sequence '%c' at %d",
					(char)code, (int)param_start);
			}
		}
	}

done:
	d->control_seq_seen[(unsigned int)code] = 1;
}

static void do_2char_code(deark *c, lctx *d, u8 ch1, u8 ch2, i64 pos)
{
	int ok = 0;

	if(!d->vt100_mode) {
		de_dbg(c, "switching to vt100 mode");
		d->vt100_mode = 1;
	}

	if(ch1=='(') {
		if(ch2=='A') { d->curr_g0_charset = CHARSET_UK; ok=1; }
		else if(ch2=='B') { d->curr_g0_charset = CHARSET_US; ok=1; }
		else if(ch2=='0') { d->curr_g0_charset = CHARSET_LINEDRAWING; ok=1; }
	}
	else if(ch1==')') {
		if(ch2=='A') { d->curr_g1_charset = CHARSET_UK; ok=1; }
		else if(ch2=='B') { d->curr_g1_charset = CHARSET_US; ok=1; }
		else if(ch2=='0') { d->curr_g1_charset = CHARSET_LINEDRAWING; ok=1; }
	}
	else if(ch1=='#') {
		if(ch2=='3') {
			if(d->ypos>=0 && d->ypos<MAX_ROWS) {
				d->row_data[d->ypos].size_mode = SIZEMODE_DBLH_TOP;
			}
			ok=1;
		}
		else if(ch2=='4') {
			if(d->ypos>=0 && d->ypos<MAX_ROWS) {
				d->row_data[d->ypos].size_mode = SIZEMODE_DBLH_BOTTOM;
			}
			ok=1;
		}
		else if(ch2=='5') {
			if(d->ypos>=0 && d->ypos<MAX_ROWS) {
				d->row_data[d->ypos].size_mode = SIZEMODE_DEFAULT;
			}
			ok=1;
		}
		else if(ch2=='6') {
			if(d->ypos>=0 && d->ypos<MAX_ROWS) {
				d->row_data[d->ypos].size_mode = SIZEMODE_DBLW;
			}
			ok=1;
		}
	}

	if(!ok && d->num_warnings<ANSIART_MAX_WARNINGS) {
		de_warn(c, "Unsupported escape code '%c%c' at %d",
			make_printable_char(ch1),
			make_printable_char(ch2), (int)pos);
		d->num_warnings++;
	}
}

static void do_escape_code(deark *c, lctx *d, u8 code, i64 pos,
	i64 *extra_bytes_to_skip)
{
	if(code>=96) return;

	if(code=='P') { // DCS
		i64 pos2;
		u8 b0, b1;

		// A DCS sequence ends with 1b 5c, or maybe 9c.

		// pos is currently the position of the 'P'.
		pos2 = pos+1;
		while(pos2 < d->effective_file_size) {
			b0 = de_getbyte(pos2);
			b1 = de_getbyte(pos2+1);
			if(b0==0x9c) {
				*extra_bytes_to_skip = pos2 - pos;
				return;
			}
			if(b0==0x1b && b1==0x5c) {
				*extra_bytes_to_skip = pos2+1 - pos;
				return;
			}
			pos2++;
		}
		// End of DCS sequence not found.
		return;
	}

	if(code=='\\') return; // Disable Manual Input (we ignore this)
	if(code=='b') return; // Enable Manual Input (we ignore this)

	if(d->control_seq_seen[(unsigned int)code]==0) {
		de_warn(c, "Unsupported escape code '%c' at %d",
			(char)code, (int)pos);
		d->control_seq_seen[(unsigned int)code] = 1;
	}
	d->control_seq_seen[(unsigned int)code] = 1;
}

static void do_main(deark *c, lctx *d)
{
	i64 pos, nextpos;
	i64 params_start_pos = 0;
#define STATE_NORMAL 0
#define STATE_GOT_ESC 1
#define STATE_READING_PARAM 2
#define STATE_GOT_1_CHAR 3
	int state;
	u8 first_ch = 0;
	u8 ch;

	d->xpos = 0; d->ypos = 0;
	d->curr_bgcol = DEFAULT_BGCOL;
	d->curr_fgcol = DEFAULT_FGCOL;
	state = STATE_NORMAL;

	nextpos = 0;
	while(nextpos<d->effective_file_size) {
		pos = nextpos;
		ch = de_getbyte(pos);
		nextpos = pos+1;

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
			else { // A byte that's not part of an escape sequence
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
				i64 extra_bytes_to_skip;
				extra_bytes_to_skip = 0;
				do_escape_code(c, d, ch, pos, &extra_bytes_to_skip);
				nextpos += extra_bytes_to_skip;
				state=STATE_NORMAL;
				continue;
			}
			else if(ch=='(' || ch==')' || ch=='#') {
				first_ch = ch;
				state=STATE_GOT_1_CHAR;
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
		else if(state==STATE_GOT_1_CHAR) {
			do_2char_code(c, d, first_ch, ch, pos-1);
			state=STATE_NORMAL;
			continue;
		}
	}
}

// With vt100 graphics, each row can be "double width".
// But our character cells are always single width. We support double
// width characters by copying each character in a double-wide row to
// two character cells,
// and setting flags to paint either the left half or the right half
// of the character.
// This function also copies the row's "double height" setting to each
// cell. (The vt100 handles double-*height* characters the same way we do.
// Consistency is not its strong point.)
static void fixup_doublesize_rows(deark *c, lctx *d)
{
	i64 i, j;
	struct de_char_cell *r;
	u8 size_mode;

	for(j=0; j<d->screen->height && j<MAX_ROWS; j++) {
		size_mode = d->row_data[j].size_mode;
		if(size_mode==0) continue;

		r = d->screen->cell_rows[j];
		if(!r) return;

		for(i=d->screen->width-1; i>=0; i--) {
			if(i>0) r[i] = r[i/2]; // struct copy
			r[i].size_flags = 0;
			if(size_mode==SIZEMODE_DBLH_TOP) {
				r[i].size_flags |= DE_PAINTFLAG_TOPHALF;
			}
			else if(size_mode==SIZEMODE_DBLH_BOTTOM){
				r[i].size_flags |= DE_PAINTFLAG_BOTTOMHALF;
			}
			if(i%2)
				r[i].size_flags |= DE_PAINTFLAG_RIGHTHALF;
			else
				r[i].size_flags |= DE_PAINTFLAG_LEFTHALF;
		}
	}
}

static void de_run_ansiart(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	i64 k;
	struct de_SAUCE_detection_data sdd;
	struct de_SAUCE_info *si = NULL;
	int valid_sauce = 0;
	const char *s;
	i64 width_req = 0;

	d = de_malloc(c, sizeof(lctx));

	if(de_get_ext_option(c, "ansiart:no24bitcolor")) {
		d->opt_disable_24bitcolor = 1;
	}
	if(de_get_ext_option(c, "ansiart:noblink")) {
		d->opt_disable_blink = 1;
	}
	if(de_get_ext_option(c, "ansiart:vt100")) {
		d->vt100_mode = 1;
	}
	s=de_get_ext_option(c, "char:width");
	if(s) {
		width_req = de_atoi(s);
	}

	d->effective_file_size = c->infile->len;

	charctx = de_malloc(c, sizeof(struct de_char_context));

	// Read SAUCE metadata, if present.
	si = de_fmtutil_create_SAUCE(c);
	de_fmtutil_detect_SAUCE(c, c->infile, &sdd, 0x1);

	if(sdd.has_SAUCE) {
		de_dbg_indent(c, 1);
		de_fmtutil_handle_SAUCE(c, c->infile, si);
		de_dbg_indent(c, -1);

		d->effective_file_size = si->original_file_size;

		charctx->title = si->title;
		charctx->artist = si->artist;
		charctx->organization = si->organization;
		charctx->creation_date = si->creation_date;
		charctx->num_comments = si->num_comments;
		charctx->comments = si->comments;

		if(si->is_valid && si->data_type==1 && (si->file_type==1 || si->file_type==2)) {
			valid_sauce = 1;
		}
	}

	if(valid_sauce) {
		if(si->tflags & 0x01) {
			d->sauce_disable_blink = 1;
		}
		if((si->tflags & 0x18)>>3 == 0x02) {
			// Square pixels requested.
			// TODO: This is a little bit wrong. Knowing that the pixels are
			// square is different from preventing a density from being written
			// to the output file. For one thing, we should consider what to do
			// if the user set "-opt char:charwidth=9".
			charctx->no_density = 1;
		}
		if((si->tflags & 0x06)>>1 == 0x02) {
			charctx->prefer_9col_mode = 1;
		}
	}

	// Ignore any Ctrl-Z at the end of data.
	if(de_getbyte(d->effective_file_size-1) == 0x1a) {
		de_dbg(c, "found Ctrl+Z byte at %d", (int)(d->effective_file_size-1));
		d->effective_file_size--;
	}
	if(d->effective_file_size!=c->infile->len) {
		de_dbg(c, "effective file size set to %d", (int)d->effective_file_size);
	}

	charctx->nscreens = 1;
	charctx->screens = de_mallocarray(c, charctx->nscreens, sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));

	d->screen = charctx->screens[0];

	if(width_req>0) {
		// Use the width requested by the user.
		d->screen->width = width_req;
	}
	else if(valid_sauce && si->width_in_chars>=40 && si->width_in_chars<=2048) {
		// Use the width from SAUCE, if it's available and seems sensible.
		d->screen->width = si->width_in_chars;
	}
	else {
		// Otherwise, assume 80 characters per row.
		d->screen->width = 80;
	}
	// We don't know the height yet. This will be updated as we read the file.
	d->screen->height = 1;

	d->screen->cell_rows = de_mallocarray(c, MAX_ROWS, sizeof(struct de_char_cell*));
	d->row_data = de_mallocarray(c, MAX_ROWS, sizeof(struct row_data_struct));

	for(k=0; k<16; k++) {
		charctx->pal[k] = ansi_palette[k];
	}

	do_main(c, d);

	fixup_doublesize_rows(c, d);

	if(d->vt100_mode) {
		charctx->no_density = 1;
	}

	de_char_output_to_file(c, charctx);

	de_free_charctx(c, charctx);
	de_free(c, d->row_data);
	de_fmtutil_free_SAUCE(c, si);
	de_free(c, d);
}

static int de_identify_ansiart(deark *c)
{
	u8 buf[4];
	int has_ans_ext;

	if(!c->detection_data.SAUCE_detection_attempted) {
		de_err(c, "ansiart detection requires sauce module");
		return 0;
	}

	de_read(buf, 0, 4);

	if(!de_memcmp(buf, "\x04\x31\x2e\x34", 4)) {
		// Looks like iCEDraw format, which may use the same SAUCE identifiers
		// as ANSI Art, even though it is incompatible.
		return 0;
	}

	has_ans_ext = de_input_file_has_ext(c, "ans");

	if(c->detection_data.sauce.has_SAUCE) {
		if(c->detection_data.sauce.data_type==1 &&
			c->detection_data.sauce.file_type==1)
		{
			// Unfortunately, iCEDraw and possibly other formats may use the
			// same SAUCE identifiers as ANSI Art, so we probably shouldn't always
			// return 100.
			if(has_ans_ext)
				return 100;
			return 91;
		}
	}

	// ANSI Art files usually start with an ANSI escape sequence.
	// TODO: Another possibility is that the file could start with email headers.
	if(buf[0]==0x1b && buf[1]==0x5b && (buf[2]=='?' ||
		(buf[2]>='0' && buf[2]<='9')))
	{
		return has_ans_ext ? 100 : 50;
	}

	if(has_ans_ext)
		return 10;
	return 0;
}

static void de_help_ansiart(deark *c)
{
	de_msg(c, "-opt ansiart:no24bitcolor : Disable extended colors");
	de_msg(c, "-opt ansiart:noblink : Disable blinking characters");
	de_msg(c, "-opt ansiart:vt100 : Use VT100 mode");
	de_msg(c, "-opt char:output=image : Write an image file instead of HTML");
	de_msg(c, " -opt char:charwidth=<8|9> : Width of a character cell");
	de_msg(c, "-opt char:width=<n> : Number of characters per row");
}

void de_module_ansiart(deark *c, struct deark_module_info *mi)
{
	mi->id = "ansiart";
	mi->id_alias[0] = "ansi";
	mi->desc = "ANSI Art character graphics";
	mi->run_fn = de_run_ansiart;
	mi->identify_fn = de_identify_ansiart;
	mi->help_fn = de_help_ansiart;
}
