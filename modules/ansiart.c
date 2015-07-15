// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// ANSI art
// (very incomplete)

#include <deark-config.h>
#include <deark-modules.h>

static const de_uint32 ansi_palette[16] = {
	0x000000,0xaa0000,0x00aa00,0xaa5500,0x0000aa,0xaa00aa,0x00aaaa,0xaaaaaa,
	0x555555,0xff5555,0x55ff55,0xffff55,0x5555ff,0xff55ff,0x55ffff,0xffffff
};

#define MAX_ROWS       5000
#define CHARS_PER_ROW  80

typedef struct localctx_struct {
	struct de_char_screen *screen;

	de_int64 xpos, ypos; // 0-based
	de_int64 saved_xpos, saved_ypos;

	de_byte curr_fgcol;
	de_byte curr_bgcol;
	de_byte curr_bold;
	de_byte curr_blink;

	de_byte param_string_buf[100];

	de_byte support_9b_csi;

#define MAX_ESC_PARAMS 16
	int num_params;
	de_int64 params[MAX_ESC_PARAMS];
} lctx;

static struct de_char_cell *get_cell_at(deark *c, struct de_char_screen *screen,
	de_int64 xpos, de_int64 ypos)
{
	de_int64 i;
	struct de_char_cell *cell;

	if(xpos<0 || ypos<0) return NULL;
	if(xpos>=CHARS_PER_ROW || ypos>=MAX_ROWS) return NULL;
	if(!screen->cell_rows[ypos]) {
		screen->cell_rows[ypos] = de_malloc(c, CHARS_PER_ROW * sizeof(struct de_char_cell));
		for(i=0; i<CHARS_PER_ROW; i++) {
			// Initialize each new cell
			cell = &screen->cell_rows[ypos][i];
			cell->codepoint = 0x20;
			cell->codepoint_unicode = 0x20;
			cell->bgcol = 0;
			cell->fgcol = 7;
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
		while(d->xpos >= d->screen->width) {
			d->xpos -= d->screen->width;
			d->ypos++;
		}

		u = de_char_to_unicode(c, (de_int32)ch, DE_ENCODING_CP437_G);

		cell = get_cell_at(c, d->screen, d->xpos, d->ypos);
		if(cell) {
			cell->codepoint = (de_int32)ch;
			cell->codepoint_unicode = u;
			cell->fgcol = d->curr_fgcol;
			cell->bold = d->curr_bold;
			cell->bgcol = d->curr_bgcol;
			cell->blink = d->curr_blink;

			if(d->ypos >= d->screen->height) d->screen->height = d->ypos+1;
		}
		else {
			de_dbg(c, "off-screen write at (%d,%d) (%d)\n",
				(int)d->xpos, (int)d->ypos, (int)pos);
		}

		d->xpos++;
	}
}

// Convert d->param_string_buf to d->params and d->num_params.
static void parse_params(deark *c, lctx *d, de_int64 default_val)
{
	de_int64 buf_len;
	de_int64 ppos;
	de_int64 param_len;
	char *p_ptr;
	int last_param = 0;

	d->num_params = 0;

	buf_len = de_strlen((const char*)d->param_string_buf);

	ppos = 0;
	while(1) {
		if(d->num_params >= MAX_ESC_PARAMS) {
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
			d->params[d->num_params] = de_atoi64((const char*)&d->param_string_buf[ppos]);
		}
		else {
			d->params[d->num_params] = default_val;
		}
		d->num_params++;

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
	parse_params(c, d, a_default);

	if(d->num_params>=1) {
		*a = d->params[0];
	}
	else {
		*a = a_default;
	}
}

// m - Select Graphic Rendition
static void do_code_m(deark *c, lctx *d)
{
	de_int64 i;
	de_int64 sgi_code;

	parse_params(c, d, 0);

	for(i=0; i<d->num_params; i++) {
		sgi_code = d->params[i];

		if(sgi_code==0) {
			// Reset
			d->curr_bold = 0;
			d->curr_blink = 0;
			d->curr_bgcol = 0;
			d->curr_fgcol = 7;
		}
		else if(sgi_code==1) {
			d->curr_bold = 1;
		}
		else if(sgi_code==5 || sgi_code==6) {
			d->curr_blink = 1;
		}
		else if(sgi_code>=30 && sgi_code<=37) {
			// Set foreground color
			d->curr_fgcol = (de_byte)(sgi_code-30);
		}
		else if(sgi_code>=40 && sgi_code<=47) {
			// Set background color
			d->curr_bgcol = (de_byte)(sgi_code-40);
		}
		else {
			de_dbg(c, "unsupported SGR code %d\n", (int)sgi_code);
		}
	}
}

// H: Set cursor position
static void do_code_H(deark *c, lctx *d)
{
	de_int64 row, col;

	parse_params(c, d, 1);

	if(d->num_params>=1) row = d->params[0];
	else row = 1;

	if(d->num_params>=2) col = d->params[1];
	else col = 1;

	d->xpos = col-1;
	d->ypos = row-1;
}

// h: Mode settings
static void do_code_h(deark *c, lctx *d)
{
	int ok=0;

	if(d->param_string_buf[0]=='?') {
		if(d->param_string_buf[1]=='7') {
			ok=1; // Set autowrap (default)
		}
	}

	if(!ok) {
		de_dbg(c, "unsupported 'h' escape sequence\n");
	}
}

// J: Clear screen
static void do_code_J(deark *c, lctx *d)
{
	de_int64 n;
	de_int64 i, j;
	struct de_char_cell *cell;

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
			cell = get_cell_at(c, d->screen, i, j);
			if(!cell) continue;
			cell->codepoint = 0x20;
			cell->codepoint_unicode = 0x20;
		}
	}

	if(n==2) {
		d->xpos = 0;
		d->ypos = 0;
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
	de_dbg2(c, "[%c at %d %d]\n", (char)code, (int)param_start, (int)param_len);

	if(param_len > (de_int64)(sizeof(d->param_string_buf)-1)) {
		de_warn(c, "Ignoring long escape sequence (len %d at %d)\n",
			(int)param_len, (int)param_start);
		return;
	}

	de_read(d->param_string_buf, param_start, param_len);
	d->param_string_buf[param_len] = '\0';

	switch(code) {
	case 'A': do_code_A(c, d); break;
	case 'B': do_code_B(c, d); break;
	case 'C': do_code_C(c, d); break;
	case 'D': do_code_D(c, d); break;
	case 'H': do_code_H(c, d); break;
	case 'h': do_code_h(c, d); break;
	case 'J': do_code_J(c, d); break;
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
		de_dbg(c, "unsupported escape sequence %c at %d\n", (char)code, (int)param_start);
	}
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
	state = STATE_NORMAL;

	for(pos=0; pos<c->infile->len; pos++) {
		ch = de_getbyte(pos);

		if(ch==0x1a) break; // Ctrl-Z apparently means we should stop.

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

static void de_run_ansiart(deark *c, const char *params)
{
	lctx *d = NULL;
	struct de_char_context *charctx = NULL;
	de_int64 k;

	d = de_malloc(c, sizeof(lctx));

	charctx = de_malloc(c, sizeof(struct de_char_context));
	charctx->nscreens = 1;
	charctx->screens = de_malloc(c, charctx->nscreens*sizeof(struct de_char_screen*));
	charctx->screens[0] = de_malloc(c, sizeof(struct de_char_screen));

	d->screen = charctx->screens[0];

	d->screen->width = CHARS_PER_ROW;
	// We don't know the height yet. This will be updated as we read the file.
	d->screen->height = 1;

	d->screen->cell_rows = de_malloc(c, MAX_ROWS * sizeof(struct de_char_cell*));

	do_main(c, d);

	for(k=0; k<16; k++) {
		charctx->pal[k] = ansi_palette[k];
	}

	de_char_output_to_file(c, charctx);

	de_free_charctx(c, charctx);
	de_free(c, d);
}

static int de_identify_ansiart(deark *c)
{
	if(de_input_file_has_ext(c, "ans"))
		return 10;
	return 0;
}

void de_module_ansiart(deark *c, struct deark_module_info *mi)
{
	mi->id = "ansiart";
	mi->run_fn = de_run_ansiart;
	mi->identify_fn = de_identify_ansiart;
}
