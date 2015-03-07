// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// ANSI art

#include <deark-config.h>
#include <deark-modules.h>

struct cell_struct {
	de_int32 codepoint;
	de_byte fgcol;
	de_byte bgcol;
};

typedef struct localctx_struct {
	dbuf *ofile;

	int width, height;
	struct cell_struct *cells; // Array of height*width cells

	de_int64 xpos, ypos; // 0-based

	de_int64 param_buf_used;
	de_byte param_buf[100];
} lctx;

static struct cell_struct *get_cell_at(deark *c, lctx *d, de_int64 xpos, de_int64 ypos)
{
	if(xpos<0 || ypos<0) return NULL;
	if(xpos>=d->width || ypos>=d->height) return NULL;
	return &d->cells[ypos*d->width + xpos];
}

static void set_cur_cell_codepoint(deark *c, lctx *d, de_int32 u)
{
	struct cell_struct *cell;
	cell = get_cell_at(c, d, d->xpos, d->ypos);
	if(!cell) return;
	cell->codepoint = u;
}

static void do_normal_char(deark *c, lctx *d, de_byte ch)
{
	de_int32 u;

	if(ch==13) { // CR
		d->xpos = 0;
	}
	else if(ch==10) { // LF
		d->ypos++;
	}
	else if(ch>=32) {
		u = de_cp437g_to_unicode(c, (int)ch);
		set_cur_cell_codepoint(c, d, u);
		d->xpos++;
	}
}

// Read x;y from a NUL-terminated buffer.
static void read_two_ints(deark *c, lctx *d, const de_byte *buf,
  de_int64 *a, de_int64 *b, de_int64 a_default, de_int64 b_default)
{
	char *b_ptr;
	de_int64 buf_len;
	de_int64 a_len, b_len;

	*a = a_default;
	*b = b_default;

	buf_len = de_strlen((const char*)buf);
	if(buf_len<1) return;

	b_ptr = de_strchr((const char*)buf, ';');
	if(b_ptr) {
		// String contains a ';'
		a_len = (const unsigned char*)b_ptr - buf;
		b_len = buf_len - a_len - 1;
		b_ptr++;
	}
	else {
		a_len = buf_len;
		b_len = 0;
	}

	if(a_len > 0) {
		*a = de_atoi64((const char*)buf);
	}

	if(b_ptr && b_len>0 ) {
		*b = de_atoi64(b_ptr);
	}
}

static void read_one_int(deark *c, lctx *d, const de_byte *buf,
  de_int64 *a, de_int64 a_default)
{
	de_int64 buf_len;

	*a = a_default;

	buf_len = de_strlen((const char*)buf);
	if(buf_len<1) return;

	*a = de_atoi64((const char*)buf);
}

// H: Set cursor position
static void do_code_H(deark *c, lctx *d)
{
	de_int64 row, col;

	read_two_ints(c, d, d->param_buf, &row, &col, 1, 1);
	de_dbg(c, "(->%d %d)\n", (int)row, (int)col);
	d->xpos = col-1;
	d->ypos = row-1;
}

// A: Up
static void do_code_A(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_buf, &n, 1);
	d->ypos -= n;
}

// B: Down
static void do_code_B(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_buf, &n, 1);
	d->ypos += n;
}

// C: Forward
static void do_code_C(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_buf, &n, 1);
	d->xpos += n;
}

// D: Back
static void do_code_D(deark *c, lctx *d)
{
	de_int64 n;
	read_one_int(c, d, d->param_buf, &n, 1);
	d->xpos -= n;
}

static void do_control_sequence(deark *c, lctx *d, de_byte code,
	de_int64 param_start, de_int64 param_len)
{
	de_dbg2(c, "[%c at %d %d]\n", (char)code, (int)param_start, (int)param_len);

	if(param_len > sizeof(d->param_buf)-1) {
		de_warn(c, "Ignoring long escape sequence (len %d at %d)\n",
			(int)param_len, (int)param_start);
		return;
	}

	de_read(d->param_buf, param_start, param_len);
	d->param_buf[param_len] = '\0';

	switch(code) {
	case 'A': do_code_A(c, d); break;
	case 'B': do_code_B(c, d); break;
	case 'C': do_code_C(c, d); break;
	case 'D': do_code_D(c, d); break;
	case 'H': do_code_H(c, d); break;
	default:
		de_dbg(c, "[unsupported escape sequence %c]\n", (char)code);
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

		if(state==STATE_NORMAL) {
			if(ch==0x1b) { // ESC
				state=STATE_GOT_ESC;
				continue;
			}
			else if(ch==0x9b) {
				state=STATE_READING_PARAM;
				params_start_pos = pos+1;
				continue;
			}
			else { // a non-escape character
				do_normal_char(c, d, ch);
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

static void do_output_main(deark *c, lctx *d)
{
	const struct cell_struct *cell;
	int i, j;
	de_int32 n;

	dbuf_fputs(d->ofile, "<pre>\n");
	for(j=0; j<d->height; j++) {
		for(i=0; i<d->width; i++) {
			cell = get_cell_at(c, d, i, j);
			if(!cell) continue;

			n = cell->codepoint;
			if(n<0x20) n='?';

			if(n=='<' || n=='>' || n>126) {
				dbuf_fprintf(d->ofile, "&#%d;", (int)n);
			}
			else {
				dbuf_writebyte(d->ofile, (de_byte)n);
			}
		}
		dbuf_fputs(d->ofile, "\n");
	}
	dbuf_fputs(d->ofile, "</pre>\n");
}

static void do_header(deark *c, lctx *d)
{
	d->ofile = dbuf_create_output_file(c, "html", NULL);

	dbuf_fputs(d->ofile, "<!DOCTYPE html>\n");
	dbuf_fputs(d->ofile, "<html>\n");
	dbuf_fputs(d->ofile, "<head>\n");
	dbuf_fputs(d->ofile, "<title></title>\n");
	dbuf_fputs(d->ofile, "</head>\n");
	dbuf_fputs(d->ofile, "<body>\n");
}

static void do_footer(deark *c, lctx *d)
{
	dbuf_fputs(d->ofile, "</body>\n</html>\n");
	dbuf_close(d->ofile);
	d->ofile = NULL;
}

static void de_run_ansiart(deark *c, const char *params)
{
	lctx *d = NULL;

	d = de_malloc(c, sizeof(lctx));
	do_header(c, d);

	d->width = 80;
	d->height = 25;
	d->cells = de_malloc(c, sizeof(struct cell_struct)*d->height*d->width);

	do_main(c, d);
	do_output_main(c, d);
	do_footer(c, d);

	de_free(c, d->cells);
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
	mi->flags |= DE_MODFLAG_NONWORKING;
}
