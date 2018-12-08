// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

// Detokenize Commodore 64 BASIC programs.
//
// For now at least, it emits a text file having PETSCII encoding.
//
// It might be nice to use UTF-8 instead, but that's not really possible,
// because not all PETSCII characters are represented in Unicode, and for
// various other reasons.
//
// Another idea is to write it to HTML format, but that will require some
// wizardry to do well.

#include <deark-config.h>
#include <deark-private.h>
DE_DECLARE_MODULE(de_module_basic_c64);

typedef struct localctx_struct {
	dbuf *outf;
} lctx;

static const char *get_token(u8 b)
{
	static const char *t[] = {"END","FOR","NEXT","DATA","INPUT#","INPUT","DIM",
		"READ","LET","GOTO","RUN","IF","RESTORE","GOSUB","RETURN","REM","STOP",
		"ON","WAIT","LOAD","SAVE","VERIFY","DEF","POKE","PRINT#","PRINT",
		"CONT","LIST","CLR","CMD","SYS","OPEN","CLOSE","GET","NEW","TAB(","TO",
		"FN","SPC(","THEN","NOT","STEP","+","-","*","/","^","AND","OR",">","=",
		"<","SGN","INT","ABS","USR","FRE","POS","SQR","RND","LOG","EXP","COS",
		"SIN","TAN","ATN","PEEK","LEN","STR$","VAL","ASC","CHR$","LEFT$",
		"RIGHT$","MID$","GO"};
	if(b>=0x80 && b<=0xcb) {
		return t[((int)b)-0x80];
	}
	return NULL;
}

static void process_line(deark *c, lctx *d, i64 file_pos, i64 mem_pos,
	i64 line_size)
{
	i64 line_num;
	i64 pos;
	u8 b;
	const char *token;
	int in_quote = 0;

	pos = file_pos;
	line_num = de_getu16le(pos);
	de_dbg(c, "line %d at %d, mem pos=%d, size=%d", (int)line_num, (int)file_pos,
		(int)mem_pos, (int)line_size);
	pos += 2;

	dbuf_printf(d->outf, "%d ", (int)line_num);

	while(pos < file_pos+line_size) {
		b = de_getbyte(pos);

		if(in_quote && b!=0x22) {
			// Quoted string data. Don't translate.
			// TODO: Can 0x00 occur in a string?
			dbuf_writebyte(d->outf, b);
			pos++;
			continue;
		}

		if(b>=0x80) {
			token = get_token(b);
			if(token) {
				dbuf_puts(d->outf, token);
			}
			else {
				dbuf_puts(d->outf, "***ERROR***");
			}
		}
		else if(b==0x00) {
			break;
		}
		else {
			dbuf_writebyte(d->outf, b);
			if(b==0x22) { // Quotation mark
				in_quote = !in_quote;
			}
		}
		pos++;
	}

	dbuf_puts(d->outf, "\n");
}

static void de_run_basic_c64(deark *c, de_module_params *mparams)
{
	lctx *d = NULL;
	i64 file_pos;
	i64 mem_start;
	i64 mem_pos;
	i64 next_line_ptr;
	i64 line_size;

	d = de_malloc(c, sizeof(lctx));

	d->outf = dbuf_create_output_file(c, "c64.bas", NULL, 0);

	// TODO: What if the first two bytes are not 0x01 0x08?
	mem_start = 0x0801;

	file_pos = 2;

	while(file_pos < c->infile->len) {
		mem_pos = file_pos - 2 + mem_start;

		next_line_ptr = de_getu16le(file_pos);
		if(next_line_ptr==0x0000) {
			break;
		}

		line_size = next_line_ptr - mem_pos - 2;
		if(line_size<1) {
			break;
		}
		process_line(c, d, file_pos+2, mem_pos+2, line_size);
		file_pos += 2 + line_size;
	}

	dbuf_close(d->outf);
	de_free(c, d);
}

static int de_identify_basic_c64(deark *c)
{
	u8 buf[8];

	if(de_input_file_has_ext(c, "prg")) {
		de_read(buf, 0, 2);
		if(!de_memcmp(buf, "\x01\x08", 2)) return 20;
	}
	return 0;
}

void de_module_basic_c64(deark *c, struct deark_module_info *mi)
{
	mi->id = "basic_c64";
	mi->desc = "Detokenize C64 BASIC";
	mi->run_fn = de_run_basic_c64;
	mi->identify_fn = de_identify_basic_c64;
}
