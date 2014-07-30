// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

#include "deark-config.h"

#include "deark-modules.h"

static void register_a_module(deark *c, de_module_getinfo_fn infofunc)
{
	if(c->num_modules>=DE_MAX_MODULES) {
		de_err(c, "Internal: Too many modules\n");
		de_fatalerror(c);
		return;
	}

	infofunc(c, &c->module_info[c->num_modules++]);
}

void de_register_modules(deark *c)
{
	register_a_module(c, de_module_jpeg);
	register_a_module(c, de_module_tiff);
	register_a_module(c, de_module_eps);
	register_a_module(c, de_module_msp);
	register_a_module(c, de_module_pcpaint);
	register_a_module(c, de_module_os2bmp);
	register_a_module(c, de_module_psd);
	register_a_module(c, de_module_amigaicon);
	register_a_module(c, de_module_epocimage);
	register_a_module(c, de_module_psionpic);
	register_a_module(c, de_module_psionapp);
	register_a_module(c, de_module_exe);
	register_a_module(c, de_module_ani);
	register_a_module(c, de_module_jpeg2000);
	register_a_module(c, de_module_dcx);
	register_a_module(c, de_module_fnt);
	register_a_module(c, de_module_hpicn);
	register_a_module(c, de_module_macpaint);
	register_a_module(c, de_module_nol);
	register_a_module(c, de_module_ngg);
	register_a_module(c, de_module_npm);
	register_a_module(c, de_module_nlm);
	register_a_module(c, de_module_nsl);
	register_a_module(c, de_module_graspgl);
	register_a_module(c, de_module_zlib);
	register_a_module(c, de_module_bsave);
	register_a_module(c, de_module_zip);
	register_a_module(c, de_module_xpuzzle);
	register_a_module(c, de_module_copy);
	register_a_module(c, de_module_unsupported);
}
