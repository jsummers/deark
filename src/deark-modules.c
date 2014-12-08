// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// When you add a module, list it in this file and deark-modules.h.

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
	// The order that modules appear in this list can affect performance, and
	// in some cases can affect what format a file will be detected as.
	// The more common and easily-identified a format is, the earlier it should
	// appear.
	de_module_getinfo_fn infofunc_list[] = {
		de_module_jpeg,
		de_module_tiff,
		de_module_eps,
		de_module_msp,
		de_module_pcpaint,
		de_module_os2bmp,
		de_module_psd,
		de_module_amigaicon,
		de_module_epocimage,
		de_module_psionpic,
		de_module_psionapp,
		de_module_exe,
		de_module_ani,
		de_module_jpeg2000,
		de_module_rpm,
		de_module_ilbm,
		de_module_icns,
		de_module_dcx,
		de_module_fnt,
		de_module_hpicn,
		de_module_macpaint,
		de_module_nol,
		de_module_ngg,
		de_module_npm,
		de_module_nlm,
		de_module_nsl,
		de_module_tivariable,
		de_module_awbm,
		de_module_lss16,
		de_module_atr,
		de_module_t64,
		de_module_mrw,
		de_module_cardfile,
		de_module_graspgl,
		de_module_zlib,
		de_module_bsave,
		de_module_zip,
		de_module_xpuzzle,
		de_module_grob,
		de_module_vivid,
		de_module_atari_cas,
		de_module_vbm,
		de_module_winzle,
		de_module_bob,
		de_module_hr,
		de_module_applevol,
		de_module_basic_c64,
		de_module_ico,
		de_module_qtif,
		de_module_ripicon,
		de_module_printshop,
		de_module_newprintshop,
		de_module_printmaster,
		de_module_jpegscan,
		de_module_copy,
		de_module_unsupported,
		NULL
	};
	size_t i;

	for(i=0; infofunc_list[i]!=NULL; i++) {
		register_a_module(c, infofunc_list[i]);
	}
}
