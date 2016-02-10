// This file is part of Deark, by Jason Summers.
// This software is in the public domain. See the file COPYING for details.

// When you add a module, list it in this file and deark-modules.h.

#include "deark-config.h"

#include "deark-modules.h"

static void register_a_module(deark *c, de_module_getinfo_fn infofunc)
{
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
		de_module_gif,
		de_module_eps,
		de_module_msp,
		de_module_pcpaint,
		de_module_bmp,
		de_module_os2bmp,
		de_module_psd,
		de_module_amigaicon,
		de_module_epocimage,
		de_module_psionpic,
		de_module_psionapp,
		de_module_exe,
		de_module_ani,
		de_module_riff,
		de_module_jpeg2000,
		de_module_mp4,
		de_module_j2c,
		de_module_png,
		de_module_wmf,
		de_module_emf,
		de_module_rpm,
		de_module_binhex,
		de_module_ilbm,
		de_module_icns,
		de_module_farbfeld,
		de_module_dcx,
		de_module_pgc,
		de_module_pgx,
		de_module_bpg,
		de_module_fnt,
		de_module_ar,
		de_module_uuencode,
		de_module_ascii85,
		de_module_hpicn,
		de_module_macpaint,
		de_module_pict,
		de_module_nol,
		de_module_ngg,
		de_module_npm,
		de_module_nlm,
		de_module_nsl,
		de_module_xbin,
		de_module_abk,
		de_module_amos_source,
		de_module_mbk,
		de_module_pff2,
		de_module_tivariable,
		de_module_olpc565,
		de_module_awbm,
		de_module_lss16,
		de_module_atr,
		de_module_t64,
		de_module_mrw,
		de_module_cardfile,
		de_module_graspgl,
		de_module_zlib,
		de_module_tim,
		de_module_bsave,
		de_module_zip,
		de_module_compress,
		de_module_sauce,
		de_module_ansiart,
		de_module_bintext,
		de_module_icedraw,
		de_module_makichan,
		de_module_xpuzzle,
		de_module_grob,
		de_module_shg,
		de_module_alias_pix,
		de_module_prismpaint,
		de_module_atari_cas,
		de_module_vbm,
		de_module_winzle,
		de_module_bob,
		de_module_hr,
		de_module_applevol,
		de_module_basic_c64,
		de_module_ico,
		de_module_pcx,
		de_module_rsc,
		de_module_gemraster,
		de_module_gemmeta,
		de_module_tga,
		de_module_fp_art,
		de_module_pf_pgf,
		de_module_qtif,
		de_module_degas,
		de_module_tinystuff,
		de_module_neochrome,
		de_module_neochrome_ani,
		de_module_iim,
		de_module_ripicon,
		de_module_insetpix,
		de_module_printshop,
		de_module_newprintshop,
		de_module_printmaster,
		de_module_rosprite,
		de_module_eggpaint,
		de_module_indypaint,
		de_module_ftc,
		de_module_graspfont,
		de_module_gemfont,
		de_module_crg,
		de_module_ybm,
		de_module_fpaint_pi4,
		de_module_fpaint_pi9,
		de_module_atari_pi7,
		de_module_falcon_xga,
		de_module_alphabmp,
		de_module_pm_xv,
		de_module_xxencode,
		de_module_base64,
		de_module_base16,
		de_module_jpegscan,
		de_module_vgafont,
		de_module_crc32,
		de_module_copy,
		de_module_unsupported
	};
	size_t num_modules;
	size_t i;

	num_modules = sizeof(infofunc_list) / sizeof(infofunc_list[0]);

	if(!c->module_info) {
		c->module_info = de_malloc(c, num_modules*sizeof(struct deark_module_info));
	}

	for(i=0; i<num_modules; i++) {
		register_a_module(c, infofunc_list[i]);
	}
}
