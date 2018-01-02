// This file is part of Deark.
// Copyright (C) 2016 Jason Summers
// See the file COPYING for terms of use.

#define DE_NOT_IN_MODULE
#include "deark-config.h"
#include "deark-private.h"
#include "deark-user.h"

#define DE_MODULE(x)      DE_DECLARE_MODULE(x);
#define DE_MODULE_LAST(x) DE_DECLARE_MODULE(x);
#include "deark-modules.h"
#undef DE_MODULE
#undef DE_MODULE_LAST

static void register_a_module(deark *c, de_module_getinfo_fn infofunc)
{
	infofunc(c, &c->module_info[c->num_modules++]);
}

void de_register_modules(deark *c)
{
	de_module_getinfo_fn infofunc_list[] = {
#define DE_MODULE(x)      x,
#define DE_MODULE_LAST(x) x
#include "deark-modules.h"
#undef DE_MODULE
#undef DE_MODULE_LAST
	};
	size_t num_modules;
	size_t i;

	num_modules = DE_ITEMS_IN_ARRAY(infofunc_list);

	if(!c->module_info) {
		c->module_info = de_malloc(c, num_modules*sizeof(struct deark_module_info));
	}

	for(i=0; i<num_modules; i++) {
		register_a_module(c, infofunc_list[i]);
	}
}
