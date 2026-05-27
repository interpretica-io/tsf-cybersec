# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side security scanners -
# binary hardening, network exposure, outgoing connections, rules over
# captured traffic, and the reverse engineering tools. Built as a
# shared library on the engine platform; see below for why there is no
# static one.

if get_option('engine')
    build_lib_shared = true
endif
# Shared on the engine and nothing on an agent, which is the rule TE
# applies to its own engine-side libraries. The default for an external
# repository is the opposite - lib/meson.build builds one static and
# agent-side, because that is what external libraries used to be - and
# the obvious override, "static as well when there are agents", is the
# rule for a library that lives on both sides. This one does not: it
# calls tapi and tapi_job, which are engine libraries with no static
# variant, so asking for a static build of it fails the configure with
# "Tried to get unknown variable dep_lib_static_tapi" before a line is
# compiled.
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_binscan.h',
    'tapi_cybersec.h',
    'tapi_egress.h',
    'tapi_frida.h',
    'tapi_netexpose.h',
    'tapi_objdump.h',
    'tapi_sniffrules.h',
)

sources += files(
    'tapi_binscan.c',
    'tapi_cybersec.c',
    'tapi_egress.c',
    'tapi_frida.c',
    'tapi_netexpose.c',
    'tapi_objdump.c',
    'tapi_sniffrules.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_rpc',
    'tapi_tad',
    'tapi_devtool',
    'tapi_kernel',
]
