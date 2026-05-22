# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side security scanners -
# binary hardening, network exposure, outgoing connections, rules over
# captured traffic, and the reverse engineering tools. Built as a shared
# library on the engine platform and as a static library when agents or
# agent apps are built.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine') \
    or get_option('agents').split().length() != 0 \
    or get_option('agent-apps').split().length() != 0
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
