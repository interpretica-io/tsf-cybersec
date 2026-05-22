/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Binary hardening scanner
 *
 * The binary is fetched to the engine and its ELF structure is read
 * here, with every field taken by offset and byte order, so that a
 * binary for another architecture or endianness reads correctly.
 */

#define TE_LGR_USER "TAPI BINSCAN"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_file.h"
#include "te_string.h"

#include "tapi_binscan.h"

/** @name ELF constants, so that <elf.h> is not needed on the engine. */
/**@{*/
#define BS_EI_CLASS         4
#define BS_EI_DATA          5
#define BS_ELFCLASS32       1
#define BS_ELFCLASS64       2
#define BS_ELFDATA2LSB      1
#define BS_ELFDATA2MSB      2

#define BS_ET_REL           1
#define BS_ET_EXEC          2
#define BS_ET_DYN           3

#define BS_PT_LOAD          1
#define BS_PT_DYNAMIC       2
#define BS_PT_INTERP        3
#define BS_PT_GNU_STACK     0x6474e551
#define BS_PT_GNU_RELRO     0x6474e552

#define BS_PF_X             0x1
#define BS_PF_W             0x2

#define BS_SHT_SYMTAB       2
#define BS_SHT_DYNSYM       11

#define BS_DT_NULL          0
#define BS_DT_NEEDED        1
#define BS_DT_RPATH         15
#define BS_DT_TEXTREL       22
#define BS_DT_BIND_NOW      24
#define BS_DT_RUNPATH       29
#define BS_DT_FLAGS         30
#define BS_DT_FLAGS_1       0x6ffffffb

#define BS_DF_TEXTREL       0x04
#define BS_DF_BIND_NOW      0x08
#define BS_DF_1_NOW         0x00000001
/**@}*/

/** Largest binary worth pulling to the engine, bytes. */
#define BS_MAX_SIZE     (256 * 1024 * 1024)

/** A binary loaded into engine memory, with its ELF shape decoded. */
typedef struct bs_image {
    const uint8_t *data;
    size_t len;
    bool le;
    bool elf64;
    unsigned int e_type;
    unsigned int e_machine;
    uint64_t e_phoff;
    uint64_t e_shoff;
    unsigned int e_phentsize;
    unsigned int e_phnum;
    unsigned int e_shentsize;
    unsigned int e_shnum;
} bs_image;

static uint16_t
bs_rd16(const uint8_t *p, bool le)
{
    return le ? (uint16_t)(p[0] | (p[1] << 8))
              : (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t
bs_rd32(const uint8_t *p, bool le)
{
    return le ? ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24))
              : (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

static uint64_t
bs_rd64(const uint8_t *p, bool le)
{
    return le ? ((uint64_t)bs_rd32(p, true) |
                 ((uint64_t)bs_rd32(p + 4, true) << 32))
              : (((uint64_t)bs_rd32(p, false) << 32) |
                 (uint64_t)bs_rd32(p + 4, false));
}

/** Read a word that is 32 bits in ELF32 and 64 bits in ELF64. */
static uint64_t
bs_rdw(const bs_image *img, const uint8_t *p)
{
    return img->elf64 ? bs_rd64(p, img->le) : bs_rd32(p, img->le);
}

/** Check that [offset, offset + size) is inside the image. */
static bool
bs_in_range(const bs_image *img, uint64_t offset, uint64_t size)
{
    return offset <= img->len && size <= img->len - offset;
}

/** Read a NUL-terminated string that must end inside the image. */
static char *
bs_strdup_at(const bs_image *img, uint64_t offset)
{
    const uint8_t *start;
    const uint8_t *end;

    if (offset >= img->len)
        return NULL;

    start = img->data + offset;
    end = memchr(start, '\0', img->len - offset);
    if (end == NULL)
        return NULL;

    return TE_STRDUP((const char *)start);
}

/** Decode the ELF header. */
static te_errno
bs_parse_header(bs_image *img)
{
    const uint8_t *e = img->data;

    if (img->len < 64 || memcmp(e, "\177ELF", 4) != 0)
        return TE_RC(TE_TAPI, TE_EBADMSG);

    switch (e[BS_EI_CLASS])
    {
        case BS_ELFCLASS32: img->elf64 = false; break;
        case BS_ELFCLASS64: img->elf64 = true; break;
        default: return TE_RC(TE_TAPI, TE_EBADMSG);
    }

    switch (e[BS_EI_DATA])
    {
        case BS_ELFDATA2LSB: img->le = true; break;
        case BS_ELFDATA2MSB: img->le = false; break;
        default: return TE_RC(TE_TAPI, TE_EBADMSG);
    }

    img->e_type = bs_rd16(e + 16, img->le);
    img->e_machine = bs_rd16(e + 18, img->le);

    if (img->elf64)
    {
        img->e_phoff = bs_rd64(e + 32, img->le);
        img->e_shoff = bs_rd64(e + 40, img->le);
        img->e_phentsize = bs_rd16(e + 54, img->le);
        img->e_phnum = bs_rd16(e + 56, img->le);
        img->e_shentsize = bs_rd16(e + 58, img->le);
        img->e_shnum = bs_rd16(e + 60, img->le);
    }
    else
    {
        img->e_phoff = bs_rd32(e + 28, img->le);
        img->e_shoff = bs_rd32(e + 32, img->le);
        img->e_phentsize = bs_rd16(e + 42, img->le);
        img->e_phnum = bs_rd16(e + 44, img->le);
        img->e_shentsize = bs_rd16(e + 46, img->le);
        img->e_shnum = bs_rd16(e + 48, img->le);
    }

    return 0;
}

/** Get program header @p i, or @c NULL when it is out of the image. */
static const uint8_t *
bs_phdr(const bs_image *img, unsigned int i)
{
    uint64_t offset = img->e_phoff + (uint64_t)i * img->e_phentsize;

    if (img->e_phentsize < (img->elf64 ? 56u : 32u) ||
        !bs_in_range(img, offset, img->e_phentsize))
        return NULL;

    return img->data + offset;
}

/** Get section header @p i, or @c NULL when it is out of the image. */
static const uint8_t *
bs_shdr(const bs_image *img, unsigned int i)
{
    uint64_t offset = img->e_shoff + (uint64_t)i * img->e_shentsize;

    if (img->e_shoff == 0 || img->e_shentsize < (img->elf64 ? 64u : 40u) ||
        !bs_in_range(img, offset, img->e_shentsize))
        return NULL;

    return img->data + offset;
}

static uint32_t
bs_phdr_type(const bs_image *img, const uint8_t *ph)
{
    return bs_rd32(ph, img->le);
}

static uint32_t
bs_phdr_flags(const bs_image *img, const uint8_t *ph)
{
    return img->elf64 ? bs_rd32(ph + 4, img->le) : bs_rd32(ph + 24, img->le);
}

static uint64_t
bs_phdr_offset(const bs_image *img, const uint8_t *ph)
{
    return img->elf64 ? bs_rd64(ph + 8, img->le) : bs_rd32(ph + 4, img->le);
}

static uint64_t
bs_phdr_filesz(const bs_image *img, const uint8_t *ph)
{
    return img->elf64 ? bs_rd64(ph + 32, img->le) : bs_rd32(ph + 16, img->le);
}

static uint32_t
bs_shdr_type(const bs_image *img, const uint8_t *sh)
{
    return bs_rd32(sh + 4, img->le);
}

static uint32_t
bs_shdr_link(const bs_image *img, const uint8_t *sh)
{
    return img->elf64 ? bs_rd32(sh + 40, img->le) : bs_rd32(sh + 24, img->le);
}

static uint64_t
bs_shdr_offset(const bs_image *img, const uint8_t *sh)
{
    return img->elf64 ? bs_rd64(sh + 24, img->le) : bs_rd32(sh + 16, img->le);
}

static uint64_t
bs_shdr_size(const bs_image *img, const uint8_t *sh)
{
    return img->elf64 ? bs_rd64(sh + 32, img->le) : bs_rd32(sh + 20, img->le);
}

static uint64_t
bs_shdr_entsize(const bs_image *img, const uint8_t *sh)
{
    return img->elf64 ? bs_rd64(sh + 56, img->le) : bs_rd32(sh + 36, img->le);
}

/** Walk the segments: NX, W+X, interpreter, RELRO, the dynamic section. */
static void
bs_scan_segments(const bs_image *img, tapi_binscan_info *info,
                 uint64_t *dyn_offset, uint64_t *dyn_size)
{
    bool has_interp = false;
    bool has_dynamic = false;
    bool has_relro = false;
    unsigned int i;

    info->nx_unknown = true;

    for (i = 0; i < img->e_phnum; i++)
    {
        const uint8_t *ph = bs_phdr(img, i);
        uint32_t type;
        uint32_t flags;

        if (ph == NULL)
            break;

        type = bs_phdr_type(img, ph);
        flags = bs_phdr_flags(img, ph);

        switch (type)
        {
            case BS_PT_LOAD:
                if ((flags & BS_PF_W) != 0 && (flags & BS_PF_X) != 0)
                    info->wx_segment = true;
                break;

            case BS_PT_GNU_STACK:
                info->nx_unknown = false;
                info->nx = (flags & BS_PF_X) == 0;
                break;

            case BS_PT_GNU_RELRO:
                has_relro = true;
                break;

            case BS_PT_INTERP:
            {
                uint64_t offset = bs_phdr_offset(img, ph);

                has_interp = true;
                if (bs_in_range(img, offset, bs_phdr_filesz(img, ph)))
                    info->interp = bs_strdup_at(img, offset);
                break;
            }

            case BS_PT_DYNAMIC:
                has_dynamic = true;
                *dyn_offset = bs_phdr_offset(img, ph);
                *dyn_size = bs_phdr_filesz(img, ph);
                break;

            default:
                break;
        }
    }

    if (has_relro)
        info->relro = TAPI_BINSCAN_RELRO_PARTIAL;

    info->static_linked = !has_interp && !has_dynamic;

    switch (img->e_type)
    {
        case BS_ET_EXEC:
            info->kind = TAPI_BINSCAN_KIND_EXEC;
            break;
        case BS_ET_DYN:
            info->kind = has_interp ? TAPI_BINSCAN_KIND_PIE
                                    : TAPI_BINSCAN_KIND_SHARED;
            break;
        case BS_ET_REL:
            info->kind = TAPI_BINSCAN_KIND_RELOC;
            break;
        default:
            info->kind = TAPI_BINSCAN_KIND_OTHER;
            break;
    }
}

/**
 * Walk the dynamic section: RPATH, RUNPATH, NEEDED, text relocations
 * and whether relocations are resolved at startup.
 *
 * The string table is found through the section headers rather than
 * through @c DT_STRTAB, because the latter is a virtual address and the
 * sections give a file offset directly.
 */
static void
bs_scan_dynamic(const bs_image *img, tapi_binscan_info *info,
                uint64_t dyn_offset, uint64_t dyn_size)
{
    te_vec needed = TE_VEC_INIT(char *);
    uint64_t strtab_offset = 0;
    uint64_t strtab_size = 0;
    uint64_t entsize = img->elf64 ? 16 : 8;
    uint64_t rpath_off = 0;
    uint64_t runpath_off = 0;
    bool bind_now = false;
    uint64_t i;
    unsigned int s;

    if (dyn_size == 0 || !bs_in_range(img, dyn_offset, dyn_size))
        return;

    /* The .dynstr section is the one .dynamic's section header links to. */
    for (s = 0; s < img->e_shnum; s++)
    {
        const uint8_t *sh = bs_shdr(img, s);

        if (sh == NULL)
            break;

        if (bs_shdr_type(img, sh) == BS_SHT_DYNSYM)
        {
            const uint8_t *str_sh = bs_shdr(img, bs_shdr_link(img, sh));

            if (str_sh != NULL)
            {
                strtab_offset = bs_shdr_offset(img, str_sh);
                strtab_size = bs_shdr_size(img, str_sh);
            }
            break;
        }
    }

    for (i = 0; i + entsize <= dyn_size; i += entsize)
    {
        const uint8_t *d = img->data + dyn_offset + i;
        uint64_t tag = bs_rdw(img, d);
        uint64_t val = bs_rdw(img, d + (img->elf64 ? 8 : 4));

        if (tag == BS_DT_NULL)
            break;

        switch (tag)
        {
            case BS_DT_NEEDED:
                if (strtab_size != 0 && val < strtab_size)
                {
                    char *name = bs_strdup_at(img, strtab_offset + val);

                    if (name != NULL)
                        TE_VEC_APPEND(&needed, name);
                }
                break;

            case BS_DT_RPATH:
                rpath_off = val;
                break;

            case BS_DT_RUNPATH:
                runpath_off = val;
                break;

            case BS_DT_TEXTREL:
                info->textrel = true;
                break;

            case BS_DT_BIND_NOW:
                bind_now = true;
                break;

            case BS_DT_FLAGS:
                if ((val & BS_DF_BIND_NOW) != 0)
                    bind_now = true;
                if ((val & BS_DF_TEXTREL) != 0)
                    info->textrel = true;
                break;

            case BS_DT_FLAGS_1:
                if ((val & BS_DF_1_NOW) != 0)
                    bind_now = true;
                break;

            default:
                break;
        }
    }

    if (strtab_size != 0)
    {
        if (rpath_off != 0 && rpath_off < strtab_size)
            info->rpath = bs_strdup_at(img, strtab_offset + rpath_off);
        if (runpath_off != 0 && runpath_off < strtab_size)
            info->runpath = bs_strdup_at(img, strtab_offset + runpath_off);
    }

    if (bind_now && info->relro == TAPI_BINSCAN_RELRO_PARTIAL)
        info->relro = TAPI_BINSCAN_RELRO_FULL;

    info->n_needed = te_vec_size(&needed);
    if (info->n_needed != 0)
    {
        info->needed = TE_ALLOC(info->n_needed * sizeof(*info->needed));
        memcpy(info->needed, needed.data.ptr,
               info->n_needed * sizeof(*info->needed));
    }
    /* The vector has no destructor, so the strings survive it. */
    te_vec_free(&needed);
}

/** Does this symbol name mean the binary has stack protection? */
static bool
bs_name_is_canary(const char *name)
{
    return strcmp(name, "__stack_chk_fail") == 0 ||
           strcmp(name, "__stack_chk_fail_local") == 0 ||
           strcmp(name, "__stack_chk_guard") == 0 ||
           strcmp(name, "__intel_security_cookie") == 0;
}

/** Does this symbol name come from _FORTIFY_SOURCE? */
static bool
bs_name_is_fortify(const char *name)
{
    size_t len = strlen(name);

    return len > 6 && strncmp(name, "__", 2) == 0 &&
           strcmp(name + len - 4, "_chk") == 0;
}

/** Walk every symbol table for the marks the hardening options leave. */
static void
bs_scan_symbols(const bs_image *img, tapi_binscan_info *info)
{
    unsigned int s;

    info->stripped = true;

    for (s = 0; s < img->e_shnum; s++)
    {
        const uint8_t *sh = bs_shdr(img, s);
        const uint8_t *str_sh;
        uint64_t sym_offset;
        uint64_t sym_size;
        uint64_t sym_entsize;
        uint64_t str_offset;
        uint64_t str_size;
        uint32_t type;
        uint64_t i;

        if (sh == NULL)
            break;

        type = bs_shdr_type(img, sh);
        if (type != BS_SHT_SYMTAB && type != BS_SHT_DYNSYM)
            continue;

        if (type == BS_SHT_SYMTAB)
            info->stripped = false;

        sym_offset = bs_shdr_offset(img, sh);
        sym_size = bs_shdr_size(img, sh);
        sym_entsize = bs_shdr_entsize(img, sh);
        if (sym_entsize == 0)
            sym_entsize = img->elf64 ? 24 : 16;

        str_sh = bs_shdr(img, bs_shdr_link(img, sh));
        if (str_sh == NULL || !bs_in_range(img, sym_offset, sym_size))
            continue;

        str_offset = bs_shdr_offset(img, str_sh);
        str_size = bs_shdr_size(img, str_sh);
        if (!bs_in_range(img, str_offset, str_size))
            continue;

        for (i = 0; i + sym_entsize <= sym_size; i += sym_entsize)
        {
            const uint8_t *sym = img->data + sym_offset + i;
            uint32_t name_off = bs_rd32(sym, img->le);
            const char *name;

            if (name_off == 0 || name_off >= str_size)
                continue;

            name = (const char *)img->data + str_offset + name_off;
            if (memchr(name, '\0', str_size - name_off) == NULL)
                continue;

            if (bs_name_is_canary(name))
                info->canary = true;
            else if (bs_name_is_fortify(name))
                info->fortify = true;
        }
    }
}

/* See description in tapi_binscan.h */
te_errno
tapi_binscan_inspect(const char *ta, const char *path,
                     tapi_binscan_info *info)
{
    te_string local = TE_STRING_INIT;
    te_string content = TE_STRING_INIT;
    uint64_t dyn_offset = 0;
    uint64_t dyn_size = 0;
    bs_image img;
    te_errno rc;

    memset(info, 0, sizeof(*info));
    memset(&img, 0, sizeof(img));

    tapi_file_make_custom_pathname(&local, NULL, ".binscan");

    rc = tapi_file_copy_ta(ta, path, NULL, local.ptr);
    if (rc != 0)
    {
        ERROR("Failed to fetch '%s' from TA %s: %r", path, ta, rc);
        goto out;
    }

    rc = te_file_read_string(&content, true, BS_MAX_SIZE, "%s", local.ptr);
    if (rc != 0)
    {
        ERROR("Failed to read the copy of '%s': %r", path, rc);
        goto out;
    }

    img.data = (const uint8_t *)content.ptr;
    img.len = content.len;

    rc = bs_parse_header(&img);
    if (rc != 0)
    {
        RING("'%s' on TA %s is not an ELF object", path, ta);
        goto out;
    }

    info->elf = true;
    info->elf_class = img.elf64 ? 64 : 32;
    info->little_endian = img.le;
    info->machine = img.e_machine;

    bs_scan_segments(&img, info, &dyn_offset, &dyn_size);
    bs_scan_dynamic(&img, info, dyn_offset, dyn_size);
    bs_scan_symbols(&img, info);

out:
    if (local.ptr != NULL)
        remove(local.ptr);
    te_string_free(&local);
    te_string_free(&content);

    if (rc != 0)
        tapi_binscan_info_free(info);

    return rc;
}

/* See description in tapi_binscan.h */
void
tapi_binscan_info_log(const tapi_binscan_info *info, const char *path)
{
    size_t i;

    if (!info->elf)
    {
        RING("%s: not an ELF object", path);
        return;
    }

    RING("%s: ELF%u %s, machine %u, %s", path, info->elf_class,
         info->little_endian ? "LE" : "BE", info->machine,
         tapi_binscan_kind2str(info->kind));
    RING("  NX: %s", info->nx_unknown ? "no PT_GNU_STACK" :
                     info->nx ? "yes" : "no");
    RING("  RELRO: %s", tapi_binscan_relro2str(info->relro));
    RING("  stack protector: %s", info->canary ? "yes" : "no");
    RING("  FORTIFY_SOURCE: %s", info->fortify ? "yes" : "no");
    RING("  symbols: %s", info->stripped ? "stripped" : "present");
    RING("  linking: %s", info->static_linked ? "static" : "dynamic");
    if (info->textrel)
        RING("  text relocations: yes");
    if (info->wx_segment)
        RING("  writable executable segment: yes");
    if (info->interp != NULL)
        RING("  interpreter: %s", info->interp);
    if (info->rpath != NULL)
        RING("  RPATH: %s", info->rpath);
    if (info->runpath != NULL)
        RING("  RUNPATH: %s", info->runpath);
    for (i = 0; i < info->n_needed; i++)
        RING("  needs: %s", info->needed[i]);
}

/* See description in tapi_binscan.h */
void
tapi_binscan_info_free(tapi_binscan_info *info)
{
    size_t i;

    free(info->rpath);
    free(info->runpath);
    free(info->interp);
    for (i = 0; i < info->n_needed; i++)
        free(info->needed[i]);
    free(info->needed);

    memset(info, 0, sizeof(*info));
}

const tapi_binscan_policy tapi_binscan_default_policy = {
    .require_pie          = true,
    .require_nx           = true,
    .require_full_relro   = true,
    .report_partial_relro = true,
    .require_canary       = true,
    .require_fortify      = false,
    .forbid_rpath         = true,
    .forbid_runpath       = true,
    .forbid_textrel       = true,
    .forbid_wx            = true,
};

/** Is this search path one an attacker could aim at? */
static bool
bs_path_is_unsafe(const char *path)
{
    return path[0] != '/';
}

/* See description in tapi_binscan.h */
te_errno
tapi_binscan_check(const char *ta, const char *path,
                   const tapi_binscan_policy *policy,
                   tapi_cybersec_report *report)
{
    tapi_binscan_info info;
    te_errno rc;

    if (policy == NULL)
        policy = &tapi_binscan_default_policy;

    rc = tapi_binscan_inspect(ta, path, &info);
    if (rc != 0)
        return rc;

    if (!info.elf)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "binary.not-elf", path,
                                 "not an ELF object, nothing to check");
        goto out;
    }

    tapi_binscan_info_log(&info, path);

    if (policy->require_pie && info.kind == TAPI_BINSCAN_KIND_EXEC)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "binary.not-pie", path,
                                 "position-dependent executable: it always "
                                 "loads at the same address");
    }

    if (policy->require_nx && (info.nx_unknown || !info.nx))
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "binary.no-nx", path,
                                 info.nx_unknown ?
                                     "no PT_GNU_STACK segment, so the stack "
                                     "policy is whatever the kernel defaults "
                                     "to" :
                                     "the stack is executable");
    }

    if (policy->require_full_relro &&
        info.relro == TAPI_BINSCAN_RELRO_NONE)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "binary.no-relro", path,
                                 "relocations stay writable for the whole "
                                 "life of the process");
    }
    else if (policy->report_partial_relro &&
             info.relro == TAPI_BINSCAN_RELRO_PARTIAL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                                 "binary.partial-relro", path,
                                 "the GOT stays writable: link with -z now "
                                 "for full RELRO");
    }

    if (policy->require_canary && !info.canary)
    {
        tapi_cybersec_report_add(report,
                                 info.stripped ? TAPI_CYBERSEC_SEV_LOW
                                               : TAPI_CYBERSEC_SEV_MEDIUM,
                                 "binary.no-canary", path,
                                 info.stripped ?
                                     "no stack protector symbol, but the "
                                     "binary is stripped, so this may be a "
                                     "false alarm" :
                                     "built without -fstack-protector");
    }

    if (policy->require_fortify && !info.fortify)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                                 "binary.no-fortify", path,
                                 "no _FORTIFY_SOURCE wrappers are linked in");
    }

    if (policy->forbid_rpath && info.rpath != NULL)
    {
        bool unsafe = bs_path_is_unsafe(info.rpath);

        tapi_cybersec_report_add(report,
                                 unsafe ? TAPI_CYBERSEC_SEV_HIGH
                                        : TAPI_CYBERSEC_SEV_MEDIUM,
                                 unsafe ? "binary.rpath-relative"
                                        : "binary.rpath",
                                 path,
                                 "DT_RPATH is '%s' and it is searched before "
                                 "the system paths", info.rpath);
    }

    if (policy->forbid_runpath && info.runpath != NULL)
    {
        bool unsafe = bs_path_is_unsafe(info.runpath);

        tapi_cybersec_report_add(report,
                                 unsafe ? TAPI_CYBERSEC_SEV_HIGH
                                        : TAPI_CYBERSEC_SEV_LOW,
                                 unsafe ? "binary.runpath-relative"
                                        : "binary.runpath",
                                 path,
                                 "DT_RUNPATH is '%s'", info.runpath);
    }

    if (policy->forbid_textrel && info.textrel)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "binary.textrel", path,
                                 "text relocations force the code pages to "
                                 "be writable while they are relocated");
    }

    if (policy->forbid_wx && info.wx_segment)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "binary.wx-segment", path,
                                 "a segment is both writable and executable");
    }

out:
    tapi_binscan_info_free(&info);

    return 0;
}

/* See description in tapi_binscan.h */
const char *
tapi_binscan_relro2str(tapi_binscan_relro relro)
{
    switch (relro)
    {
        case TAPI_BINSCAN_RELRO_PARTIAL:
            return "partial";
        case TAPI_BINSCAN_RELRO_FULL:
            return "full";
        default:
            return "none";
    }
}

/* See description in tapi_binscan.h */
const char *
tapi_binscan_kind2str(tapi_binscan_kind kind)
{
    switch (kind)
    {
        case TAPI_BINSCAN_KIND_EXEC:
            return "executable";
        case TAPI_BINSCAN_KIND_PIE:
            return "position-independent executable";
        case TAPI_BINSCAN_KIND_SHARED:
            return "shared library";
        case TAPI_BINSCAN_KIND_RELOC:
            return "relocatable object";
        default:
            return "other";
    }
}
