/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas@tklengyel.com)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "arch/arm_aarch64.h"

// 0th Level Page Table Index (4kb Pages)
static inline
uint64_t zero_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 39) & VMI_BIT_MASK(0,8);
}

// 0th Level Descriptor (4kb Pages)
static inline
void get_zero_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.zld_location = (dtb & VMI_BIT_MASK(12,47)) | (zero_level_4kb_table_index(vaddr) << 3);
    uint64_t zld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.zld_location, &zld_v)) {
        info->arm_aarch64.zld_value = zld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read zld4 0x%"PRIx64"\n", info->arm_aarch64.zld_location);
}

// 1st Level Page Table Index (4kb Pages)
static inline
uint64_t first_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 30) & VMI_BIT_MASK(0,8);
}

// 1st Level Descriptor (4kb Pages)
static inline
void get_first_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & VMI_BIT_MASK(12,47)) | (first_level_4kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read fld4 0x%"PRIx64"\n", info->arm_aarch64.fld_location);
}

// 1st Level Page Table Index (64kb Pages)
static inline
uint64_t first_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 42) & VMI_BIT_MASK(0,5);
}

// 1st Level Descriptor (64kb Pages)
static inline
void get_first_level_64kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & VMI_BIT_MASK(9,47)) | (first_level_64kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read fld64 0x%"PRIx64"\n", info->arm_aarch64.fld_location);
}

// 2nd Level Page Table Index (4kb Pages)
static inline
uint64_t second_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 21) & VMI_BIT_MASK(0,8);
}

// 2nd Level Page Table Descriptor (4kb Pages)
static inline
void get_second_level_4kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & VMI_BIT_MASK(12,47)) | (second_level_4kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read sld4 0x%"PRIx64"\n", info->arm_aarch64.sld_location);
}

// 2nd Level Page Table Index (64kb Pages)
static inline
uint64_t second_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 29) & VMI_BIT_MASK(0,12);
}

// 2nd Level Page Table Descriptor (64kb Pages)
static inline
void get_second_level_64kb_descriptor(vmi_instance_t vmi, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & VMI_BIT_MASK(16,47)) | (second_level_64kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read sld64 0x%"PRIx64"\n", info->arm_aarch64.sld_location);
}

// 3rd Level Page Table Index (4kb Pages)
static inline
uint64_t third_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 12) & VMI_BIT_MASK(0,8);
}

// 3rd Level Page Table Descriptor (4kb Pages)
static inline
void get_third_level_4kb_descriptor(vmi_instance_t vmi, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & VMI_BIT_MASK(12,47)) | (third_level_4kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read tld4 0x%"PRIx64"\n", info->arm_aarch64.tld_location);
}

// 3rd Level Page Table Index (64kb Pages)
static inline
uint64_t third_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 16) & VMI_BIT_MASK(0,12);
}

// 3rd Level Page Table Descriptor (64kb Pages)
static inline
void get_third_level_64kb_descriptor(vmi_instance_t vmi, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & VMI_BIT_MASK(16,47)) | (third_level_64kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (VMI_SUCCESS == vmi_read_64_pa(vmi, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
    else
        dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: Failed to read tld64 0x%"PRIx64"\n", info->arm_aarch64.tld_location);
}

// Based on ARM Reference Manual
// D4.3 ARM ARMv8-A VMSAv8-64 translation table format descriptors
// K7.1.2 ARM ARMv8-A Full translation flows for VMSAv8-64 address translation
status_t v2p_aarch64 (vmi_instance_t vmi,
                      addr_t UNUSED(npt),
                      page_mode_t UNUSED(npm),
                      addr_t pt,
                      addr_t vaddr,
                      page_info_t *info)
{
    status_t status = VMI_FAILURE;

    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch64 PTLookup: vaddr = 0x%.16"PRIx64", pt = 0x%.16"PRIx64"\n", vaddr, pt);

    page_size_t ps;
    uint8_t levels;
    uint8_t va_width;

    // TODO: actually look at t1sz and t0sz.
    if ((vaddr & VMI_BIT_MASK(47,63)) == VMI_BIT_MASK(47,63)) {
        ps = vmi->arm64.tg1;
        va_width = 64 - vmi->arm64.t1sz;
    } else {
        ps = vmi->arm64.tg0;
        va_width = 64 - vmi->arm64.t0sz;
    }

    if ( VMI_PS_4KB == ps )
        levels = va_width == 39 ? 3 : 4;
    else if ( VMI_PS_64KB == ps )
        levels = va_width == 42 ? 2 : 3;
    else {
        errprint("16KB granule size ARM64 lookups are not yet implemented\n");
        goto done;
    }

    if ( 4 == levels ) {
        /* Only true when ps == VMI_PS_4KB */
        get_zero_level_4kb_descriptor(vmi, pt, vaddr, info);
        dbprint(VMI_DEBUG_PTLOOKUP,
                "--ARM AArch64 PTLookup: zld_value = 0x%"PRIx64"\n",
                info->arm_aarch64.zld_value);

        if ( (info->arm_aarch64.zld_value & VMI_BIT_MASK(0,1)) != 0b11)
            goto done;

        pt = info->arm_aarch64.zld_value & VMI_BIT_MASK(12,47);
        --levels;
    }

    if ( 3 == levels) {
        if ( VMI_PS_4KB == ps ) {
            get_first_level_4kb_descriptor(vmi, pt, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 4kb PTLookup: fld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    pt = info->arm_aarch64.fld_value & VMI_BIT_MASK(12,47);
                    --levels;
                    break;
                case 0b01:
                    info->size = VMI_PS_1GB;
                    info->paddr = (info->arm_aarch64.fld_value & VMI_BIT_MASK(30,47)) | (vaddr & VMI_BIT_MASK(0,29));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }

        }
        if ( VMI_PS_64KB == ps ) {
            get_first_level_64kb_descriptor(vmi, pt, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 64kb PTLookup: fld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    pt = info->arm_aarch64.fld_value & VMI_BIT_MASK(16,47);
                    --levels;
                    break;
                default:
                    goto done;
            }
        }
    }

    if ( 2 == levels ) {
        if ( VMI_PS_4KB == ps ) {
            get_second_level_4kb_descriptor(vmi, pt, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 4kb PTLookup: sld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_4kb_descriptor(vmi, vaddr, info);
                    dbprint(VMI_DEBUG_PTLOOKUP,
                            "--ARM AArch64 4kb PTLookup: tld_value = 0x%"PRIx64"\n",
                            info->arm_aarch64.tld_value);

                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & VMI_BIT_MASK(12,47)) | (vaddr & VMI_BIT_MASK(0,11));
                    status = VMI_SUCCESS;
                    break;
                case 0b01:
                    info->size = VMI_PS_2MB;
                    info->paddr = (info->arm_aarch64.sld_value & VMI_BIT_MASK(21,47)) | (vaddr & VMI_BIT_MASK(0,20));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }
        }
        if ( VMI_PS_64KB == ps ) {
            get_second_level_64kb_descriptor(vmi, pt, vaddr, info);
            dbprint(VMI_DEBUG_PTLOOKUP,
                    "--ARM AArch64 64kb PTLookup: sld_value = 0x%"PRIx64"\n",
                    info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & VMI_BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_64kb_descriptor(vmi, vaddr, info);
                    dbprint(VMI_DEBUG_PTLOOKUP,
                            "--ARM AArch64 64kb PTLookup: tld_value = 0x%"PRIx64"\n",
                            info->arm_aarch64.tld_value);

                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & VMI_BIT_MASK(16,47)) | (vaddr & VMI_BIT_MASK(0,15));
                    status = VMI_SUCCESS;
                    goto done;
                case 0b01:
                    info->size = VMI_PS_512MB;
                    info->paddr = (info->arm_aarch64.sld_value & VMI_BIT_MASK(29,47)) | (vaddr & VMI_BIT_MASK(0,28));
                    status = VMI_SUCCESS;
                    goto done;
                default:
                    goto done;
            }
        }
    }

done:
    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: PA = 0x%"PRIx64"\n", info->paddr);
    return status;
}

GSList* get_pages_aarch64(vmi_instance_t vmi, addr_t UNUSED(npt), page_mode_t UNUSED(npm), addr_t dtb)
{
    GSList *ret = NULL;
    uint64_t *l0_page = g_malloc(VMI_PS_4KB);
    uint64_t *l1_page = g_try_malloc0(VMI_PS_4KB);
    uint64_t *l2_page = g_try_malloc0(VMI_PS_4KB);
    uint64_t *l3_page = g_try_malloc0(VMI_PS_4KB);

    if (!l0_page || !l1_page || !l2_page || !l3_page)
        goto done;

    page_size_t ps;
    uint8_t va_width;
    addr_t l0_location = dtb & VMI_BIT_MASK(12,47);

    if (l0_location == (vmi->kpgd & VMI_BIT_MASK(12,47))) {
        ps = vmi->arm64.tg1;
        va_width = 64 - vmi->arm64.t1sz;
    } else {
        ps = vmi->arm64.tg0;
        va_width = 64 - vmi->arm64.t0sz;
    }

    if ( VMI_PS_4KB != ps && va_width != 39 )
    {
        errprint("Only 4 level 4KB ARM64 tables are implemented for now\n");
        goto done;
    }

    ACCESS_CONTEXT(ctx);

    ctx.addr = l0_location;
    if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, l0_page, NULL))
        goto done;

    for (uint64_t l0_index = 0; l0_index < 0x200; l0_index++, l0_location += sizeof(uint64_t))
    {
        uint64_t l0_value = l0_page[l0_index];
        uint64_t l1_location = l0_value & VMI_BIT_MASK(12,47);

        if (!l1_location)
               continue;

        ctx.addr = l1_location;
        if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, l1_page, NULL))
            continue;

        for (uint64_t l1_index = 0; l1_index < 0x200; l1_index++, l1_location += sizeof(uint64_t))
        {
            uint64_t l1_value = l1_page[l1_index];
            uint64_t l2_location = l1_value & VMI_BIT_MASK(12,47);

            if (!l2_location)
                continue;

            ctx.addr = l2_location;
            if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, l2_page, NULL))
                continue;

            for (uint64_t l2_index = 0; l2_index < 0x200; l2_index++, l2_location += sizeof(uint64_t))
            {
                uint64_t l2_value = l2_page[l2_index];
                uint64_t l3_location = l2_value & VMI_BIT_MASK(12,47);

                if (!l3_location)
                    continue;

                ctx.addr = l3_location;
                if (VMI_FAILURE == vmi_read(vmi, &ctx, VMI_PS_4KB, l3_page, NULL))
                    continue;

                for (uint64_t l3_index = 0; l3_index < 0x200; l3_index++)
                {
                    uint64_t l3_value = l3_page[l3_index];

                    if (!l3_value)
                        continue;

                    page_info_t *info = g_try_malloc0(sizeof(page_info_t));

                    if (!info)
                        goto done;

                    info->pt = dtb;
                    info->vaddr = canonical_addr((l0_index << 39) | (l1_index << 30)
                        | (l2_index << 21) | (l3_index << 12));
                    info->paddr = l3_value | (info->vaddr & VMI_BIT_MASK(0,11));
                    info->size = VMI_PS_4KB;
                    info->arm_aarch64.zld_location = l0_location;
                    info->arm_aarch64.zld_value = l0_value;
                    info->arm_aarch64.fld_location = l1_location;
                    info->arm_aarch64.fld_value = l1_value;
                    info->arm_aarch64.sld_location = l2_location;
                    info->arm_aarch64.sld_value = l2_value;
                    info->arm_aarch64.tld_location = l3_location;
                    info->arm_aarch64.tld_value = l3_value;
                    ret = g_slist_prepend(ret, info);
                }
            }
        }

    }

done:
    g_free(l0_page);
    g_free(l1_page);
    g_free(l2_page);
    g_free(l3_page);

    return ret;
}
