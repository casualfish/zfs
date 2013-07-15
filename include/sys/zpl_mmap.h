/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2013, Richard Yao. All rights reserved.
 */

#ifndef	_SYS_FS_ZFS_MMAP_H
#define	_SYS_FS_ZFS_MMAP_H

#include <sys/uio.h>
#include <sys/zfs_context.h>
#if defined(_KERNEL)
#include <sys/kmem.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

struct vm_area_struct;
typedef struct zpl_mmap_ref zpl_mmap_ref_t;
typedef struct dmu_buf dmu_buf_t;

struct zpl_mmap_ref {
	list_node_t ref;
	uint64_t offset;
	uint64_t refcnt;
        struct vm_area_struct *vma;
        dmu_buf_t *dbuf;
};

extern kmem_cache_t *zpl_mmap_ref_cache;
extern void zpl_mmap_init(void);
extern void zpl_mmap_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_MMAP_H */
