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
 * Copyright (c) 2013, Ying Zhu. All rights reserved.
 */

#include <sys/zpl_mmap.h>

kmem_cache_t *zpl_mmap_ref_cache;

void
zpl_mmap_init(void)
{
	zpl_mmap_ref_cache = kmem_cache_create("zpl_mmap_ref_t", sizeof (zpl_mmap_ref_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
zpl_mmap_fini(void)
{
	kmem_cache_destroy(zpl_mmap_ref_cache);
}
