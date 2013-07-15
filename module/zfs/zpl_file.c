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
 * Copyright (c) 2011, Lawrence Livermore National Security, LLC.
 */


#include <sys/zfs_vfsops.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_znode.h>
#include <sys/zpl.h>
#include <sys/zpl_mmap.h>

const static struct vm_operations_struct zpl_file_vm_ops;

static int
zpl_open(struct inode *ip, struct file *filp)
{
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_open(ip, filp->f_mode, filp->f_flags, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	if (error)
		return (error);

	return generic_file_open(ip, filp);
}

static int
zpl_release(struct inode *ip, struct file *filp)
{
	cred_t *cr = CRED();
	int error;

	if (ITOZ(ip)->z_atime_dirty)
		mark_inode_dirty(ip);

	crhold(cr);
	error = -zfs_close(ip, filp->f_flags, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct dentry *dentry = filp->f_path.dentry;
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_readdir(dentry->d_inode, dirent, filldir,
	    &filp->f_pos, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#if defined(HAVE_FSYNC_WITH_DENTRY)
/*
 * Linux 2.6.x - 2.6.34 API,
 * Through 2.6.34 the nfsd kernel server would pass a NULL 'file struct *'
 * to the fops->fsync() hook.  For this reason, we must be careful not to
 * use filp unconditionally.
 */
static int
zpl_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_fsync(dentry->d_inode, datasync, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#elif defined(HAVE_FSYNC_WITHOUT_DENTRY)
/*
 * Linux 2.6.35 - 3.0 API,
 * As of 2.6.35 the dentry argument to the fops->fsync() hook was deemed
 * redundant.  The dentry is still accessible via filp->f_path.dentry,
 * and we are guaranteed that filp will never be NULL.
 */
static int
zpl_fsync(struct file *filp, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	cred_t *cr = CRED();
	int error;

	crhold(cr);
	error = -zfs_fsync(inode, datasync, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#elif defined(HAVE_FSYNC_RANGE)
/*
 * Linux 3.1 - 3.x API,
 * As of 3.1 the responsibility to call filemap_write_and_wait_range() has
 * been pushed down in to the .fsync() vfs hook.  Additionally, the i_mutex
 * lock is no longer held by the caller, for zfs we don't require the lock
 * to be held so we don't acquire it.
 */
static int
zpl_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	cred_t *cr = CRED();
	int error;

	error = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (error)
		return (error);

	crhold(cr);
	error = -zfs_fsync(inode, datasync, cr);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}
#else
#error "Unsupported fops->fsync() implementation"
#endif

ssize_t
zpl_read_common(struct inode *ip, const char *buf, size_t len, loff_t pos,
     uio_seg_t segment, int flags, cred_t *cr)
{
	int error;
	struct iovec iov;
	uio_t uio;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_resid = len;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = pos;
	uio.uio_limit = MAXOFFSET_T;
	uio.uio_segflg = segment;

	error = -zfs_read(ip, &uio, flags, cr);
	if (error < 0)
		return (error);

	return (len - uio.uio_resid);
}

static ssize_t
zpl_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	cred_t *cr = CRED();
	ssize_t read;

	crhold(cr);
	read = zpl_read_common(filp->f_mapping->host, buf, len, *ppos,
	    UIO_USERSPACE, filp->f_flags, cr);
	crfree(cr);

	if (read < 0)
		return (read);

	*ppos += read;
	return (read);
}

ssize_t
zpl_write_common(struct inode *ip, const char *buf, size_t len, loff_t pos,
    uio_seg_t segment, int flags, cred_t *cr)
{
	int error;
	struct iovec iov;
	uio_t uio;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_resid = len,
	uio.uio_iovcnt = 1;
	uio.uio_loffset = pos;
	uio.uio_limit = MAXOFFSET_T;
	uio.uio_segflg = segment;

	error = -zfs_write(ip, &uio, flags, cr);
	if (error < 0)
		return (error);

	return (len - uio.uio_resid);
}

static ssize_t
zpl_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	cred_t *cr = CRED();
	ssize_t wrote;

	crhold(cr);
	wrote = zpl_write_common(filp->f_mapping->host, buf, len, *ppos,
	    UIO_USERSPACE, filp->f_flags, cr);
	crfree(cr);

	if (wrote < 0)
		return (wrote);

	*ppos += wrote;
	return (wrote);
}

static loff_t
zpl_llseek(struct file *filp, loff_t offset, int whence)
{
#if defined(SEEK_HOLE) && defined(SEEK_DATA)
	if (whence == SEEK_DATA || whence == SEEK_HOLE) {
		struct inode *ip = filp->f_mapping->host;
		loff_t maxbytes = ip->i_sb->s_maxbytes;
		loff_t error;

		spl_inode_lock(ip);
		error = -zfs_holey(ip, whence, &offset);
		if (error == 0)
			error = lseek_execute(filp, ip, offset, maxbytes);
		spl_inode_unlock(ip);

		return (error);
	}
#endif /* SEEK_HOLE && SEEK_DATA */

	return generic_file_llseek(filp, offset, whence);
}

/*
 * ZFSOnLinux mmap() implementation
 * Solaris would buffer mmap'ed files in both ARC and the page cache, with
 * careful attention taken to ensure that to two remained in sync. That wasted
 * memory and was inefficient, so we instead use ARC loan buffers so that we
 * can utilize ARC itself. This is possible because all ARC buffers are page
 * aligned.
 */
static int
zpl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct inode *ip = filp->f_mapping->host;
	int error;

	error = -zfs_map(ip, vma->vm_pgoff, (caddr_t *)vma->vm_start,
	    (size_t)(vma->vm_end - vma->vm_start), vma->vm_flags);
	if (error)
		return (error);
	file_accessed(filp);
	vma->vm_ops = &zpl_file_vm_ops;
	return 0;
}

/*
 * The only flag combination which matches the behavior of zfs_space()
 * is FALLOC_FL_PUNCH_HOLE.  This flag was introduced in the 2.6.38 kernel.
 */
long
zpl_fallocate_common(struct inode *ip, int mode, loff_t offset, loff_t len)
{
	cred_t *cr = CRED();
	int error = -EOPNOTSUPP;

	if (mode & FALLOC_FL_KEEP_SIZE)
		return (-EOPNOTSUPP);

	crhold(cr);

#ifdef FALLOC_FL_PUNCH_HOLE
	if (mode & FALLOC_FL_PUNCH_HOLE) {
		flock64_t bf;

		bf.l_type = F_WRLCK;
		bf.l_whence = 0;
		bf.l_start = offset;
		bf.l_len = len;
		bf.l_pid = 0;

		error = -zfs_space(ip, F_FREESP, &bf, FWRITE, offset, cr);
	}
#endif /* FALLOC_FL_PUNCH_HOLE */

	crfree(cr);

	ASSERT3S(error, <=, 0);
	return (error);
}

#ifdef HAVE_FILE_FALLOCATE
static long
zpl_fallocate(struct file *filp, int mode, loff_t offset, loff_t len)
{
	return zpl_fallocate_common(filp->f_path.dentry->d_inode,
	    mode, offset, len);
}
#endif /* HAVE_FILE_FALLOCATE */

static long
zpl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ZFS_IOC_GETFLAGS:
	case ZFS_IOC_SETFLAGS:
		return (-EOPNOTSUPP);
	default:
		return (-ENOTTY);
	}
}

#ifdef CONFIG_COMPAT
static long
zpl_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return zpl_ioctl(filp, cmd, arg);
}
#endif /* CONFIG_COMPAT */

static void
zpl_mmap_open(struct vm_area_struct *vma)
{
}

static void
zpl_mmap_close(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct inode *ip = filp->f_mapping->host;
	znode_t *zp = ITOZ(ip);
	zpl_mmap_ref_t *zmap_ref = NULL;

	if ((vma->vm_flags & VM_SHARED)) {
		// FIXME: Flush here
	}

	mutex_enter(&zp->z_lock);

	for (zmap_ref = list_head(&zp->z_mmap_reflist);
		zmap_ref; list_next(&zp->z_mmap_reflist, zmap_ref)) {
		if (zmap_ref->vma == vma)
			break;
	}

	ASSERT(zmap_ref);
        if (!list_is_empty(&zp->z_mmap_reflist))
	        list_remove(&zp->z_mmap_reflist, zmap_ref);
        dmu_buf_unmap(zmap_ref->dbuf, NULL, zp);
	mutex_exit(&zp->z_lock);
}

static int
zpl_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{

	struct file *filp = vma->vm_file;
	struct inode *ip = filp->f_mapping->host;
	znode_t *zp = ITOZ(ip), *tp;
	zfs_sb_t *zsb = ITOZSB(ip);
	uint64_t byte_offset = vmf->pgoff << PAGE_SHIFT;
	zpl_mmap_ref_t *zmap_ref;
	dmu_buf_t *dbuf;
        void *page_addr = NULL;

	mutex_enter(&zp->z_lock);

	dmu_buf_hold(zsb->z_os, zp->z_id, byte_offset, NULL, &dbuf, 0);
	tp = dmu_buf_mmap_owner(dbuf, NULL);
	if (tp == NULL) {
                zmap_ref = kmem_cache_alloc(zpl_mmap_ref_cache, KM_PUSHPAGE);

		if (zmap_ref == NULL) {
		        mutex_exit(&zp->z_lock);
			return -ENOMEM;
                }

		zmap_ref->offset = byte_offset;
		zmap_ref->refcnt = 1;
                zmap_ref->vma = vma;
                zmap_ref->dbuf = dbuf;

		list_insert_head(&zp->z_mmap_reflist, zmap_ref);

		/* Add a reference to object to pin it in place for mmap. */
		dmu_buf_mmap(dbuf, NULL, zp);
	} else if (tp == zp) {
		for (zmap_ref = list_head(&zp->z_mmap_reflist);
			zmap_ref; list_next(&zp->z_mmap_reflist, zmap_ref)) {
			if (zmap_ref->offset == byte_offset)
				break;
		}
		zmap_ref->refcnt++;
	} else {
		// We should never fault on another znode's buffer
		VERIFY(0);
	}

	dmu_buf_rele(dbuf, NULL);
	zp->z_mapcnt++;
        /*
         * Calculate the faulted page in the following 2 scenarios:
         * 1. dmu block size <= PAGE_SIZE, since a dmu buf will
         * never cross page boundary, so use the page this dmu buf
         * resides directly.
         * 2. dmu block size > PAGE_SIZE, since the size of the dmu 
         * buf is multiple of pages, we calculate the page using
         * this formula:
         *  page number = dbuf->db_data + 
         *      vmf->pgoff % (dbuf->db_size >> PAGE_SHIFT)
         */
        if (dbuf->db_size <= PAGE_SIZE)
              page_addr = dbuf->db_data;
        else
              page_addr = dbuf->db_data + 
                      vmf->pgoff % (dbuf->db_size >> PAGE_SHIFT);
        
        /*
         *  Dmu bufs can be backed both by vmalloced and kmalloced memory.
         */
        if (kmem_virt(page_addr))
              vmf->page = vmalloc_to_page(page_addr);
        else
              vmf->page = virt_to_page(page_addr);
	get_page(vmf->page);
	lock_page(vmf->page);
	mutex_exit(&zp->z_lock);

	return VM_FAULT_LOCKED;
}

static int
zpl_mmap_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	lock_page(page);
	set_page_dirty(page);
	SetPageUptodate(page);
	return VM_FAULT_LOCKED;
}

const struct file_operations zpl_file_operations = {
	.open		= zpl_open,
	.release	= zpl_release,
	.llseek		= zpl_llseek,
	.read		= zpl_read,
	.write		= zpl_write,
	.mmap		= zpl_mmap,
	.fsync		= zpl_fsync,
#ifdef HAVE_FILE_FALLOCATE
	.fallocate      = zpl_fallocate,
#endif /* HAVE_FILE_FALLOCATE */
	.unlocked_ioctl = zpl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = zpl_compat_ioctl,
#endif
};

const static struct vm_operations_struct zpl_file_vm_ops = {
	.open		= zpl_mmap_open,
	.close		= zpl_mmap_close,
	.fault		= zpl_mmap_fault,
	.page_mkwrite	= zpl_mmap_mkwrite,
};

const struct file_operations zpl_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= zpl_readdir,
	.fsync		= zpl_fsync,
	.unlocked_ioctl = zpl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = zpl_compat_ioctl,
#endif
};
