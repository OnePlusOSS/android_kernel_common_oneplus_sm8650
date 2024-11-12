// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-2022 Oplus. All rights reserved.
 */

#define pr_fmt(fmt) "fileprotectT_drv: " fmt

#include <linux/module.h>
#include <linux/oom.h>
#include <linux/printk.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/psi.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/cpufreq.h>
#include <linux/syscalls.h>
#include <linux/suspend.h>
#include "../../../mm/internal.h"
#include <uapi/linux/fadvise.h>

#define MAX_TRACE_PATHBUF_LEN	512

unsigned long  memavail_noprotected = 0;
static struct proc_dir_entry *fileprotect_node;

static int should_record;
LIST_HEAD(fileprotect_file_list);
spinlock_t fileprotect_file_lock;

struct file_fileprotect_node {
	char file_path[MAX_TRACE_PATHBUF_LEN];
	unsigned long i_ino;
	unsigned long nr_to_read;
	struct list_head lru;
};

unsigned long pageprotect = 0;
unsigned long shrink_protect = 0;

bool mem_available_is_low(void)
{
	long available = si_mem_available();

	if (available < memavail_noprotected)
		return true;

	return false;
}

bool should_be_protect(struct folio *folio, bool mem_is_low)
{
	if (!mem_is_low && unlikely(folio_test_protect(folio))) {
		shrink_protect++;
		return true;
	}

	return false;
}

bool mapping_protect(struct address_space *mapping)
{
	struct file_fileprotect_node *node;

	if (unlikely(mapping->host->i_flags & S_MEMPROTECT))
		return true;

	if (likely(!should_record))
		return false;

	spin_lock_irq(&fileprotect_file_lock);

	list_for_each_entry(node, &fileprotect_file_list, lru) {
		if (node->i_ino == mapping->host->i_ino) {
			mapping->host->i_flags |= S_MEMPROTECT;
			should_record--;
			spin_unlock_irq(&fileprotect_file_lock);
			return true;
		}
	}

	spin_unlock_irq(&fileprotect_file_lock);

	return false;
}

void check_destory_protect_inode(struct inode *inode)
{
	if (unlikely(inode->i_flags & S_MEMPROTECT)) {
		struct file_fileprotect_node *node;

		spin_lock_irq(&fileprotect_file_lock);
		list_for_each_entry(node, &fileprotect_file_list, lru) {
			if (node->i_ino == inode->i_ino) {
				should_record++;
				pr_err("%s:%d\n", __func__, __LINE__);
			}
		}
		spin_unlock_irq(&fileprotect_file_lock);
	}
}

static inline char *
android_fstrace_get_pathname(char *buf, int buflen, struct inode *inode)
{
	char *path;
	struct dentry *d;

	ihold(inode);
	d = d_obtain_alias(inode);

	if (likely(!IS_ERR(d))) {
		path = dentry_path_raw(d, buf, buflen);
		if (unlikely(IS_ERR(path))) {
			strcpy(buf, "ERROR");
			path = buf;
		}
		dput(d);
	} else {
		strcpy(buf, "ERROR");
		path = buf;
	}
	return path;
}

static void recorded_single_file(struct file_fileprotect_node *node,
		struct file *filp)
{
	struct inode *inode = NULL;
	char *path, pathbuf[MAX_TRACE_PATHBUF_LEN];

	inode = file_inode(filp);
	if (IS_ERR(inode)) {
		pr_err("fileprotect_drv: inode err %s\n", node->file_path);
		return;
	}
	path = android_fstrace_get_pathname(pathbuf,
			MAX_TRACE_PATHBUF_LEN, inode);

	memcpy(node->file_path, path, strlen(path));
	node->i_ino = inode->i_ino;
	node->nr_to_read = (inode->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	should_record++;
	pr_info("%s[%d] recorded protect-file : %s\n",
			(char *)current->comm, current->pid, node->file_path);
}

static ssize_t fileprotectT_write(struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	struct file_fileprotect_node *node;
	char proctectfd[64] = {0};
	char *start = NULL;
	int ret = 0;
	int fd = -1;
	struct fd f;

	if ((count > sizeof(proctectfd) - 1) || (count <= 0)) {
		pr_info("%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (copy_from_user(proctectfd, buf, count)) {
		pr_info("%s:%d\n", __func__, __LINE__);
		return -EFAULT;
	}

	proctectfd[count] = '\0';
	start = strstrip(proctectfd);
	if (strlen(start) <= 0) {
		pr_info("%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (kstrtoint(start, 10, &fd)) {
		pr_info("%s:%d\n", __func__, __LINE__);
		return -EINVAL;
	}

	f = fdget(fd);
	if (!f.file) {
		pr_info("%s:%d\n", __func__, __LINE__);
		return -EBADF;
	}

	if (!file_inode(f.file)) {
		pr_info("%s:%d\n", __func__, __LINE__);
		goto put_file;
	}

	node = kmalloc(sizeof(struct file_fileprotect_node), GFP_ATOMIC);
	if (!node) {
		pr_info("%s:%d\n", __func__, __LINE__);
		ret = -ENOMEM;
		goto put_file;
	}

	memset(node->file_path, 0, MAX_TRACE_PATHBUF_LEN);

	INIT_LIST_HEAD(&node->lru);

	spin_lock_irq(&fileprotect_file_lock);
	list_add(&node->lru, &fileprotect_file_list);
	recorded_single_file(node, f.file);
	spin_unlock_irq(&fileprotect_file_lock);

put_file:
	fdput(f);

	return ret ? ret : count;
}

static int fileprotectT_show(struct seq_file *m, void *p)
{
	struct file_fileprotect_node *node;
	unsigned long total_file_pages = 0;

	spin_lock_irq(&fileprotect_file_lock);
	if (list_empty(&fileprotect_file_list)) {
		spin_unlock_irq(&fileprotect_file_lock);
		return 0;
	}

	list_for_each_entry(node, &fileprotect_file_list, lru) {
		total_file_pages += node->nr_to_read;
		seq_printf(m, "protect_file = %s, ino = %lu, nr_to_read = %lu\n",
					node->file_path, node->i_ino, node->nr_to_read);
	}

	spin_unlock_irq(&fileprotect_file_lock);
        seq_printf(m, "total = %lu, protected: %lu, shrink_protect = %lu, should_record = %d\n",
			total_file_pages, pageprotect, shrink_protect, should_record);

	return 0;
}

static int fileprotect_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fileprotectT_show, NULL);
}

static int kcrit_scene_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct proc_ops fileprotect_proc_fops = {
	.proc_open = fileprotect_proc_open,
	.proc_release = kcrit_scene_proc_release,
	.proc_write = fileprotectT_write,
	.proc_read       = seq_read,
};

void set_fileprotect_page(struct folio *folio)
{
	__folio_set_protect(folio);
	pageprotect += folio_nr_pages(folio);
}

static int __init fileprotect_drv_init(void)
{
	spin_lock_init(&fileprotect_file_lock);
	memavail_noprotected = totalram_pages() / 10;
	fileprotect_node = proc_create("fileprotect_node", 0644, NULL, &fileprotect_proc_fops);

	pr_info("%s init succeed!\n", __func__);
	return 0;
}

static void __exit fileprotect_drv_exit(void)
{
	proc_remove(fileprotect_node);

	pr_info("%s exit succeed!\n", __func__);
}

module_init(fileprotect_drv_init);
module_exit(fileprotect_drv_exit);

MODULE_LICENSE("GPL v2");
