/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sgfs.h"
# include <linux/mm.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <crypto/hash.h>
# include <keys/ceph-type.h>
# include <linux/hash.h>
#include <linux/ceph/types.h>
#include <linux/ceph/buffer.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <crypto/skcipher.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>

int32_t value = 0;

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

struct dir_context *org_ctx;
static int ls_filldir(struct dir_context * ctx, const char * name, int namelen, loff_t offset, u64 ino, unsigned int d_type){
     uid_t curr_user;
     uid_t k_id;
     int err1 = 0;
     char kid[5];
     char *fname = kmalloc(sizeof(char)*PATH_MAX,GFP_KERNEL);
     strcpy(fname,name);
     printk("filename is %s\n",fname);
     struct user_struct *us;
     us = current_user();
     curr_user = get_uid(us)->uid.val;
     printk("curr id is %d\n",curr_user);
     if(curr_user == 0){
          if(fname) kfree(fname);
          return org_ctx->actor(org_ctx, name, namelen, offset, ino, d_type);
     }
     strncpy(kid,fname,4);
     // if(fname[0] != '.'){
     //      while(i<4 || fname[i] != '\0'){
     //           kid[i] = fname[i];
     //           i++;
     //      }
     // }
     // kid[i] = '\0';
     err1 = kstrtoint(kid,10,&k_id);
     printk("err is %d\n",err1);
     if(k_id == curr_user){
               if(fname) kfree(fname);
               return org_ctx->actor(org_ctx, name, namelen, offset, ino, d_type);
     }
     else{
               printk("users don't match\n");
               if(fname) kfree(fname);
               return 0;
     }


}

static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
     struct dir_context my_ctx = {.actor=&ls_filldir, .pos = ctx->pos};
     org_ctx = ctx;
	lower_file = sgfs_lower_file(file);
     if(!strcmp(file->f_path.dentry->d_iname,".sg")){
	         err = iterate_dir(lower_file, &my_ctx);
     }
     else {
          err = iterate_dir(lower_file, ctx);
     }
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}
static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int sgfs_decryption(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len){
	int ivsize;
	int ret;
	int last_byte;
	char pad[48];
	struct scatterlist sg_in[1], sg_out[2];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm };
	void *iv;

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);

	crypto_free_blkcipher(tfm);

	if (ret < 0) {
		pr_err("Eror in decryption key: %d\n", ret);
		return ret;
	}

	 if (src_len <= *dst_len)
 		last_byte = ((char *)dst)[src_len - 1];
 	else
 		last_byte = pad[src_len - *dst_len - 1];

 	if (last_byte <= 16 && src_len >= last_byte) {

 		*dst_len = src_len - last_byte;
 	}
 	else {
 		pr_err("INVALID KEY!!\n");
                  return -EPERM;
          }
	return 0;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	char *filename = NULL;
     int flen, end, start, revlen, curr_read_size, curr_write_size;
     curr_write_size = 0;
     curr_read_size = 0;
     struct file *f_read;
     struct file *f_write;
     int bytes1, ioctl_err;
     mm_segment_t oldfs1;
     mm_segment_t oldfs2;
     int fsize, temp_size;
     int bytes2;
     char *buff3 = NULL;
     char *buff4 = NULL;
     char *key = NULL;
     char *path = NULL;
     char *fname = NULL;
     char *tok = NULL;
     char *rev_tok = NULL;
     struct inode *Inode;
     size_t key_len;
     struct dentry *lower_dentry;
	struct inode *lower_dir_inode;
	struct dentry *lower_dir_dentry;
	struct path lower_path;
     int del_err;
     
     filename = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
     if(!filename){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     path = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
     if(!path){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     fname = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
     if(!fname){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     tok = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
     if(!tok){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     rev_tok = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
     if(!rev_tok){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     key = (char*)kmalloc(sizeof(char)*20,GFP_KERNEL);
     if(!key){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }
     size_t *dst_len = kmalloc(sizeof(size_t),GFP_KERNEL);
     if(!dst_len){
          printk("Insufficient memory\n");
          return -ENOMEM;
     }

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));

     lower_dir_inode = lower_file->f_path.dentry->d_parent->d_inode;
      strcpy(key,SGFS_SB(file->f_path.dentry->d_inode->i_sb)->enckey);
      printk("Key is %s\n",key);
      key_len = strlen(key);

	switch(cmd) {
               case RD_VALUE:
     			path = d_path(&lower_file->f_path,filename,PATH_MAX);
     			printk("file path is %s\n",path);
                    printk("file name is %s\n",lower_file->f_path.dentry->d_iname);
                    strcpy(fname,lower_file->f_path.dentry->d_iname);
                    flen = strlen(fname);
                    printk("flen is %d\n",flen);
                    if(key_len == 0){

                         end = flen;
                         start = 0;
                         revlen = 0;
                         while(fname[end] != '-'){
                              tok[revlen] = fname[end];
                              end--;
                              revlen++;
                         }
                         tok[revlen] = '\0';
                         revlen--;
                         while(revlen >= 0){
                              rev_tok[start] = tok[revlen];
                              revlen--;
                              start++;
                         }
                         rev_tok[start] = '\0';
                         printk("rev tok is %s\n", rev_tok);
          			printk("Executing the RD ioctl\n");
                         f_read = filp_open(path, O_RDONLY, 0);
               		if (!f_read || IS_ERR(f_read)) {
                    		printk("Reading file 1 is failed\n");
                    		printk("wrapfs_read_file err %d\n", (int) PTR_ERR(f_read));
                    		return -(int)PTR_ERR(f_read);  // or do something else
               		}
     
                         Inode = f_read->f_path.dentry->d_inode;
               		fsize = i_size_read(Inode);
               		printk("file size is %d\n",fsize);
     
                         f_write = filp_open(rev_tok, O_WRONLY | O_CREAT, 0644);
               		if(!f_write || IS_ERR(f_write)){
               			printk("Wrapfs_write_file_4 err %d\n", (int)PTR_ERR(f_write));
               			return -(int)PTR_ERR(f_write);
               		}
     
                         while(fsize > 0){
     
                              buff3 = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
                              buff4 = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
                              if(fsize > PAGE_SIZE){
                                   temp_size = PAGE_SIZE;
                                   fsize = fsize - temp_size;
                              }
                              else{
                                   temp_size = fsize;
                                   fsize = 0;
                              }
     
                              f_read->f_pos = curr_read_size;
                              oldfs1 = get_fs();
                    		set_fs(KERNEL_DS);
                    		bytes1 = vfs_read(f_read, buff3,temp_size, &f_read->f_pos);
                    		set_fs(oldfs1);
                    		printk("data is %s\n",buff3);
                    		printk("%d\n",bytes1);
     
                              f_write->f_pos = curr_write_size;
                              oldfs2 = get_fs();
                    		set_fs(KERNEL_DS);
                    		bytes2 = vfs_write(f_write, buff3, bytes1, &f_write->f_pos);
                    		set_fs(oldfs2);
                    		printk("%d\n",bytes2);
     
                              printk("Successfully written the file\n");
               			kfree(buff3);
               			kfree(buff4);
               			printk("successfully freed the buffer\n");
     
               			curr_read_size += bytes1;
                              curr_write_size += bytes2;
     
                         }
     
                         printk("before locking 1\n");
                         sgfs_get_lower_path(file->f_path.dentry, &lower_path);
                         printk("before locking 2\n");
               		lower_dentry = lower_path.dentry;
               		dget(lower_dentry);
                         printk("before locking 3\n");
               		lower_dir_dentry = lock_parent(lower_dentry);
     
                         printk("before unlink\n");
     
               		del_err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
     
                         printk("After unlink\n");
     
               		if (del_err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
               			del_err = 0;
               		if (del_err) {
               			unlock_dir(lower_dir_dentry);
               			dput(lower_dentry);
               			sgfs_put_lower_path(file->f_path.dentry, &lower_path);
               			printk("Could not unlink the file error is %d\n", del_err);
               			return err;
               		}
               		fsstack_copy_attr_times(file->f_path.dentry->d_inode, lower_dir_inode);
               		fsstack_copy_inode_size(file->f_path.dentry->d_inode, lower_dir_inode);
               		set_nlink(d_inode(file->f_path.dentry),
               			  sgfs_lower_inode(d_inode(file->f_path.dentry))->i_nlink);
               		d_inode(file->f_path.dentry)->i_ctime = file->f_path.dentry->d_inode->i_ctime;
               		d_drop(file->f_path.dentry);
               		unlock_dir(lower_dir_dentry);
               		dput(lower_dentry);
               		sgfs_put_lower_path(file->f_path.dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
               		printk("Successfully deleted the file\n");
                         filp_close(f_read,NULL);
               		filp_close(f_write,NULL);
                         if(filename) kfree(filename);
                         if(fname) kfree(fname);
                         if(tok) kfree(tok);
                         if(rev_tok) kfree(rev_tok);
                         if(key) kfree(key);
                         if(dst_len) kfree(dst_len);
                         if(path) kfree(path);
                         
                    }

                    else {
                         end = flen - 5;
                         start = 0;
                         revlen = 0;
                         while(fname[end] != '-'){
                              tok[revlen] = fname[end];
                              end--;
                              revlen++;
                         }
                         tok[revlen] = '\0';
                         revlen--;
                         while(revlen >= 0){
                              rev_tok[start] = tok[revlen];
                              revlen--;
                              start++;
                         }
                         rev_tok[start] = '\0';
                         printk("rev tok is %s\n", rev_tok);
          			printk("Executing the RD ioctl\n");
                         f_read = filp_open(path, O_RDONLY, 0);
               		if (!f_read || IS_ERR(f_read)) {
                    		printk("Reading file 1 is failed\n");
                    		printk("wrapfs_read_file err %d\n", (int) PTR_ERR(f_read));
                    		return -(int)PTR_ERR(f_read);  // or do something else
               		}

                         Inode = f_read->f_path.dentry->d_inode;
               		fsize = i_size_read(Inode);
               		printk("file size is %d\n",fsize);

                         f_write = filp_open(rev_tok, O_WRONLY | O_CREAT, 0644);
               		if(!f_write || IS_ERR(f_write)){
               			printk("Wrapfs_write_file_4 err %d\n", (int)PTR_ERR(f_write));
               			return -(int)PTR_ERR(f_write);
               		}

                         while(fsize > 0){

                              buff3 = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
                              buff4 = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
                              if(fsize > PAGE_SIZE){
                                   temp_size = PAGE_SIZE;
                                   fsize = fsize - temp_size;
                              }
                              else{
                                   temp_size = fsize;
                                   fsize = 0;
                              }

                              f_read->f_pos = curr_read_size;
                              oldfs1 = get_fs();
                    		set_fs(KERNEL_DS);
                    		bytes1 = vfs_read(f_read, buff3,temp_size, &f_read->f_pos);
                    		set_fs(oldfs1);
                    		printk("data is %s\n",buff3);
                    		printk("%d\n",bytes1);

                              printk("Done reading the file successfully\n");
                              printk("Going to do decryption\n");

                              ioctl_err = sgfs_decryption(key,key_len,buff4,dst_len,buff3,bytes1);
                              if(ioctl_err){
                                   printk("Decryption failed with error %d\n",ioctl_err);
                                   return ioctl_err;
                              }
                              printk("Decryption success\n");
                              printk("decrpt is %s\n",buff4);
                              printk("dest len is %d\n",*dst_len);

                              f_write->f_pos = curr_write_size;
                              oldfs2 = get_fs();
                    		set_fs(KERNEL_DS);
                    		bytes2 = vfs_write(f_write, buff4, *dst_len, &f_write->f_pos);
                    		set_fs(oldfs2);
                    		printk("%d\n",bytes2);

                              printk("Successfully written the file\n");
               			kfree(buff3);
               			kfree(buff4);
               			printk("successfully freed the buffer\n");

               			curr_read_size += bytes1;
                              curr_write_size += bytes2;

                         }

                         printk("before locking 1\n");
                         sgfs_get_lower_path(file->f_path.dentry, &lower_path);
                         printk("before locking 2\n");
               		lower_dentry = lower_path.dentry;
               		dget(lower_dentry);
                         printk("before locking 3\n");
               		lower_dir_dentry = lock_parent(lower_dentry);

                         printk("before unlink\n");

               		del_err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

                         printk("After unlink\n");

               		/*
               		 * Note: unlinking on top of NFS can cause silly-renamed files.
               		 * Trying to delete such files results in EBUSY from NFS
               		 * below.  Silly-renamed files will get deleted by NFS later on, so
               		 * we just need to detect them here and treat such EBUSY errors as
               		 * if the upper file was successfully deleted.
               		 */
               		if (del_err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
               			del_err = 0;
               		if (del_err) {
               			unlock_dir(lower_dir_dentry);
               			dput(lower_dentry);
               			sgfs_put_lower_path(file->f_path.dentry, &lower_path);
               			printk("Could not unlink the file error is %d\n", del_err);
               			return err;
               		}
               		fsstack_copy_attr_times(file->f_path.dentry->d_inode, lower_dir_inode);
               		fsstack_copy_inode_size(file->f_path.dentry->d_inode, lower_dir_inode);
               		set_nlink(d_inode(file->f_path.dentry),
               			  sgfs_lower_inode(d_inode(file->f_path.dentry))->i_nlink);
               		d_inode(file->f_path.dentry)->i_ctime = file->f_path.dentry->d_inode->i_ctime;
               		d_drop(file->f_path.dentry);
               		unlock_dir(lower_dir_dentry);
               		dput(lower_dentry);
               		sgfs_put_lower_path(file->f_path.dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
               		printk("Successfully deleted the file\n");
                         filp_close(f_read,NULL);
               		filp_close(f_write,NULL);
                         if(filename) kfree(filename);
                         if(fname) kfree(fname);
                         if(tok) kfree(tok);
                         if(rev_tok) kfree(rev_tok);
                         if(key) kfree(key);
                         if(dst_len) kfree(dst_len);
                         if(path) kfree(path);
                    }
                    break;
        }

	printk("Reached ioctl\n");
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
