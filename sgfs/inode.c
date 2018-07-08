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
#include <linux/time.h>
#include <linux/rtc.h>

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int sgfs_encryption(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len){
	int ret;
	int ivsize;
	char pad[48];
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	void *iv;
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);

	*dst_len = src_len + zero_padding;
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst,*dst_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                     src_len + zero_padding);
	crypto_free_blkcipher(tfm);
	if (ret < 0)
		printk("Error in key encryption : %d\n", ret);
	return 0;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err, key_len;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	struct path abs_path;
	char *parent_dir = NULL;
	char *key = NULL;
	char *filename = NULL;
	struct file *f_read;
	struct file *f_write;
	char *buff3 = NULL;
	char *buff4 = NULL;
	char *path = NULL;
	char *key = NULL;
	
	path = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
	if(!path){
		printk("Insufficient memory\n");
		return -ENOMEM;
	}
	key = (char*)kmalloc(sizeof(char)*20,GFP_KERNEL);
	if(!key){
		printk("Insufficient memory\n");
		return -ENOMEM;
	}
	filename = kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
	if(!filename){
		printk("Insufficient memory\n");
		return -ENOMEM;
	}

	sgfs_get_lower_path(dentry, &abs_path);
	path = d_path(&abs_path,filename,PATH_MAX);
	printk("path is %s\n",path);
	printk("Filename is %s\n",dentry->d_iname);
	parent_dir = (char*)kmalloc(sizeof(char)*strlen(dentry->d_parent->d_iname),GFP_KERNEL);
	strcpy(parent_dir,dentry->d_parent->d_iname);

	strcpy(key,SGFS_SB(dir->i_sb)->enckey);
	key_len = strlen(key);
	printk("Key is %s\n",key);

	if(key_len == 0){

		printk("Hi I am in unlink removing\n");
		printk(" parent d_iname is %s\n", dentry->d_parent->d_iname);
	
		printk(" parent d_iname is %s\n", parent_dir);
	
		if(!strcmp(parent_dir,".sg")){
			printk("I am directly unlinking\n");
			sgfs_get_lower_path(dentry, &lower_path);
			lower_dentry = lower_path.dentry;
			dget(lower_dentry);
			lower_dir_dentry = lock_parent(lower_dentry);
	
			err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	
			if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
				err = 0;
			if (err) {
				unlock_dir(lower_dir_dentry);
				dput(lower_dentry);
				sgfs_put_lower_path(dentry, &lower_path);
				printk("Could not unlink the file error is %d\n", err);
				return err;
			}
			fsstack_copy_attr_times(dir, lower_dir_inode);
			fsstack_copy_inode_size(dir, lower_dir_inode);
			set_nlink(d_inode(dentry),
				  sgfs_lower_inode(d_inode(dentry))->i_nlink);
			d_inode(dentry)->i_ctime = dir->i_ctime;
			d_drop(dentry);
			unlock_dir(lower_dir_dentry);
			dput(lower_dentry);
			sgfs_put_lower_path(dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
			printk("Successfully deleted the file\n");
			return 0;
		}
	
		else{
			printk("I am unlinking after encryption\n");
			// char *buff5 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
			key = (char*)kmalloc(sizeof(char)*10,GFP_KERNEL);
			size_t dst_len;
			mm_segment_t oldfs1;
			mm_segment_t oldfs2;
			int bytes1;
			int bytes2;
			int curr_read_size = 0;
			int curr_write_size = 0;
			char *fname = kmalloc(sizeof(char)*PATH_MAX,GFP_KERNEL);
			char *abs_path = kmalloc(sizeof(char)*100,GFP_KERNEL);
			char *year = kmalloc(sizeof(char)*4,GFP_KERNEL);
			char *month = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *day = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *hrs = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *mins = kmalloc(sizeof(char)*2,GFP_KERNEL);
			int c, fsize, temp_size;
			struct inode *Inode;
	
	
	
			struct timeval time;
			struct rtc_time tm;
			unsigned long local_time;
			char uid[5];
	
			uid_t curr_user;
			struct user_struct *us = current_user();
		     curr_user = get_uid(us)->uid.val;
		     printk("curr id is %d\n",curr_user);
	
			c = snprintf(uid,5,"%04d",curr_user);
			strcat(fname,uid);
			strcat(fname,"-");
			
			do_gettimeofday(&time);
			local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
			rtc_time_to_tm(local_time, &tm);
	
			c = snprintf(year,5,"%0ld",tm.tm_year + 2016);
			strcat(fname,year);
			strcat(fname,"-");
			c = snprintf(month,3,"%02d",tm.tm_mon);
			strcat(fname,month);
			strcat(fname,"-");
			c = snprintf(day,3,"%02d",tm.tm_mday + 1);
			strcat(fname,day);
			strcat(fname,"-");
			c = snprintf(hrs,3,"%02d",tm.tm_hour);
			strcat(fname,hrs);
			strcat(fname,":");
			c = snprintf(mins,3,"%02d",tm.tm_min);
			strcat(fname,mins);
			strcat(fname,"-");
			strcat(fname,dentry->d_iname);
			printk("filename is %s\n",fname);
	
			
	
			f_read = filp_open(path, O_RDONLY, 0);
			if (!f_read || IS_ERR(f_read)) {
			printk("Reading file 1 is failed\n");
			printk("wrapfs_read_file err %d\n", (int) PTR_ERR(f_read));
			return -(int)PTR_ERR(f_read);  // or do something else
			}
	
			Inode = f_read->f_path.dentry->d_inode;
			fsize = i_size_read(Inode);
			printk("file size is %d\n",fsize);
			strcpy(abs_path,"/usr/src/hw2-vanugu/hw2/sgfs/.sg/");
			strcat(abs_path,fname);
	
			f_write = filp_open(abs_path, O_WRONLY | O_CREAT, 0644);
			if(!f_write || IS_ERR(f_write)){
				printk("Wrapfs_write_file_4 err %d\n", (int)PTR_ERR(f_write));
				return -(int)PTR_ERR(f_write);
			}
	
	
			while(fsize > 0){
	
				buff3 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
				buff4 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
				if(fsize > PAGE_SIZE){
					temp_size = PAGE_SIZE;
					fsize = fsize - temp_size;
				}
				else {
					temp_size = fsize;
					fsize = 0;
				}
				f_read->f_pos = curr_read_size;
				oldfs1 = get_fs();
				set_fs(KERNEL_DS);
				bytes1 = vfs_read(f_read, buff3,temp_size, &f_read->f_pos);
				set_fs(oldfs1);
				printk("data is %s\n",buff3);
				printk("Bytes read is %d\n",bytes1);
	
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
	
	
			filp_close(f_read,NULL);
			filp_close(f_write,NULL);
			kfree(key);
	
	
			sgfs_get_lower_path(dentry, &lower_path);
			lower_dentry = lower_path.dentry;
			dget(lower_dentry);
			lower_dir_dentry = lock_parent(lower_dentry);
	
			err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	
			/*
			 * Note: unlinking on top of NFS can cause silly-renamed files.
			 * Trying to delete such files results in EBUSY from NFS
			 * below.  Silly-renamed files will get deleted by NFS later on, so
			 * we just need to detect them here and treat such EBUSY errors as
			 * if the upper file was successfully deleted.
			 */
			if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
				err = 0;
			if (err){
				unlock_dir(lower_dir_dentry);
				dput(lower_dentry);
				sgfs_put_lower_path(dentry, &lower_path);
				printk("Couldn't unlink the file error is %d", err);
				return err;
			}
			fsstack_copy_attr_times(dir, lower_dir_inode);
			fsstack_copy_inode_size(dir, lower_dir_inode);
			set_nlink(d_inode(dentry),
				  sgfs_lower_inode(d_inode(dentry))->i_nlink);
			d_inode(dentry)->i_ctime = dir->i_ctime;
			d_drop(dentry);
			unlock_dir(lower_dir_dentry);
			dput(lower_dentry);
			sgfs_put_lower_path(dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
			printk("Successfully moved the file to the recycle bin after encryption\n");
			return 0;
		}
		
	}

	else {
		
		printk("Hi I am in unlink removing\n");
		printk(" parent d_iname is %s\n", dentry->d_parent->d_iname);

		printk(" parent d_iname is %s\n", parent_dir);

		if(!strcmp(parent_dir,".sg")){
			printk("I am directly unlinking\n");
			sgfs_get_lower_path(dentry, &lower_path);
			lower_dentry = lower_path.dentry;
			dget(lower_dentry);
			lower_dir_dentry = lock_parent(lower_dentry);

			err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

			/*
			 * Note: unlinking on top of NFS can cause silly-renamed files.
			 * Trying to delete such files results in EBUSY from NFS
			 * below.  Silly-renamed files will get deleted by NFS later on, so
			 * we just need to detect them here and treat such EBUSY errors as
			 * if the upper file was successfully deleted.
			 */
			if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
				err = 0;
			if (err) {
				unlock_dir(lower_dir_dentry);
				dput(lower_dentry);
				sgfs_put_lower_path(dentry, &lower_path);
				printk("Could not unlink the file error is %d\n", err);
				return err;
			}
			fsstack_copy_attr_times(dir, lower_dir_inode);
			fsstack_copy_inode_size(dir, lower_dir_inode);
			set_nlink(d_inode(dentry),
				  sgfs_lower_inode(d_inode(dentry))->i_nlink);
			d_inode(dentry)->i_ctime = dir->i_ctime;
			d_drop(dentry);
			unlock_dir(lower_dir_dentry);
			dput(lower_dentry);
			sgfs_put_lower_path(dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
			printk("Successfully deleted the file\n");
			return 0;
		}

		else{
			printk("I am unlinking after encryption\n");
			struct file *f_read = NULL;
			struct file *f_write = NULL;
			char *buff3 = NULL;
			char *buff4 = NULL;
			// char *buff5 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
			char *key = (char*)kmalloc(sizeof(char)*10,GFP_KERNEL);
			size_t key_len, src_len;
			size_t dst_len;
			mm_segment_t oldfs1;
			mm_segment_t oldfs2;
			int bytes1;
			int bytes2;
			int curr_read_size = 0;
			int curr_write_size = 0;
			char *fname = kmalloc(sizeof(char)*PATH_MAX,GFP_KERNEL);
			char *abs_path = kmalloc(sizeof(char)*100,GFP_KERNEL);
			char *year = kmalloc(sizeof(char)*4,GFP_KERNEL);
			char *month = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *day = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *hrs = kmalloc(sizeof(char)*2,GFP_KERNEL);
			char *mins = kmalloc(sizeof(char)*2,GFP_KERNEL);
			int c, fsize, temp_size;
			struct inode *Inode;



			struct timeval time;
			struct tm tm;
			unsigned long local_time;
			char uid[5];

			uid_t curr_user;
			struct user_struct *us = current_user();
		     curr_user = get_uid(us)->uid.val;
		     printk("curr id is %d\n",curr_user);

			c = snprintf(uid,5,"%04d",curr_user);
			strcat(fname,uid);
			strcat(fname,"-");
			
			do_gettimeofday(&time);
			local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
			rtc_time_to_tm(local_time, &tm);

			c = snprintf(year,5,"%04d",tm.tm_year + 2016);
			strcat(fname,year);
			strcat(fname,"-");
			c = snprintf(month,3,"%02d",tm.tm_mon);
			strcat(fname,month);
			strcat(fname,"-");
			c = snprintf(day,3,"%02d",tm.tm_mday + 1);
			strcat(fname,day);
			strcat(fname,"-");
			c = snprintf(hrs,3,"%02d",tm.tm_hour);
			strcat(fname,hrs);
			strcat(fname,":");
			c = snprintf(mins,3,"%02d",tm.tm_min);
			strcat(fname,mins);
			strcat(fname,"-");
			strcat(fname,dentry->d_iname);
			strcat(fname,".enc");
			printk("filename is %s\n",fname);

			

			f_read = filp_open(path, O_RDONLY, 0);
			if (!f_read || IS_ERR(f_read)) {
			printk("Reading file 1 is failed\n");
			printk("wrapfs_read_file err %d\n", (int) PTR_ERR(f_read));
			return -(int)PTR_ERR(f_read);  // or do something else
			}

			Inode = f_read->f_path.dentry->d_inode;
			fsize = i_size_read(Inode);
			printk("file size is %d\n",fsize);
			strcpy(abs_path,"/usr/src/hw2-vanugu/hw2/sgfs/.sg/");
			strcat(abs_path,fname);

			f_write = filp_open(abs_path, O_WRONLY | O_CREAT, 0644);
			if(!f_write || IS_ERR(f_write)){
				printk("Wrapfs_write_file_4 err %d\n", (int)PTR_ERR(f_write));
				return -(int)PTR_ERR(f_write);
			}


			while(fsize > 0){

				buff3 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
				buff4 = (char*)kmalloc(sizeof(char)*PAGE_SIZE,GFP_KERNEL);
				if(fsize > PAGE_SIZE - 16){
					temp_size = PAGE_SIZE - 16;
					fsize = fsize - temp_size;
				}
				else {
					temp_size = fsize;
					fsize = 0;
				}
				f_read->f_pos = curr_read_size;
				oldfs1 = get_fs();
				set_fs(KERNEL_DS);
				bytes1 = vfs_read(f_read, buff3,temp_size, &f_read->f_pos);
				set_fs(oldfs1);
				printk("data is %s\n",buff3);
				printk("Bytes read is %d\n",bytes1);

				printk("About to encrypt the file\n");
				src_len = bytes1;
				err = sgfs_encryption(key,key_len,buff4,&dst_len,buff3,src_len);
				if(err < 0){
					printk("Encryption failed\n");
					kfree(buff3);
					kfree(buff4);
					kfree(key);
					return err;
				}
				printk("Encryption_success\n");
				printk("Encrypted buff is %s\n",buff4);

				f_write->f_pos = curr_write_size;
				oldfs2 = get_fs();
				set_fs(KERNEL_DS);
				bytes2 = vfs_write(f_write, buff4, (int)dst_len, &f_write->f_pos);
				set_fs(oldfs2);
				printk("%d\n",bytes2);

				printk("Successfully written the file\n");
				kfree(buff3);
				kfree(buff4);
				printk("successfully freed the buffer\n");

				curr_read_size += bytes1;
				curr_write_size += bytes2;

			}


			filp_close(f_read,NULL);
			filp_close(f_write,NULL);
			kfree(key);


			sgfs_get_lower_path(dentry, &lower_path);
			lower_dentry = lower_path.dentry;
			dget(lower_dentry);
			lower_dir_dentry = lock_parent(lower_dentry);

			err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

			/*
			 * Note: unlinking on top of NFS can cause silly-renamed files.
			 * Trying to delete such files results in EBUSY from NFS
			 * below.  Silly-renamed files will get deleted by NFS later on, so
			 * we just need to detect them here and treat such EBUSY errors as
			 * if the upper file was successfully deleted.
			 */
			if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
				err = 0;
			if (err){
				unlock_dir(lower_dir_dentry);
				dput(lower_dentry);
				sgfs_put_lower_path(dentry, &lower_path);
				printk("Couldn't unlink the file error is %d", err);
				return err;
			}
			fsstack_copy_attr_times(dir, lower_dir_inode);
			fsstack_copy_inode_size(dir, lower_dir_inode);
			set_nlink(d_inode(dentry),
				  sgfs_lower_inode(d_inode(dentry))->i_nlink);
			d_inode(dentry)->i_ctime = dir->i_ctime;
			d_drop(dentry);
			unlock_dir(lower_dir_dentry);
			dput(lower_dentry);
			sgfs_put_lower_path(dentry, &lower_path); /* this is needed, else LTP fails (VFS won't do it) */
			printk("Successfully moved the file to the recycle bin after encryption\n");
			return 0;
		}
	}
}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
