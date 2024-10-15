/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Joe Farnham"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;
static long aesd_adjust_file_offset(struct file* filp, unsigned int write_cmd, unsigned int write_cmd_offset);

int aesd_open(struct inode *inode, struct file *filp)
{
	struct aesd_dev *dev; /* device information */
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; /* for other methods */	
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
	struct aesd_dev* dev = filp->private_data;
	if(mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

	size_t entry_offset_byte_rtn = 0;
	struct aesd_buffer_entry* entry = aesd_circular_buffer_find_entry_offset_for_fpos(
																	&dev->buffer,
																	*f_pos,
																	&entry_offset_byte_rtn);
	PDEBUG("offset: %u", entry_offset_byte_rtn);
	if(!entry)
		goto out;

	if(entry_offset_byte_rtn + count > entry->size)
		count = entry->size - entry_offset_byte_rtn;

	if(copy_to_user(buf, entry->buffptr + entry_offset_byte_rtn, count)) {
		PDEBUG("copy failed");
		retval = -EFAULT;
		goto out;
	}

	PDEBUG("copied to user");
	*f_pos += count;
	retval = count;

out:
	mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
	struct aesd_dev* dev = filp->private_data;
	if(mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

	if(!dev->entry.buffptr) {
		dev->entry.buffptr = kmalloc(count, GFP_KERNEL);
		
		if(!dev->entry.buffptr)
			goto out;
		
		if(copy_from_user(dev->entry.buffptr, buf, count)) {
			retval = -EFAULT;
			goto out;
		}
		dev->entry.size = count;
	}
	else {
		const char* tmp = dev->entry.buffptr;
		dev->entry.buffptr = kmalloc(dev->entry.size + count, GFP_KERNEL);

		if(!dev->entry.buffptr)
			goto out;

		memcpy(dev->entry.buffptr, tmp, dev->entry.size);
		kfree(tmp);

		if(copy_from_user(dev->entry.buffptr + dev->entry.size, buf, count)) {
			retval = -EFAULT;
			goto out;
		}
		dev->entry.size += count;
	}

	if(dev->entry.buffptr[dev->entry.size - 1] == '\n') {
		aesd_circular_buffer_add_entry(&dev->buffer, &dev->entry);
		dev->entry.buffptr = NULL;
		dev->entry.size = 0;
	}
	retval = count;

out:
	mutex_unlock(&dev->lock);

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
	PDEBUG("llseek");
	loff_t retval = 0;
	struct aesd_dev* dev = filp->private_data;

	if(mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

	struct aesd_buffer_entry* entry;
	uint8_t index;
	loff_t size = 0;
	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
		size += entry->size;
	}

	retval = fixed_size_llseek(filp, offset, whence, size);

	mutex_unlock(&dev->lock);
	return retval;
}

long aesd_unlocked_ioctl(struct file* filp, unsigned int cmd, unsigned long arg) {
	PDEBUG("unlocked ioctl");
	long retval = -ENOTTY;

	if((_IOC_TYPE(cmd) != AESD_IOC_MAGIC) || (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR))
		return -ENOTTY;

	switch(cmd) {
		case AESDCHAR_IOCSEEKTO:
		{
			struct aesd_seekto seekto;
			if(copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto))) {
				retval = EFAULT;
			}
			else {
				retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
			}
			break;
		}

		default:
			break;
	}
	return retval;
}

static long aesd_adjust_file_offset(struct file* filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
	PDEBUG("adjust file offset");
	long retval = -EINVAL;
	struct aesd_dev* dev = filp->private_data;

	if(mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	
	if(write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
		goto out;

	struct aesd_buffer_entry* entry = &dev->buffer.entry[write_cmd];
	if(write_cmd_offset >= entry->size)
		goto out;

	size_t start_pos = 0;
	size_t i = 0;
	for(i = 0; i < write_cmd; i++)
		start_pos += dev->buffer.entry[i].size;

	filp->f_pos = start_pos + write_cmd_offset;
	retval = 0;

out:
	mutex_unlock(&dev->lock);

	return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
	.llseek = 	aesd_llseek,
	.unlocked_ioctl = aesd_unlocked_ioctl
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
	aesd_circular_buffer_init(&aesd_device.buffer);
	mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
	struct aesd_buffer_entry* entry;
	uint8_t index;
	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
		if(entry->buffptr)
			kfree(entry->buffptr);
	}

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
