#include <linux/fs.h>

int test_fsync(struct file *f, struct dentry *dentry, int x)
    { return 0; }

static const struct file_operations
    fops __attribute__ ((unused)) = {
	.fsync = test_fsync,
};
