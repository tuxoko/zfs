#include <linux/fs.h>

int test_fsync(struct file *f, loff_t a, loff_t b, int c)
    { return 0; }

static const struct file_operations
    fops __attribute__ ((unused)) = {
	.fsync = test_fsync,
};
