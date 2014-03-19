#include <linux/fs.h>

int permission_fn(struct inode *inode, int mask) { return 0; }

static const struct inode_operations
    iops __attribute__ ((unused)) = {
	.permission = permission_fn,
};
