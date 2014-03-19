#include <linux/fs.h>

int check_acl_fn(struct inode *inode, int mask) { return 0; }

static const struct inode_operations
    iops __attribute__ ((unused)) = {
	.check_acl = check_acl_fn,
};
