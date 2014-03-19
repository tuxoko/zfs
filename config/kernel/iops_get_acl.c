#include <linux/fs.h>

struct posix_acl *get_acl_fn(struct inode *inode, int type)
    { return NULL; }

static const struct inode_operations
    iops __attribute__ ((unused)) = {
	.get_acl = get_acl_fn,
};
