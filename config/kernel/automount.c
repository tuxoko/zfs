#include <linux/dcache.h>
struct vfsmount *d_automount(struct path *p) { return NULL; }
struct dentry_operations dops __attribute__ ((unused)) = {
	.d_automount = d_automount,
};
