#include <linux/fs.h>

void test(void) {
	struct inode ino;
	ino.i_acl = NULL;
	ino.i_default_acl = NULL;
}
