#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/posix_acl.h>

void test(void) {
	struct posix_acl *tmp = posix_acl_alloc(1, 0);
	posix_acl_release(tmp);
}
