#include <linux/fs.h>
#include <linux/posix_acl.h>

void test(void)
{
	posix_acl_chmod(NULL, 0, 0);
}
