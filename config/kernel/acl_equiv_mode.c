#include <linux/fs.h>
#include <linux/posix_acl.h>

void test(void)
{
	umode_t tmp;
	posix_acl_equiv_mode(NULL, &tmp);
}
