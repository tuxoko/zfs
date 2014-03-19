dnl #
dnl # 2.6.37 API change
dnl # The dops->d_automount() dentry operation was added as a clean
dnl # solution to handling automounts.  Prior to this cifs/nfs clients
dnl # which required automount support would abuse the follow_link()
dnl # operation on directories for this purpose.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_AUTOMOUNT], [
	AC_MSG_CHECKING([whether dops->d_automount() exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([automount],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_AUTOMOUNT, 1, [dops->automount() exists])
	],[
		_AC_MSG_LOG_CONFTEST m4_ifvaln([AC_MSG_RESULT(no)],[AC_MSG_RESULT(no)])
	])
])
