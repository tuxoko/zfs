dnl #
dnl # Check if posix_acl_release can be used from a CDDL module,
dnl # The is_owner_or_cap macro was replaced by
dnl # inode_owner_or_capable
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_RELEASE], [
	AC_MSG_CHECKING([whether posix_acl_release() is available])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([acl_release],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_RELEASE, 1,
		    [posix_acl_release() is available])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([whether posix_acl_release() is GPL-only])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([acl_release_gpl],[
		AC_MSG_RESULT(no)
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_RELEASE_GPL_ONLY, 1,
		    [posix_acl_release() is GPL-only])
	])
])

dnl #
dnl # 3.1 API change,
dnl # posix_acl_chmod_masq() is not exported anymore and posix_acl_chmod()
dnl # was introduced to replace it.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_CHMOD], [
	AC_MSG_CHECKING([whether posix_acl_chmod exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([acl_chmod],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_CHMOD, 1, [posix_acl_chmod() exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.30 API change,
dnl # caching of ACL into the inode was added in this version.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_CACHING], [
	AC_MSG_CHECKING([whether inode has i_acl and i_default_acl])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([acl_caching],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_CACHING, 1,
		    [inode contains i_acl and i_default_acl])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 3.1 API change,
dnl # posix_acl_equiv_mode now wants an umode_t* instead of a mode_t*
dnl #
AC_DEFUN([ZFS_AC_KERNEL_POSIX_ACL_EQUIV_MODE_WANTS_UMODE_T], [
	AC_MSG_CHECKING([whether posix_acl_equiv_mode() wants umode_t])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([acl_equiv_mode],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_POSIX_ACL_EQUIV_MODE_UMODE_T, 1,
		    [ posix_acl_equiv_mode wants umode_t*])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.27 API change,
dnl # Check if inode_operations contains the function permission
dnl # and expects the nameidata structure to have been removed.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_PERMISSION], [
	AC_MSG_CHECKING([whether iops->permission() exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([iops_permission],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_PERMISSION, 1, [iops->permission() exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.26 API change,
dnl # Check if inode_operations contains the function permission
dnl # and expects the nameidata structure to be passed.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_PERMISSION_WITH_NAMEIDATA], [
	AC_MSG_CHECKING([whether iops->permission() wants nameidata])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([iops_permission_metadata],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_PERMISSION, 1, [iops->permission() exists])
		AC_DEFINE(HAVE_PERMISSION_WITH_NAMEIDATA, 1,
		    [iops->permission() with nameidata exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.32 API change,
dnl # Check if inode_operations contains the function check_acl
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_CHECK_ACL], [
	AC_MSG_CHECKING([whether iops->check_acl() exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([iops_check_acl],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CHECK_ACL, 1, [iops->check_acl() exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.38 API change,
dnl # The function check_acl gained a new parameter: flags
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_CHECK_ACL_WITH_FLAGS], [
	AC_MSG_CHECKING([whether iops->check_acl() wants flags])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([iops_check_acl_flags],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CHECK_ACL, 1, [iops->check_acl() exists])
		AC_DEFINE(HAVE_CHECK_ACL_WITH_FLAGS, 1,
		    [iops->check_acl() wants flags])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 3.1 API change,
dnl # Check if inode_operations contains the function get_acl
dnl #
AC_DEFUN([ZFS_AC_KERNEL_INODE_OPERATIONS_GET_ACL], [
	AC_MSG_CHECKING([whether iops->get_acl() exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([iops_get_acl],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_GET_ACL, 1, [iops->get_acl() exists])
	],[
		AC_MSG_RESULT(no)
	])
])

dnl #
dnl # 2.6.30 API change,
dnl # current_umask exists only since this version.
dnl #
AC_DEFUN([ZFS_AC_KERNEL_CURRENT_UMASK], [
	AC_MSG_CHECKING([whether current_umask exists])
	ZFS_AC_KERNEL_PARALLEL_TEST_IF([current_umask],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_CURRENT_UMASK, 1, [current_umask() exists])
	],[
		AC_MSG_RESULT(no)
	])
])
