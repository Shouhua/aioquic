# _AX_FUNC_MKDIR_ONE_ARG(IF-ONE-ARG, IF-TWO-ARGS)
# -----------------------------------------------
# Execute IF-TWO-ARGS if mkdir() accepts two
# arguments; execute IF-ONE-ARG otherwise.
AC_DEFUN([_AX_FUNC_MKDIR_ONE_ARG],
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/stat.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_IO_H
# include <io.h>
#endif
]], [[mkdir (".", 0700);]])], [$2], [$1])])

AC_DEFUN([AX_FUNC_MKDIR_ONE_ARG],
[AC_CACHE_CHECK([whether mkdir takes one argument],
[ax_cv_mkdir_one_arg],
[_AX_FUNC_MKDIR_ONE_ARG([ax_cv_mkdir_one_arg=yes],
[ax_cv_mkdir_one_arg=no])])
if test x"$ax_cv_mkdir_one_arg" = xyes; then
AC_DEFINE([MKDIR_ONE_ARG], 1,
[Define if mkdir takes only one argument.])
fi]) # AX_FUNC_MKDIR_ONE_ARG

AC_DEFUN([AX_FUNC_MKDIR],
[AC_CHECK_FUNCS([mkdir _mkdir])
AC_CHECK_HEADERS([io.h])
AX_FUNC_MKDIR_ONE_ARG
])