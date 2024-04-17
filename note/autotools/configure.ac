#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# rm -rf aclocal.m4 autom4te.cache build-aux/ config.* Makefile.in configure stamp-h1 configure~ Makefile configure.log lib
# tool hello main.o .deps .libs build m4/*

AC_PREREQ([2.71])
AC_INIT([amhello], [1.0], [bug-report@address])

AC_CONFIG_AUX_DIR([build-aux])

# safe check
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

# subdir-objects 表示Makefile.am可能会引用其他文件夹中文件
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign 1.1])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
# AC_CHECK_HEADERS([time.h], [echo "Header time.h was found"; has_timer=yes])

# Checks for typedefs, structures, and compiler characteristics.
# AC_CHECK_TYPES([uint8_t uint16_t])
# AC_CHECK_FUNC([fork], [echo "Function fork was found"; has_fork=yes])

# Checks for library functions.
# AC_SEARCH_LIBS([PEM_write], [crypto], [echo "OpenSSL crypto library was found"])


# Package Options
# --enable-debug
AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [Turn on debug output])], [debug=$enableval;echo "ENABLE debug"], [debug=no;echo "DISABLE debug"])
if test "x${debug}" = "xyes"; then
    DEBUGFLAGS="-O0 -g3"
    AC_SUBST([DEBUGFLAGS])
    AC_DEFINE([DEBUGBUILD], [1], [Define to 1 to enable debug output.])
fi

AC_OUTPUT
