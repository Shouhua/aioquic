#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#  rm -rf autom4te.cache build-aux aclocal.m4 config.* configure configure~ Makefile Makefile.in stamp-h1 .deps


AC_PREREQ([2.71])
AC_INIT([amhello], [1.0], [bug-report@address])

AC_CONFIG_AUX_DIR([build-aux])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# safe check, 确保configure在正确的目录
AC_CONFIG_SRCDIR([src/main.c])

# 告知哪个文件夹包含外部M4宏, 还需要再Makefile.am中设置ACLOCAL_AMFLAGS=  -I m4
AC_CONFIG_MACRO_DIR([m4])
# 根据in文件生成对应的头文件，AC_DEFINE，check结果的变量都会放到里面
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

# subdir-objects 表示Makefile.am可能会引用其他文件夹中文件
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign 1.1])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([time.h], [echo "Header time.h was found"; has_timer=yes])
if test "x$has_timer" = "xyes"; then
  AC_MSG_RESULT([[CHECK] HAS time.h HEADER >>>])
fi

# Checks for typedefs, structures, and compiler characteristics.
# AC_CHECK_TYPES([uint8_t uint16_t])
# AC_CHECK_FUNC([fork], [echo "Function fork was found"; has_fork=yes])

# Checks for library functions.
# AC_SEARCH_LIBS([PEM_write], [crypto], [echo "OpenSSL crypto library was found"])


AC_CHECK_DECLS([be64toh], [], [])


# Package Options
# --enable-debug
AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [Turn on debug output])], [debug=$enableval;echo "ENABLE debug"], [debug=no;echo "DISABLE debug"])
if test "x${debug}" = "xyes"; then
    DEBUGFLAGS="-O0 -g3"
    AC_SUBST([DEBUGFLAGS])
    AC_DEFINE([DEBUGBUILD], [1], [Define to 1 to enable debug output.])
fi

# 自定义宏，放在m4文件夹中，mkdir.m4
AX_FUNC_MKDIR

AC_OUTPUT

AC_MSG_NOTICE([summary of build options:
    Package version: ${VERSION}
    Library version: $LT_CURRENT:$LT_REVISION:$LT_AGE
    Install prefix:  ${prefix}
    System types:
      Build:         ${build}
      Host:          ${host}
      Target:        ${target}
    Compiler:
      C preprocessor: ${CPP}
      CPPFLAGS:       ${CPPFLAGS}
      C compiler:     ${CC}
      CFLAGS:         ${CFLAGS}
      C++ compiler:   ${CXX}
      CXXFLAGS:       ${CXXFLAGS}
      LDFLAGS:        ${LDFLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      WARNCXXFLAGS:   ${WARNCXXFLAGS}
      EXTRACFLAG:     ${EXTRACFLAG}
      LIBS:           ${LIBS}
    Library:
      Shared:         ${enable_shared}
      Static:         ${enable_static}
    Debug:
      Debug:          ${debug} (CFLAGS='${DEBUGCFLAGS}')
    Library only:     ${lib_only}
    Examples:         ${enable_examples}
])

