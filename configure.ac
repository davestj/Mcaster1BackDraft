AC_PREREQ([2.69])
AC_INIT([Mcaster1BackDraft], [0.0.1], [davestj@mcaster1.com])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_LANG([C++])
AC_PROG_CXX

# ---- C++17 ----
AX_CXX_COMPILE_STDCXX([17], [noext], [mandatory])

# ---- pkg-config libraries ----
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([OPENSSL],  [openssl >= 1.1.0])
PKG_CHECK_MODULES([YAMLCPP],  [yaml-cpp >= 0.5.0])

# ---- MySQL / MariaDB ----
AC_PATH_PROG([MYSQL_CONFIG], [mysql_config mariadb_config], [not-found])
AS_IF([test "$MYSQL_CONFIG" != "not-found"], [
    MYSQLCLIENT_CFLAGS=`$MYSQL_CONFIG --cflags`
    MYSQLCLIENT_LIBS=`$MYSQL_CONFIG --libs`
], [
    AC_MSG_ERROR([mysql_config / mariadb_config not found. Install libmysqlclient-dev or libmariadb-dev.])
])
AC_SUBST([MYSQLCLIENT_CFLAGS])
AC_SUBST([MYSQLCLIENT_LIBS])

# ---- libgd (CAPTCHA image generation) ----
PKG_CHECK_MODULES([GDLIB], [gdlib >= 2.3.0])

# ---- pthreads ----
AX_PTHREAD([],  [AC_MSG_ERROR([pthreads not found])])
LIBS="$PTHREAD_LIBS $LIBS"
CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"

# ---- nlohmann/json (header-only) ----
AC_CHECK_HEADERS([nlohmann/json.hpp], [],
    [AC_MSG_ERROR([nlohmann/json.hpp not found. Install nlohmann-json3-dev.])])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo ""
echo "  Mcaster1BackDraft configured:"
echo "    CXXFLAGS: $CXXFLAGS"
echo "    LIBS:     $OPENSSL_LIBS $YAMLCPP_LIBS $MYSQLCLIENT_LIBS $GDLIB_LIBS $PTHREAD_LIBS"
