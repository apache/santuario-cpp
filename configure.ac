# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

# Process this file with autoreconf
AC_PREREQ(2.50)
AC_INIT([[XML-Security-C]],[2.0.0],[dev@santuario.apache.org],[xml-security-c])
AC_CONFIG_SRCDIR(xsec)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE([foreign dist-bzip2 dist-zip subdir-objects nostdinc])
AC_PROG_LIBTOOL
PKG_INSTALLDIR

AC_SYS_LARGEFILE

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Have GCC compile with symbols (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi


# Define the files we wish to generate

AC_CONFIG_FILES([Makefile xsec/Makefile xml-security-c.pc])
AC_CONFIG_HEADERS([config.h xsec/framework/XSECConfig.hpp])
AH_BOTTOM([#include <xsec/framework/XSECVersion.hpp>])

# Check for basic programs

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
AC_CHECK_PROG(AUTOCONF, autoconf, autoconf, true)

if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $GCC_CFLAGS"
    CXXFLAGS="-Wall $GCC_CXXFLAGS"
fi

# Check for required includes
AC_CHECK_HEADERS([unistd.h direct.h])

AC_CHECK_FUNCS([strcasecmp])

# Check whether getcwd can dynamically allocate memory.
AC_MSG_CHECKING([whether getcwd(NULL, 0) works])
AC_RUN_IFELSE([AC_LANG_PROGRAM([#include <stdlib.h>
     #include <unistd.h>],
[char *cwd = getcwd(NULL, 0);
return (cwd != NULL) ? EXIT_SUCCESS : EXIT_FAILURE;])],
     [AC_MSG_RESULT(yes)
      AC_DEFINE([XSEC_HAVE_GETCWD_DYN], [1],
         [Define to 1 if getcwd(NULL, 0) works])],
     [AC_MSG_RESULT(no)])

AC_LANG(C++)

AX_PKG_CHECK_MODULES([xerces],,[xerces-c >= 3.2])

# Get user options

AC_ARG_WITH(xalan, 
    AS_HELP_STRING([--with-xalan],[Enable Xalan integration.  Values = 'yes' or installation directory (Default = yes)]), 
    use_xalan=$withval, use_xalan=yes)

if test x"$use_xalan" != "xyes" ; then
  if test x"$use_xalan" != "xno" ; then
    XALANCROOT=$use_xalan
  fi
fi

# Now check for Xalan

if test x"$use_xalan" != x"no" ; then

  if test $XALANCROOT; then

    AC_MSG_CHECKING([for Xalan headers in XALANCROOT])

    OLD_CPPFLAGS=$CPPFLAGS
    # Updated to include nls/include as this is generally needed for
    # compilation against non-installed xalan.
    # Also now include XALANCROOT/include to cater for installed xalan
    CPPFLAGS=["-I${XALANCROOT}/src -I${XALANCROOT}/include -I${XALANCROOT}/nls/include ${CPPFLAGS}"]

    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[#include <xalanc/Include/XalanVersion.hpp>]])],[xalan_found=yes 
      LIBS="-L${XALANCROOT}/lib -lxalan-c ${LIBS}"
      AC_MSG_RESULT([found])],[CPPFLAGS=$OLD_CPPFLAGS
      AC_MSG_RESULT([no])]);

  fi

  if test -z "$xalan_found" ; then

    AC_MSG_CHECKING([for Xalan in system includes])
    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[#include <xalanc/Include/XalanVersion.hpp>]])],
        [xalan_found=yes 
        LIBS="${LIBS} -lxalan-c"
        AC_MSG_RESULT([found])],
      [AC_MSG_RESULT([no - WARNING - configuring without Xalan])]);

  fi
fi

if test "${xalan_found}" = "yes" ; then

AC_MSG_CHECKING([Xalan version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xalanc/Include/XalanVersion.hpp>],
[#if  _XALAN_VERSION >= 11100
int i = 0;
#else
#error requires Xalan version 1.11+
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xalan-C 1.11+ is required])])

  # Do we need xalanMsg.so?
  AC_MSG_CHECKING([if libxalanMsg is required])
  old_libs=$LIBS
  LIBS="${LIBS} -lxalanMsg"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
    int test=1;
  ]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT(no)
  LIBS=${old_libs}]);
  
  AC_DEFINE([XSEC_HAVE_XALAN],[1],[Define to 1 if Xalan is available.])

else
  AC_MSG_NOTICE([Xalan not included in build - XPath and XSLT will not be available])
fi


# Crypto provider options (OpenSSL / NSS)

AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl],[use the OpenSSL crypto provider @<:@default=check@:>@])],,
    [with_openssl=check])

AS_IF([test x"$with_openssl" != xno],
    [AX_PKG_CHECK_MODULES([openssl],,[libcrypto],
        [with_openssl=found
         AC_DEFINE([XSEC_HAVE_OPENSSL],[1],[Define if OpenSSL is in use])

    # Now try to find out some things about this version of OpenSSL
    
    old_flags=$CFLAGS
    old_libs=$LIBS
    CFLAGS="$CFLAGS $openssl_CFLAGS"
    LIBS="$LIBS $openssl_LIBS"

    AC_MSG_CHECKING([for const input buffers in OpenSSL])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <openssl/rsa.h>]], [[ const unsigned char * buf;
    	  unsigned char * outbuf;
    	  RSA rsa;
    	  RSA_private_decrypt(1,buf,outbuf,&rsa,RSA_PKCS1_PADDING);]])],
    	[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_CONST_BUFFERS],[1],[Define to 1 if OpenSSL uses const input buffers.])],
    	[AC_MSG_RESULT([no])])
    
    AC_CHECK_DECL(EVP_PKEY_id,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_EVP_PKEY_ID],[1],[Define to 1 if OpenSSL has EVP_PKEY_id function.])],
        ,[#include <openssl/evp.h>])
    
    AC_MSG_CHECKING([for non-broken AES support])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/evp.h>]], [[ EVP_aes_256_cbc();
    	]])],[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_HAVE_AES],[1],[Define to 1 if OpenSSL has full AES support.])],
    	[AC_MSG_RESULT([no])])

    AC_MSG_CHECKING([for GCM support])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/evp.h>]], [[ EVP_aes_256_gcm();
    	]])],[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_HAVE_GCM],[1],[Define to 1 if OpenSSL has GCM support.])],
    	[AC_MSG_RESULT([no])])

    AC_CHECK_DECL(PKCS1_MGF1,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_MGF1],[1],[Define to 1 if OpenSSL has PKCS1_MGF1 function.])],
        ,[#include <openssl/rsa.h>])
    
    AC_CHECK_DECL(EVP_PKEY_set1_EC_KEY,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_EC],[1],[Define to 1 if OpenSSL has EC support.])],
        ,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(EVP_sha512,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_SHA2],[1],[Define to 1 if OpenSSL has SHA2 support.])],
        ,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(EVP_CIPHER_CTX_set_padding,
    	[AC_DEFINE([XSEC_OPENSSL_CANSET_PADDING],[1],[Define to 1 if OpenSSL has EVP_CIPHER_CTX_set_padding.])],
    	,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(CRYPTO_cleanup_all_ex_data,
    	[AC_DEFINE([XSEC_OPENSSL_HAVE_CRYPTO_CLEANUP_ALL_EX_DATA],[1],[Define to 1 if OpenSSL has CRYPTO_cleanup_all_ex_data.])],
    	,[#include <openssl/crypto.h>])
    
    AC_MSG_CHECKING([for const input buffer in loadX509Base64Bin])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <openssl/x509.h>]], [[ const unsigned char * buf; d2i_X509(NULL, &buf, 1);]])],
        [AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_D2IX509_CONST_BUFFER],[1],[Define to 1 if OpenSSL X509 API has const input buffer.])],
    	[AC_MSG_RESULT([no])])

    CFLAGS="$old_CFLAGS"
    LIBS="$old_LIBS"

        ],[AS_IF([test "x$with_openssl" != xcheck],[AC_MSG_ERROR([Unable to find OpenSSL])])])
    ])

AC_ARG_WITH([nss],
    [AS_HELP_STRING([--with-nss],[use the NSS crypto provider @<:@default=check@:>@])],,
    [with_nss=check])

AS_IF([test x"$with_nss" != xno],
    [AX_PKG_CHECK_MODULES([nss],,[nss],
        [with_nss=found
         AC_DEFINE([XSEC_HAVE_NSS],[1],[Define if NSS is in use])
         AC_MSG_WARN([NSS is no longer officially supported])
        ],[AS_IF([test "x$with_nss" != "xcheck"],[AC_MSG_ERROR([Unable to find NSS])])])
    ])

AC_ARG_ENABLE(xkms,
    AS_HELP_STRING([--disable-xkms],[disable XKMS support]),
    [have_xkms=${enableval}],
    [have_xkms=yes])
if test x"$have_xkms" = "xyes" ; then
    AC_DEFINE([XSEC_XKMS_ENABLED],[1],[Define to 1 if XKMS support is included.])
fi

# Populate the Makefile conditionals
AM_CONDITIONAL([XSEC_AM_HAVE_OPENSSL],[test "x$with_openssl" = xfound])
AM_CONDITIONAL([XSEC_AM_HAVE_NSS],[test "x$with_nss" = xfound])
AM_CONDITIONAL(XSEC_AM_HAVE_XKMS, test x"$have_xkms" = "xyes")

# output the Makefiles
AC_OUTPUT
