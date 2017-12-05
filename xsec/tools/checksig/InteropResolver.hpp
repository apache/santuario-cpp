/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * XSEC
 *
 * InteropResolver := Class to resolve key elements into certificates for
 *                      merlin-18 interop test
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

// XSEC

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECKeyInfoResolver.hpp>

#if defined (_WIN32)
#    include <io.h>
#else
#    include <glob.h>
#endif

#if defined (XSEC_HAVE_OPENSSL)
#   include <openssl/x509.h>

class InteropResolver : public XSECKeyInfoResolver {

public :

    InteropResolver(const XMLCh * baseURI);
    ~InteropResolver();

    // Interface functions

    virtual XSECCryptoKey * resolveKey(const DSIGKeyInfoList * lst) const;
    virtual XSECKeyInfoResolver * clone(void) const;

    // Internal functions
    X509 * nextFile2Cert(void) const;
    bool checkMatch(const DSIGKeyInfoList * lst, X509 * x) const;
    XSECCryptoKey * openCertURI(const XMLCh * uri) const;

private:

    XMLCh *         mp_baseURI;
    mutable bool    m_searchStarted;
    mutable bool    m_searchFinished;

#if defined (_WIN32)
    mutable _finddata_t m_finder;
    mutable long    m_handle;
#else
    mutable glob_t  m_globbuf;
    mutable int     m_fcount;
#endif

};

#endif /* XSEC_HAVE_OPENSSL */
