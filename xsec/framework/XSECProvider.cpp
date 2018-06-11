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
 * XSECProvider.hpp := The main interface for users wishing to gain access
 *                     to signature objects
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECProvider.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/framework/XSECURIResolverXerces.hpp>

#include "../utils/XSECDOMUtils.hpp"
#include "../xenc/impl/XENCCipherImpl.hpp"

#ifdef XSEC_XKMS_ENABLED
#  include "../xkms/impl/XKMSMessageFactoryImpl.hpp"
#endif

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Constructors/Destructors
// --------------------------------------------------------------------------------


XSECProvider::XSECProvider() {

    mp_URIResolver = new XSECURIResolverXerces();
#ifdef XSEC_XKMS_ENABLED
    XSECnew(mp_xkmsMessageFactory, XKMSMessageFactoryImpl());
#endif
}

XSECProvider::~XSECProvider() {

    if (mp_URIResolver != NULL)
        delete mp_URIResolver;

#ifdef XSEC_XKMS_ENABLED
    // Clean up XKMS stuff
    delete mp_xkmsMessageFactory;
#endif
}

// --------------------------------------------------------------------------------
//           Signature Creation/Deletion
// --------------------------------------------------------------------------------


DSIGSignature* XSECProvider::newSignatureFromDOM(DOMDocument* doc, DOMNode* sigNode) {

    DSIGSignature* ret;

    XSECnew(ret, DSIGSignature(doc, sigNode));

    setup(ret);

    return ret;
}

DSIGSignature* XSECProvider::newSignatureFromDOM(DOMDocument* doc) {

    DSIGSignature* ret;

    DOMNode* sigNode = findDSIGNode(doc, "Signature");

    if (sigNode == NULL) {

        throw XSECException(XSECException::SignatureCreationError,
            "Could not find a signature node in passed in DOM document");

    }

    XSECnew(ret, DSIGSignature(doc, sigNode));

    setup(ret);

    return ret;
}

DSIGSignature* XSECProvider::newSignature() {

    DSIGSignature* ret;

    XSECnew(ret, DSIGSignature());

    setup(ret);

    return ret;
}

void XSECProvider::releaseSignature(DSIGSignature* toRelease) {
    delete toRelease;
}

// --------------------------------------------------------------------------------
//           Cipher Creation/Deletion
// --------------------------------------------------------------------------------

XENCCipher* XSECProvider::newCipher(DOMDocument* doc) {

    XENCCipherImpl* ret;

    XSECnew(ret, XENCCipherImpl(doc));

    setup(ret);

    return ret;
}

void XSECProvider::releaseCipher(XENCCipher* toRelease) {
    delete toRelease;
}

#ifdef XSEC_XKMS_ENABLED
// --------------------------------------------------------------------------------
//           XKMS Methods
// --------------------------------------------------------------------------------

XKMSMessageFactory* XSECProvider::getXKMSMessageFactory() {
    return mp_xkmsMessageFactory;
}
#endif

// --------------------------------------------------------------------------------
//           Environmental methods
// --------------------------------------------------------------------------------


void XSECProvider::setDefaultURIResolver(XSECURIResolver* resolver) {

    if (mp_URIResolver != 0)
        delete mp_URIResolver;

    mp_URIResolver = resolver->clone();
}

// --------------------------------------------------------------------------------
//           Internal functions
// --------------------------------------------------------------------------------

void XSECProvider::setup(DSIGSignature* sig) {

    // Called by all Signature creation methods to set up the sig
    sig->setURIResolver(mp_URIResolver);
}

void XSECProvider::setup(XENCCipher* cipher) {

}
