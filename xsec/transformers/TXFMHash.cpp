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
 * TXFMHash := Class that performs a hash/HMAC transform
 *
 * $Id$
 *
 */

#include <xsec/transformers/TXFMHash.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/framework/XSECException.hpp>

XERCES_CPP_NAMESPACE_USE

TXFMHash::TXFMHash(DOMDocument* doc, XSECCryptoHash::HashType type, const XSECCryptoKey* key) :
    TXFMBase(doc), mp_h(NULL), md_value(NULL), md_len(0), toOutput(0) {

    if (key == NULL) {
        // Get a hash worker
        mp_h = XSECPlatformUtils::g_cryptoProvider->hash(type);
        if (!mp_h) {
            throw XSECException(XSECException::CryptoProviderError,
                "Error requesting hash object from Crypto Provider");
        }
    } 
    else {
        // Get an HMAC worker

        mp_h = XSECPlatformUtils::g_cryptoProvider->HMAC(type);
        if (!mp_h) {
            throw XSECException(XSECException::CryptoProviderError,
                    "Error requesting HMAC object from Crypto Provider");
        }
        mp_h->setKey(key);
    }

    md_value = new unsigned char[XSECPlatformUtils::g_cryptoProvider->getMaxHashSize()];
    if (!md_value) {
        delete mp_h;
    }
};

TXFMHash::~TXFMHash() {

    // Clean up
    if (mp_h)
        delete mp_h;

    if (md_value)
        delete[] md_value;
};

    // Methods to set the inputs

//void TXFMHash::setInput(TXFMBase *input);

    // Methods to get tranform output type and input requirement

TXFMBase::ioType TXFMHash::getInputType() const {
    return TXFMBase::BYTE_STREAM;
}

TXFMBase::ioType TXFMHash::getOutputType() const {
    return TXFMBase::BYTE_STREAM;
}

TXFMBase::nodeType TXFMHash::getNodeType() const {
    return TXFMBase::DOM_NODE_NONE;
}

    // Methods to set input data

void TXFMHash::setInput(TXFMBase* inputT) {

    input = inputT;

    keepComments = input->getCommentsStatus();

    // Now run through the data
    unsigned char buffer[1024];
    unsigned int size;

    while ((size = input->readBytes((XMLByte *) buffer, 1024)) != 0) {
        mp_h->hash(buffer, size);
    }

    // Finalise

    md_len = mp_h->finish(md_value, XSECPlatformUtils::g_cryptoProvider->getMaxHashSize());

    toOutput = md_len;
}


unsigned int TXFMHash::readBytes(XMLByte * const toFill, unsigned int maxToFill) {

    unsigned int ret;

    if (toOutput == 0)
        return 0;

    // Check if we can just output everything left
    if (toOutput <= maxToFill) {

        memcpy((char *) toFill, &md_value[md_len - toOutput], toOutput);
        ret = toOutput;
        toOutput = 0;

        return ret;

    }

    // Output just some

    memcpy((char *) toFill, &md_value[md_len - toOutput], maxToFill);
    ret = maxToFill;
    toOutput -= maxToFill;

    return ret;
}
