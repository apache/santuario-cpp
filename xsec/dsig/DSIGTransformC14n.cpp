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
 * DSIGTransformC14n := Class that performs C14n canonicalisation
 *
 * $Id$
 *
 */

#include <xsec/dsig/DSIGTransformC14n.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/transformers/TXFMC14n.hpp>
#include <xsec/transformers/TXFMChain.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/framework/XSECEnv.hpp>
#include <xsec/dsig/DSIGSignature.hpp>

#include "../utils/XSECAlgorithmSupport.hpp"

#include <xercesc/util/Janitor.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Constructors and Destructors
// --------------------------------------------------------------------------------

DSIGTransformC14n::DSIGTransformC14n(const XSECEnv* env, DOMNode* node) :
DSIGTransform(env, node) {

    m_cMethod = NULL;
    mp_inclNSNode = NULL;
    mp_inclNSStr = NULL;
    m_exclusive = false;
    m_comments = false;
    m_onedotone = false;
}


DSIGTransformC14n::DSIGTransformC14n(const XSECEnv* env) :
DSIGTransform(env) {

    m_cMethod = NULL;
    mp_inclNSNode = NULL;
    mp_inclNSStr = NULL;
    m_exclusive = false;
    m_comments = false;
    m_onedotone = false;
}

DSIGTransformC14n::~DSIGTransformC14n() {};

// --------------------------------------------------------------------------------
//           Interface Methods
// --------------------------------------------------------------------------------

void DSIGTransformC14n::appendTransformer(TXFMChain* input) {

    TXFMC14n* c;

    XSECnew(c, TXFMC14n(mp_txfmNode->getOwnerDocument()));
    input->appendTxfm(c);

    if (m_comments)
        c->activateComments();
    else
        c->stripComments();

    // Check for exclusive and 1.1
    if (m_exclusive) {
        if (mp_inclNSStr == NULL) {
            c->setExclusive();
        }
        else {
            safeBuffer incl;
            incl << (*(mp_env->getSBFormatter()) << mp_inclNSStr);
            c->setExclusive(incl);
        }
    }
    else if (m_onedotone) {
        c->setInclusive11();
    }
}

DOMElement* DSIGTransformC14n::createBlankTransform(DOMDocument* parentDoc) {

    safeBuffer str;
    const XMLCh * prefix;
    DOMElement *ret;
    DOMDocument *doc = mp_env->getParentDocument();

    prefix = mp_env->getDSIGNSPrefix();

    // Create the transform node
    makeQName(str, prefix, "Transform");
    ret = doc->createElementNS(DSIGConstants::s_unicodeStrURIDSIG, str.rawXMLChBuffer());
    ret->setAttributeNS(NULL,DSIGConstants::s_unicodeStrAlgorithm, DSIGConstants::s_unicodeStrURIC14N_NOC);

    m_cMethod = ret->getAttributeNS(NULL, DSIGConstants::s_unicodeStrAlgorithm);
    m_comments = false;
    m_exclusive = false;
    m_onedotone = false;

    mp_txfmNode = ret;
    mp_inclNSStr = NULL;
    mp_inclNSNode = NULL;

    return ret;
}

void DSIGTransformC14n::load() {

    const XMLCh* uri;
    DOMNamedNodeMap* atts;
    DOMNode* att;

    // Read the URI for the type
    if (mp_txfmNode == NULL) {
        throw XSECException(XSECException::ExpectedDSIGChildNotFound,
            "Expected <Transform> Node in DSIGTrasnformC14n::load");
    }

    atts = mp_txfmNode->getAttributes();

    if (atts == NULL ||
        ((att = atts->getNamedItem(DSIGConstants::s_unicodeStrAlgorithm)) == NULL)) {

        throw XSECException(XSECException::ExpectedDSIGChildNotFound,
            "Expected to find Algorithm attribute in <Transform> node");
    }

    m_cMethod = att->getNodeValue();

    if (!XSECAlgorithmSupport::evalCanonicalizationMethod(m_cMethod, m_exclusive, m_comments, m_onedotone)) {
        throw XSECException(XSECException::TransformError,
            "Unexpected URI found in canonicalization <Transform>");
    }

    // Determine whether there is an InclusiveNamespaces list

    if (m_exclusive) {

        // Exclusive, so there may be an InclusiveNamespaces node

        DOMNode* inclNSNode = mp_txfmNode->getFirstChild();

        while (inclNSNode != NULL && (inclNSNode->getNodeType() != DOMNode::ELEMENT_NODE ||
            !strEquals(getECLocalName(inclNSNode), "InclusiveNamespaces")))
                inclNSNode = inclNSNode->getNextSibling();

        if (inclNSNode != 0) {

            mp_inclNSNode = static_cast<DOMElement *>(inclNSNode);

            // Have a prefix list
            atts = mp_inclNSNode->getAttributes();
            safeBuffer inSB;

            if (atts == 0 || ((att = atts->getNamedItem(MAKE_UNICODE_STRING("PrefixList"))) == NULL)) {
                throw XSECException(XSECException::ExpectedDSIGChildNotFound,
                    "Expected PrefixList in InclusiveNamespaces");
            }

            mp_inclNSStr = att->getNodeValue();
        }
    }
}

// --------------------------------------------------------------------------------
//           Canonicalization Specific Methods
// --------------------------------------------------------------------------------


void DSIGTransformC14n::setCanonicalizationMethod(const XMLCh* uri) {

    bool exclusive;
    bool comments;
    bool onedotone;

    if (mp_txfmNode == NULL || !XSECAlgorithmSupport::evalCanonicalizationMethod(uri, exclusive, comments, onedotone)) {
        throw XSECException(XSECException::TransformError,
            "Either method unknown or Node not set in setCanonicalizationMethod");
    }

    // Switching from exclusive to inclusive?
    if (!exclusive && m_exclusive) {
        if (mp_inclNSNode != 0) {

            mp_txfmNode->removeChild(mp_inclNSNode);
            mp_inclNSNode->release();        // No longer required

            mp_inclNSNode = NULL;
            mp_inclNSStr = NULL;
        }
    }

    // Now do the set.
    ((DOMElement *) mp_txfmNode)->setAttributeNS(NULL, DSIGConstants::s_unicodeStrAlgorithm, uri);
    m_cMethod = ((DOMElement *) mp_txfmNode)->getAttributeNS(NULL, DSIGConstants::s_unicodeStrAlgorithm);

    m_exclusive = exclusive;
    m_comments = comments;
    m_onedotone = onedotone;
}

const XMLCh* DSIGTransformC14n::getCanonicalizationMethod() const {
    return m_cMethod;
}

void DSIGTransformC14n::createInclusiveNamespaceNode() {

    // Creates an empty inclusiveNamespace node.  Does _not_ set the prefixlist attribute

    if (mp_inclNSNode != NULL)
        return;        // Already exists

    safeBuffer str;
    const XMLCh * prefix;
    DOMDocument *doc = mp_env->getParentDocument();

    // Use the Exclusive Canonicalisation prefix
    prefix = mp_env->getECNSPrefix();

    // Create the transform node
    makeQName(str, prefix, "InclusiveNamespaces");
    mp_inclNSNode = doc->createElementNS(DSIGConstants::s_unicodeStrURIEC, str.rawXMLChBuffer());

    // Add the node to the owner element
    mp_env->doPrettyPrint(mp_txfmNode);
    mp_txfmNode->appendChild(mp_inclNSNode);
    mp_env->doPrettyPrint(mp_txfmNode);

    // Set the namespace attribute
    if (prefix[0] == '\0') {
        str.sbTranscodeIn("xmlns");
    }
    else {
        str.sbTranscodeIn("xmlns:");
        str.sbXMLChCat(prefix);
    }

    mp_inclNSNode->setAttributeNS(DSIGConstants::s_unicodeStrURIXMLNS,
                            str.rawXMLChBuffer(),
                            DSIGConstants::s_unicodeStrURIEC);
}

void DSIGTransformC14n::setInclusiveNamespaces(const XMLCh* ns) {

    // Set all the namespaces at once

    if (!m_exclusive) {
        throw XSECException(XSECException::TransformError,
            "Cannot set inclusive namespaces on non Exclusive Canonicalization");
    }

    if (mp_inclNSNode == NULL) {
        // Create the transform node
        createInclusiveNamespaceNode();
    }

    // Now create the prefix list

    mp_inclNSNode->setAttributeNS(NULL,MAKE_UNICODE_STRING("PrefixList"), ns);
    mp_inclNSStr = mp_inclNSNode->getAttributes()->getNamedItem(MAKE_UNICODE_STRING("PrefixList"))->getNodeValue();
}


void DSIGTransformC14n::addInclusiveNamespace(const char* ns) {

    if (!m_exclusive) {
        throw XSECException(XSECException::TransformError,
            "Cannot set inclusive namespaces on non Exclusive Canonicalization");
    }

    if (mp_inclNSNode == NULL) {
        // Create the transform node
        createInclusiveNamespaceNode();

        // Now create the prefix list

        mp_inclNSNode->setAttributeNS(NULL,MAKE_UNICODE_STRING("PrefixList"), MAKE_UNICODE_STRING(ns));
        mp_inclNSStr = mp_inclNSNode->getAttributes()->getNamedItem(MAKE_UNICODE_STRING("PrefixList"))->getNodeValue();
    }
    else {
        // More tricky
        safeBuffer str;

        str << (*(mp_env->getSBFormatter()) << mp_inclNSStr);
        str.sbStrcatIn(" ");
        str.sbStrcatIn((char *) ns);
        mp_inclNSNode->setAttributeNS(NULL,MAKE_UNICODE_STRING("PrefixList"), str.sbStrToXMLCh());
        mp_inclNSStr = mp_inclNSNode->getAttributes()->getNamedItem(MAKE_UNICODE_STRING("PrefixList"))->getNodeValue();
    }
}

const XMLCh* DSIGTransformC14n::getPrefixList() const {
    return mp_inclNSStr;
}

void DSIGTransformC14n::clearInclusiveNamespaces() {

    if (mp_inclNSNode != 0) {
        mp_txfmNode->removeChild(mp_inclNSNode);
        mp_inclNSNode->release();        // No longer required

        mp_inclNSNode = NULL;
        mp_inclNSStr = NULL;
    }
}
