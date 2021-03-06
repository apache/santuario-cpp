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
 * TXFMXPath := Class that performs XPath transforms
 *
 * $Id$
 *
 */

#if !defined (TXFMXPATHFILTER_HEADER)
#define TXFMXPATHFILTER_HEADER

#include <xsec/transformers/TXFMBase.hpp>
#include <xsec/utils/XSECXPathNodeList.hpp>
#include <xsec/dsig/DSIGTransformXPathFilter.hpp>
#include <xsec/dsig/DSIGConstants.hpp>

// Xerces

XSEC_DECLARE_XERCES_CLASS(DOMNode);
XSEC_DECLARE_XERCES_CLASS(DOMNamedNodeMap);

class TXFMXPathFilterExpr;
class XSECSafeBufferFormatter;

struct filterSetHolder {
    XSECXPathNodeList* lst;
    DSIGXPathFilterExpr::XPathFilterType type;
    XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* ancestorInScope;
};


#ifdef XSEC_HAVE_XPATH

/**
 * \brief Transformer to handle XPath transforms
 * @ingroup internal
 */


class XSEC_EXPORT TXFMXPathFilter : public TXFMBase {

public:

    TXFMXPathFilter(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument* doc);
    virtual ~TXFMXPathFilter();

    // Methods to set the inputs

    void setInput(TXFMBase* newInput);

    // Methods to get tranform output type and input requirement

    virtual TXFMBase::ioType getInputType() const;
    virtual TXFMBase::ioType getOutputType() const;
    virtual TXFMBase::nodeType getNodeType() const;

    // XPathFilter unique

    void evaluateExprs(DSIGTransformXPathFilter::exprVectorType* exprs);
    XSECXPathNodeList* evaluateSingleExpr(DSIGXPathFilterExpr* expr);

    // Methods to get output data

    virtual unsigned int readBytes(XMLByte* const toFill, const unsigned int maxToFill);
    virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument* getDocument() const;
    virtual XSECXPathNodeList& getXPathNodeList();

private:
    typedef std::vector<filterSetHolder*> lstsVectorType;
    TXFMXPathFilter();
    void walkDocument(XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* n);
    bool checkNodeInScope(XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* n);
    bool checkNodeInInput(XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* n,
        XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* attParent);


    XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument* document;
    XSECXPathNodeList m_xpathFilterMap;
    lstsVectorType m_lsts;

    XSECSafeBufferFormatter* mp_formatter;

    /* Used to hold details during tree-walk */
    XERCES_CPP_NAMESPACE_QUALIFIER DOMNode* mp_fragment;
    XSECXPathNodeList* mp_inputList;
};

#endif

#endif /* XPATHFILTER_HEADER */
