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
 * TXFMXSL := Class that performs XML Stylesheet Language transforms
 *
 * $Id$
 *
 */

#include <xsec/transformers/TXFMBase.hpp>

// Xerces

#include <xercesc/dom/DOM.hpp>

// Xalan

#ifdef XSEC_HAVE_XPATH

#include <xalanc/XalanDOM/XalanDocument.hpp>
#include <xalanc/XercesParserLiaison/XercesDOMSupport.hpp>
#include <xalanc/XercesParserLiaison/XercesParserLiaison.hpp>
#include <xalanc/XPath/NodeRefList.hpp>
#include <xalanc/XPath/ElementPrefixResolverProxy.hpp>
#include <xalanc/XalanTransformer/XalanTransformer.hpp>

// If this isn't defined, we're on Xalan 1.12+ and require modern C++
#ifndef XALAN_USING_XALAN
# define XALAN_USING_XALAN(NAME) using xalanc :: NAME;
#endif

// Xalan Namespace usage
XALAN_USING_XALAN(XercesDOMSupport)
XALAN_USING_XALAN(XercesParserLiaison)
XALAN_USING_XALAN(XalanDocument)
XALAN_USING_XALAN(XalanTransformer)

#endif

#ifdef XSEC_HAVE_XSLT

/**
 * \brief Transformer to handle XSLT transforms
 * @ingroup internal
 */

class XSEC_EXPORT TXFMXSL : public TXFMBase {

private:

	safeBuffer expr;							// The expression being worked with

	XercesDOMSupport	xds;
	XercesParserLiaison xpl;

	XalanDocument		* xd;

	safeBuffer			sbInDoc;

	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument		
						* document;
	
	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument		
						* docOut;			// The output from the transformation

public:

	TXFMXSL(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc);
	virtual ~TXFMXSL();

	// Methods to set the inputs

	void setInput(TXFMBase *newInput);
	
	// Methods to get tranform output type and input requirement

	virtual TXFMBase::ioType getInputType(void) const;
	virtual TXFMBase::ioType getOutputType(void) const;
	virtual nodeType getNodeType(void) const;

	// We do our own name spaces - we have a new document!
	
	virtual bool nameSpacesExpanded(void) const;
	virtual void expandNameSpaces(void);


	// XSL Unique

	void evaluateStyleSheet(const safeBuffer &sbStyleSheet);

	// Methods to get output data

	virtual unsigned int readBytes(XMLByte * const toFill, const unsigned int maxToFill);
	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *getDocument() const;
	
private:
	TXFMXSL();

};


#endif /* No XSLT */
