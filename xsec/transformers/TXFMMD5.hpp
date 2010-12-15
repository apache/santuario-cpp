/*
 * Copyright 2002-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * XSEC
 *
 * TXFMMD5 := Class that performs a MD5 transform
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#ifndef TXFMMD5_INCLUDE
#define TXFMMD5_INCLUDE

// XSEC Includes

#include <xsec/transformers/TXFMBase.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>

/**
 * \brief Transformer to handle create a MD5-1 hash from a chain
 * @ingroup internal
 */

class DSIG_EXPORT TXFMMD5 : public TXFMBase {

private:

	XSECCryptoHash		* mp_h;							// To hold the hash
	unsigned char		md_value[CRYPTO_MAX_HASH_SIZE];	// Final output
	unsigned int		md_len;							// Length of digest

	unsigned int		toOutput;						// Amount still to output

public:

	TXFMMD5(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc, XSECCryptoKey * key = NULL);
	~TXFMMD5();

	// Methods to get tranform output type and input requirement

	virtual TXFMBase::ioType getInputType(void);
	virtual TXFMBase::ioType getOutputType(void);
	virtual nodeType getNodeType(void);

	// Methods to set input data

	virtual void setInput(TXFMBase * inputT);

	// Methods to get output data

	virtual unsigned int readBytes(XMLByte * const toFill, const unsigned int maxToFill);
	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *getDocument();
	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMNode *getFragmentNode();
	virtual const XMLCh * getFragmentId();
	
private:
	TXFMMD5();
};



#endif /* TXFMMD5 */
