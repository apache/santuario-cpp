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
 * TXFMChar := Class that takes an input from a static buffer to start a pipe
 *
 */

#ifndef TXFMCHAR_INCLUDE
#define TXFMCHAR_INCLUDE

#include <xsec/transformers/TXFMBase.hpp>

/**
 * \brief Base transformer to start a chain from a static buffer
 * @ingroup internal
 */

class XSEC_EXPORT TXFMChar : public TXFMBase {

private:

	const char*	buf;	// Buffer to use
	XMLSize_t toOutput;	// Amount left to output
	XMLSize_t sbs;		// Size of raw buffer

public:

	TXFMChar(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc);
	virtual ~TXFMChar();

	// Methods to set the inputs

	virtual void setInput(TXFMBase *newInput);
	void setInput(const char* in);
	void setInput(const char* in, unsigned int bufSize);

	// Methods to get tranform output type and input requirement

	virtual TXFMBase::ioType getInputType() const;
	virtual TXFMBase::ioType getOutputType() const;
	virtual nodeType getNodeType() const;

	// Methods to get output data

	virtual unsigned int readBytes(XMLByte* const toFill, const unsigned int maxToFill);
	
private:
	TXFMChar();
};

#endif
