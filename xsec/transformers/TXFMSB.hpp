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
 * TXFMSB := Class that takes an input from a safeBuffer to start a pipe
 *
 * $Id$
 *
 */

#ifndef TXFMSB_INCLUDE
#define TXFMSB_INCLUDE

#include <xsec/transformers/TXFMBase.hpp>
#include <xsec/utils/XSECSafeBuffer.hpp>

/**
 * \brief Base transformer to start a chain from a safeBuffer
 * @ingroup internal
 */

class XSEC_EXPORT TXFMSB : public TXFMBase {

private:

	safeBuffer	sb;			// SafeBuffer to use
	XMLSize_t toOutput;	// Amount left to output
	XMLSize_t sbs;		    // Size of raw buffer

public:

	TXFMSB(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc);
	virtual ~TXFMSB();

	// Methods to set the inputs

	virtual void setInput(TXFMBase *newInput);
	void setInput(const safeBuffer& sbIn);
	void setInput(const safeBuffer& sbIn, unsigned int sbSize); 

	// Methods to get tranform output type and input requirement

	virtual TXFMBase::ioType getInputType(void) const;
	virtual TXFMBase::ioType getOutputType(void) const;
	virtual nodeType getNodeType(void) const;

	// Methods to get output data

	virtual unsigned int readBytes(XMLByte * const toFill, const unsigned int maxToFill);
	
private:
	TXFMSB();
};

#endif

