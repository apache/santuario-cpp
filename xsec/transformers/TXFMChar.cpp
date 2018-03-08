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
 * TXFMChar := Class that takes an input static buffer to start a transform pipe
 *
 */

#include <xsec/transformers/TXFMChar.hpp>

XERCES_CPP_NAMESPACE_USE

// General includes 

#include <memory.h>

TXFMChar::TXFMChar(DOMDocument *doc) : TXFMBase(doc) {

	toOutput = 0;
}


TXFMChar::~TXFMChar() {

}

// Methods to set the inputs

void TXFMChar::setInput(TXFMBase *newInput) {

	// We're the start of the actual data pipe, but we need to track
    // the pointer for chain disposal.
    input = newInput;

	return;
}

void TXFMChar::setInput(const char* in) {

	// Assume this is a string

	buf = in;
	toOutput = in ? strlen(in) : 0;
	sbs = toOutput;

}

void TXFMChar::setInput(const char* in, unsigned int bSize) {

	// Assume this is a raw buffer

	buf = in;
	toOutput = bSize;
	sbs = toOutput;

}


// Methods to get tranform output type and input requirement

TXFMBase::ioType TXFMChar::getInputType() const {
	return TXFMBase::BYTE_STREAM;
}

TXFMBase::ioType TXFMChar::getOutputType() const {
	return TXFMBase::BYTE_STREAM;
}


TXFMBase::nodeType TXFMChar::getNodeType() const {
	return TXFMBase::DOM_NODE_NONE;
}

// Methods to get output data

unsigned int TXFMChar::readBytes(XMLByte* const toFill, unsigned int maxToFill) {
	
	// Return from the buffer
	
	unsigned int ret;

	if (toOutput == 0)
		return 0;

	// Check if we can just output everything left
	if (toOutput <= maxToFill) {

		memcpy((char *) toFill, &(buf[sbs - toOutput]), toOutput);
		ret = (unsigned int) toOutput;
		toOutput = 0;
		return ret;
	}

	// Output just some

	memcpy((char *) toFill, &(buf[sbs - toOutput]), maxToFill);
	ret = maxToFill;
	toOutput -= maxToFill;

	return ret;
}
