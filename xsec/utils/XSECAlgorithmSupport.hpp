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
 * XSECAlgorithmSupport := internal helpers for mapping from W3C/IETF algorithm URIs
 *
 * Author(s): Scott Cantor
 */


#ifndef XSECALGSUP_INCLUDE
#define XSECALGSUP_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECCryptoHash.hpp>

/**
 * \addtogroup internal
 * @{
 */

 /**
  * Helper class for dealing with algorithm extensibility externally to library.
  */
class XSECAlgorithmSupport
{
    XSECAlgorithmSupport();
    XSECAlgorithmSupport(const XSECAlgorithmSupport&);
    XSECAlgorithmSupport& operator=(const XSECAlgorithmSupport&);
public:

    /**
     * \brief Map digest algorithm URI to the corresponding hash type.
     *
     * @param uri algorithm identifier
     * @returns hash type
     */
    static XSECCryptoHash::HashType getHashType(const XMLCh* uri);

    /**
     * \brief Map MGF algorithm URI to the corresponding hash type.
     *
     * Currently the only supported function is the MGF1 algorithm, together with
     * a variable hash type, so this function currently just validates the first
     * assumption and returns the type of hash to use. If a future extension adds
     * additional mask functions, this can be changed internally to the library.
     *
     * @param uri algorithm identifier
     * @returns hash type to use with MGF1
     */
    static XSECCryptoHash::HashType getMGF1HashType(const XMLCh* uri);

    /**
     * \brief Map signature algorithm URI to the corresponding hash type while
     * verifying the compatibility of an associated key.
     *
     * @param uri algorithm identifier
     * @param key signing key
     * @param hashType hash type to use
     */
    static bool evalSignatureMethod(
            const XMLCh* uri, const XSECCryptoKey* key, XSECCryptoHash::HashType& hashType
            );

    /**
     * \brief Process a c14n method URI to determine the relevant properties to use.
     *
     * Currently the only supported methods are the original 1.0 and 1.1 inclusive and 1.0
     * exclusive algorithms. Any extension would require significant redesign.
     *
     * @param uri algorithm identifier
     * @param exclusive true on output iff the algorithm was 1.0 Exclusive
     * @param comments true on output iff the algorithm was a "with-comments" variant
     * @param onedotone true on output iff the algorithm was 1.1 Inclusive
     * @returns true iff the algorithm was known
     */
    static bool evalCanonicalizationMethod(
            const XMLCh* uri, bool& exclusive, bool& comments, bool& onedotone
            );
};


/** @} */

#endif /* XSECALGSUP_INCLUDE */
