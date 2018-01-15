/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.

 Copyright 2017-2018 Jon Griffeth

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -----------------------------------------------------------------------------
 */


import Foundation


/**
 RSA Public Key
 */
public class PKCS1RSAPublicKey: ASN1Codable {

    // MARK: - Properties
    public let modulus  : ASN1UnsignedInteger
    public let exponent : ASN1UnsignedInteger
    public var size     : UInt { return UInt(modulus.data.count * 8) }

    // MARK: - Initializers

    public init(modulus: ASN1UnsignedInteger, exponent: ASN1UnsignedInteger)
    {
        self.modulus  = modulus
        self.exponent = exponent
    }

    // MARK: - ASN1Codable

    required public init(from decoder: ASN1Decoder) throws
    {
        let sequence = try decoder.sequence()

        modulus  = try sequence.decode(ASN1UnsignedInteger.self)
        exponent = try sequence.decode(ASN1UnsignedInteger.self)
        try sequence.assertAtEnd()
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()
        try sequence.encode(modulus)
        try sequence.encode(exponent)
    }

}


// End of File
