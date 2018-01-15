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
 */
public struct ASN1BitString: ASN1Codable {

    // MARK: - Properties

    public let bytes  : [UInt8]
    public let unused : UInt8

    // MARK: - Initializers

    public init(bytes: [UInt8], unused: UInt8 = 0)
    {
        self.bytes  = bytes
        self.unused = unused
    }

    // MARK: - ASN1Codable

    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let bytes     = try container.decode([UInt8].self, forTag: .bitString)

        self.bytes  = [UInt8](bytes[1..<bytes.count])
        self.unused = bytes[0]
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        try container.encode([unused] + bytes, forTag: .bitString)
    }

}


// End of File


