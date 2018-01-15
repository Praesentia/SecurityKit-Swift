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
public struct ASN1UnsignedInteger: ASN1Codable {

    // MARK: - Properties
    public let data: Data

    // MARK: - Initializers

    public init(data: Data)
    {
        self.data = data
    }

    public init(bytes: [UInt8])
    {
        self.data = Data(bytes)
    }

    // MARK: - ASN1Codable

    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let rawBytes  = try container.decode([UInt8].self, forTag: .integer)

        if rawBytes[0] == 0x00 && rawBytes.count > 1 {
            data = Data(Array(rawBytes[1..<rawBytes.count]))
        }
        else {
            data = Data(rawBytes)
        }
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        let bytes     = [UInt8](data)

        if (bytes[0] & 0x80) == 0x80 {
            try container.encode([0] + bytes, forTag: .integer)
        }
        else {
            try container.encode(bytes, forTag: .integer)
        }
    }

}


// End of File




