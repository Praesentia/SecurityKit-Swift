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
 Encoder for ASN.1 Distinguished Encoding Rules (DER).
 */
class DERTaggedEncodingContainer: DEREncodingContainer {

    // MARK: - Private Properties
    private let tag: ASN1CodingTag

    // MARK: - Initializers

    init(forTag tag: ASN1CodingTag)
    {
        self.tag = tag
    }

    // MARK: - DEREncodingFragment

    override func freeze() -> [UInt8]
    {
        var bytes: [UInt8]

        finalizeContainer()

        bytes  = [tag.value]
        bytes += encodeLength(self.bytes.count)
        bytes += self.bytes

        frozen = true
        return bytes
    }

}


// End of File


