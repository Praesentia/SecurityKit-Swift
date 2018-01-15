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
 X509 Extended Key Usage
 
 - Requirement: RFC-5280
 */
public struct X509ExtendedKeyUsage: ASN1Codable {
    
    // MARK: - Properties
    public var purposeIdentifiers = [ASN1OID]()

    // MARK: - ASN1Codable

    /**
     Initialize instance from extension.
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence       = try decoder.sequence()
        purposeIdentifiers = try sequence.decode([ASN1OID].self)
    }
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()
        try sequence.encode(purposeIdentifiers)
    }
    
}


// End of File
