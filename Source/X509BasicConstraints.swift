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
 X509 Basic Constraints
 
 - Requirement: RFC-5280
 */
public struct X509BasicConstraints: ASN1Codable {
    
    // MARK: - Properties
    public var ca                : Bool
    public var pathLenConstraint : UInt? = nil
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    public init()
    {
        ca = false
    }
    
    /**
     Initialize instance.
     */
    public init(ca: Bool)
    {
        self.ca = ca
    }
    
    // MARK: - ASN1Codable

    /**
     Initialize instance from decoder.
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence = try decoder.sequence()

        ca                = try sequence.decodeIfPresent(Bool.self) ?? false
        pathLenConstraint = try sequence.decodeIfPresent(UInt.self)
        try sequence.assertAtEnd()
    }

    /**
     Encode

     - Parameters:
         - encoder: ASN1Encoder to which the instance will be encoded.tagObjectIdentifier
     */
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()

        if ca != false {
            try sequence.encode(ca)
        }
        try sequence.encode(pathLenConstraint)
    }
    
}


// End of File
