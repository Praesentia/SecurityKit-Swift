/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2017 Jon Griffeth
 
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
public struct X509BasicConstraints: DERCodable {
    
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
    
    /**
     Initialize instance from extension.
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        if sequence.peekTag(with: DERCoder.TagBoolean) {
            ca = try sequence.decodeBoolean()
        }
        else {
            ca = false
        }
        
        if sequence.peekTag(with: DERCoder.TagInteger) {
            pathLenConstraint = try sequence.decodeUnsignedIntegerAsValue()
        }
        
        try decoder.assertAtEnd()
    }
    
    /**
     Initialize instance from extension.
     */
    public init(from extn: X509Extension) throws
    {
        let decoder = DERDecoder(bytes: extn.extnValue)
        try self.init(decoder: decoder)
        try decoder.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encodeBoolean(ca)
        if let pathLenConstraint = self.pathLenConstraint {
            sequence.encodeUnsignedInteger(pathLenConstraint)
        }
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
}


// End of File
