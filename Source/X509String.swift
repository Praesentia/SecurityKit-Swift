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
 X509 String
 
 - Requirement: RFC-5280
 */
public struct X509String: Equatable, DERCodable {
    
    // MARK: - Types
    public enum Encoding {
        case ia5
        case printable
        case utf8
    }
    
    // MARK: - Properties
    public var string   : String
    public var encoding : Encoding
    public var encoded  : [UInt8] { return X509String.transcode(string: string, encoding: encoding) }
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    public init(string: String, encoding: Encoding = .utf8)
    {
        self.string   = string
        self.encoding = encoding
    }
    
    /**
     Initialize instance.
     */
    public init(bytes: [UInt8], encoding: Encoding)
    {
        self.string   = X509String.transcode(bytes: bytes, encoding: encoding)
        self.encoding = encoding
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    public init(decoder: DERDecoder) throws
    {
        if let tag = decoder.peekTag() {
            switch tag {
            case DERCoder.TagIA5String :
                let bytes: [UInt8] = try decoder.decodeIA5String()
                self.init(bytes: bytes, encoding: .ia5)
                
            case DERCoder.TagPrintableString :
                let bytes: [UInt8] = try decoder.decodePrintableString()
                self.init(bytes: bytes, encoding: .printable)
                
            case DERCoder.TagUTF8String :
                let bytes: [UInt8] = try decoder.decodeUTF8String()
                self.init(bytes: bytes, encoding: .utf8)
                
            default :
                throw SecurityKitError.failed
            }
        }
        else {
            throw SecurityKitError.failed
        }
    }
    
    // MARK: - Equatable
    
    public static func ==(lhs: X509String, rhs: X509String) -> Bool
    {
        return lhs.string == rhs.string
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        switch encoding {
        case .ia5 :
            encoder.encodeIA5String(encoded)
            
        case .printable :
            encoder.encodePrintableString(encoded)
            
        case .utf8 :
            encoder.encodeUTF8String(encoded)
        }
    }
    
    // MARK: - Transcoders
    
    static func transcode(bytes: [UInt8], encoding: Encoding) -> String
    {
        switch encoding {
        case .ia5 :
            return String(bytes: bytes, encoding: .ascii)!
            
        case .printable :
            return String(bytes: bytes, encoding: .ascii)!
            
        case .utf8 :
            return String(bytes: bytes, encoding: .utf8)!
        }
    }
    
    static func transcode(string: String, encoding: Encoding) -> [UInt8]
    {
        switch encoding {
        case .ia5 :
            return string.unicodeScalars.map { UInt8($0.value) }
            
        case .printable :
            return string.unicodeScalars.map { UInt8($0.value) }
            
        case .utf8 :
            return [UInt8](string.utf8)
        }
    }
    
}



// End of File
