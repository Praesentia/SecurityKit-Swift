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
public struct X509String: Equatable {
    
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
    
    // MARK: - Equatable
    
    public static func ==(lhs: X509String, rhs: X509String) -> Bool
    {
        return lhs.string == rhs.string
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
