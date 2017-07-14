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
 X509 Key Usage
 
 - Requirement: RFC 5280
 */
public struct X509KeyUsage {
    
    // MARK: - Properties
    public var digitalSignature : Bool
    public var nonRepudiation   : Bool
    public var keyEncipherment  : Bool
    public var dataEncipherment : Bool
    public var keyAgreement     : Bool
    public var keyCertSign      : Bool
    public var cRLSign          : Bool
    public var encipherOnly     : Bool
    public var decipherOnly     : Bool
    
    // MARK: - Initializers
    
    public init()
    {
        digitalSignature = false
        nonRepudiation   = false
        keyEncipherment  = false
        dataEncipherment = false
        keyAgreement     = false
        keyCertSign      = false
        cRLSign          = false
        encipherOnly     = false
        decipherOnly     = false
    }
    
}


// End of File
