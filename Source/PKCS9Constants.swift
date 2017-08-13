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


// RFC 2985
public let pkcs9                 = OID(components: [ 1, 2, 840, 113549, 1, 9 ])
public let pkcs9EmailAddress     = OID(prefix: pkcs9, components: [  1 ])
public let pkcs9UnstructuredName = OID(prefix: pkcs9, components: [  2 ])
public let pkcs9ContentType      = OID(prefix: pkcs9, components: [  3 ])
public let pkcs9MessageDigest    = OID(prefix: pkcs9, components: [  4 ])
public let pkcs9SigningTime      = OID(prefix: pkcs9, components: [  5 ])
public let pkcs9ExtensionRequest = OID(prefix: pkcs9, components: [ 14 ])

// End of File
