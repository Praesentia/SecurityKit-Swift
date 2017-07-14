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


public let pkcs1                        = OID(components: [ 1, 2, 840, 113549, 1, 1 ])
public let pkcs1RSAEncryption           = OID(prefix: pkcs1, components: [  1 ])
public let pkcs1MD5WithRSAEncryption    = OID(prefix: pkcs1, components: [  4 ])
public let pkcs1SHA1WithRSAEncryption   = OID(prefix: pkcs1, components: [  5 ])
public let pkcs1SHA256WithRSAEncryption = OID(prefix: pkcs1, components: [ 11 ])
public let pkcs1SHA384WithRSAEncryption = OID(prefix: pkcs1, components: [ 12 ])
public let pkcs1SHA512WithRSAEncryption = OID(prefix: pkcs1, components: [ 13 ])


// End of File
