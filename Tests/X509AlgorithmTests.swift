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


import XCTest
@testable import SecurityKit


class X509AlgorithmTests: XCTestCase {
    
    func testClassConstants()
    {
        // oid property
        XCTAssert(X509Algorithm.md5WithRSAEncryption.oid    == pkcs1MD5WithRSAEncryption)
        XCTAssert(X509Algorithm.sha1WithRSAEncryption.oid   == pkcs1SHA1WithRSAEncryption)
        XCTAssert(X509Algorithm.sha256WithRSAEncryption.oid == pkcs1SHA256WithRSAEncryption)
        XCTAssert(X509Algorithm.sha384WithRSAEncryption.oid == pkcs1SHA384WithRSAEncryption)
        XCTAssert(X509Algorithm.sha512WithRSAEncryption.oid == pkcs1SHA512WithRSAEncryption)
        
        // parameters property
        XCTAssert(X509Algorithm.md5WithRSAEncryption.parameters    == nil)
        XCTAssert(X509Algorithm.sha1WithRSAEncryption.parameters   == nil)
        XCTAssert(X509Algorithm.sha256WithRSAEncryption.parameters == nil)
        XCTAssert(X509Algorithm.sha384WithRSAEncryption.parameters == nil)
        XCTAssert(X509Algorithm.sha512WithRSAEncryption.parameters == nil)
        
        // digest property
        XCTAssert(X509Algorithm.md5WithRSAEncryption.digest    == .md5)
        XCTAssert(X509Algorithm.sha1WithRSAEncryption.digest   == .sha1)
        XCTAssert(X509Algorithm.sha256WithRSAEncryption.digest == .sha256)
        XCTAssert(X509Algorithm.sha384WithRSAEncryption.digest == .sha384)
        XCTAssert(X509Algorithm.sha512WithRSAEncryption.digest == .sha512)
        
        // localized description property
        XCTAssert(X509Algorithm.md5WithRSAEncryption.localizedDescription    == "MD5 with RSA Encryption")
        XCTAssert(X509Algorithm.sha1WithRSAEncryption.localizedDescription   == "SHA-1 with RSA Encryption")
        XCTAssert(X509Algorithm.sha256WithRSAEncryption.localizedDescription == "SHA-256 with RSA Encryption")
        XCTAssert(X509Algorithm.sha384WithRSAEncryption.localizedDescription == "SHA-384 with RSA Encryption")
        XCTAssert(X509Algorithm.sha512WithRSAEncryption.localizedDescription == "SHA-512 with RSA Encryption")
    }
    
}


// End of File
