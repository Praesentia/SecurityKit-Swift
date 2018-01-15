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


import XCTest
@testable import SecurityKit


class X509CertificateTests: XCTestCase {
    
    let certificates = [ testCERURL, testCACERURL ]
    func testDecoderEncoder()
    {
        for url in certificates {
            do {
                let expected    = try Data(contentsOf: url)
                let certificate = try DERDecoder().decode(X509Certificate.self, from: expected)
                let data        = try DEREncoder().encode(certificate)

                XCTAssertEqual(data, expected)
            }
            catch let error {
                XCTFail("\(url.pathComponents.last!): \(error)")
            }
        }
    }
    
}


// End of File

