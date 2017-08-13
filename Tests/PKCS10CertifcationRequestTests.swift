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


class PCKS10CertificationRequestTests: XCTestCase {
    
    let certificationRequests = [ testCSRURL ]
    
    func testInitializers()
    {
        for url in certificationRequests {
            do {
                let data                 = try Data(contentsOf: url)
                let certificationRequest = PCKS10CertificationRequest(from: data)
                
                XCTAssertNotNil(certificationRequest)
            }
            catch let error {
                XCTFail("\(url.pathComponents.last!): \(error)")
            }
        }
    }
    
    func testDecoder()
    {
        for url in certificationRequests {
            let data    = try! Data(contentsOf: url)
            let decoder = DERDecoder(data: data)
            
            let _ = try! PCKS10CertificationRequest(decoder: decoder)
        }
    }
    
    func testEncoder()
    {
        for url in certificationRequests {
            do {
                let data                 = try Data(contentsOf: url)
                let certificationRequest = PCKS10CertificationRequest(from: data)!
                let encoder              = DEREncoder()
                
                encoder.encode(certificationRequest)
                XCTAssertEqual(encoder.data, data)
            }
            catch let error {
                XCTFail("\(url.pathComponents.last!): \(error)")
            }
        }
    }
    
}


// End of File


