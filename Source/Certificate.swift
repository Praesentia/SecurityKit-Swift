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
 Public key certificate.
 */
public protocol Certificate: class {
    
    // MARK: - Properties
    
    /**
     Certificate data.
     
     The encoded form of the certificate.   For X509 certficates, this will DER
     encoded data.
     */
    var data: Data { get }
    
    /**
     Identity
     
     The identity associated with the certificate.
     */
    var identity: Identity? { get }
    
    /**
     Public key.
     
     The public key associate with the certificate.
     */
    var publicKey : PublicKey   { get }
    var privateKey: PrivateKey? { get }
    
    /**
     Validity period.
     
     Specifies a closed time period for which the certificate is valid.
     */
    var validity: ClosedRange<Date> { get }
    
    /**
     X509 structure.
     
     For X509 certificates, this property will reference an X509Certificate
     structure.   The property will be nil for other types of certificates.
     */
    var x509: X509Certificate?  { get }
    
    /**
     Is a twin of certificate?
     
     Two certificates are twins if they shared the same identity (X509 subject
     name) and the same public key.
     
     - Parameters:
         - certificate:
     */
    func twin(of certificate: Certificate) -> Bool
    func createCertificationRequest(completionHandler completion: @escaping (PCKS10CertificationRequest?, Error?) -> Void)
    func selfSigned() -> Bool
    func certifiedBy(_ authority: Certificate) -> Bool
    
}

public extension Certificate {
    
    /**
     Are credentials valid for date.
     
     - Parameters:
     - date: The time to be checked.
     */
    public func valid(for date: Date) -> Bool
    {
        return validity.contains(date)
    }
    
    /**
     Are credentials valid for period.
     
     - Parameters:
         - period: The time period to be checked.
     */
    public func valid(for period: ClosedRange<Date>) -> Bool
    {
        return validity.contains(period.lowerBound) && validity.contains(period.upperBound)
    }
    
}


// End of File
