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
    var data      : Data              { get }
    var identity  : Identity?         { get }
    var publicKey : Key               { get }
    var validity  : ClosedRange<Date> { get }
    var x509      : X509Certificate?  { get }
    
}

public extension Certificate {
    
    /**
     Are credentials valid for date.
     
     - Parameters:
     - date: The time to be checked.
     */
    func valid(for date: Date) -> Bool
    {
        return validity.contains(date)
    }
    
    /**
     Are credentials valid for date.
     
     - Parameters:
     - date: The time to be checked.
     */
    func valid(for period: ClosedRange<Date>) -> Bool
    {
        return validity.contains(period.lowerBound) && validity.contains(period.upperBound)
    }
    
}


// End of File