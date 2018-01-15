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


import Foundation


/**
 X509 Validity
 
 - Requirement: RFC-5280
 */
public struct X509Validity: ASN1Codable {
    
    // MARK: - Properties
    public var period: ClosedRange<Date>
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    public init(period: ClosedRange<Date>)
    {
        self.period = period
    }
    
    /**
     Initialize instance.
     */
    public init(from date: Date, until timeInterval: TimeInterval)
    {
        self.init(period: date...date.addingTimeInterval(timeInterval))
    }

    // MARK: - ASN1Codable
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let sequence  = try container.sequence()
        
        let fromDate  = try sequence.decode(ASN1Time.self).time
        let untilDate = try sequence.decode(ASN1Time.self).time
        
        try sequence.assert(fromDate <= untilDate)
        try sequence.assertAtEnd()
        
        period = fromDate ... untilDate
    }
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        let sequence  = try container.sequence()
        
        try sequence.encode(ASN1Time(time: period.lowerBound))
        try sequence.encode(ASN1Time(time: period.upperBound))
    }
    
    // MARK: - Containment
    
    public func contains(date: Date) -> Bool
    {
        return period.contains(date)
    }
    
    public func contains(period: ClosedRange<Date>) -> Bool
    {
        return self.period.contains(period.lowerBound) && self.period.contains(period.upperBound)
    }
    
}


// End of File
