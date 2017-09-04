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
 SecurityKit Error
 
 Enumeration of SecurityKit error codes.
 */
public enum SecurityKitError: Int, Error, CustomStringConvertible, LocalizedError {
    case badCredentials =  1
    case badSignature   =  2
    case decodingError  =  3
    case failed         =  4 // General failure.
    case invalidData    =  5
    case notInitialized =  6
    case notFound       =  7
    case notPermitted   =  8
    case notSupported   =  9
    
    public var description      : String  { return "SecurityKitError Code=\( rawValue ) \"(\( localizedDescription ))\"" }
    public var errorDescription : String? { return SecurityKitError.localizedDescriptions[self] }
}

extension SecurityKitError {
    
    /**
     Localizable description of error codes.
     */
    static let localizedDescriptions: [SecurityKitError : String] = [
        .badCredentials : NSLocalizedString("Bad credentials.",      comment: "SecurityKit error description."),
        .badSignature   : NSLocalizedString("Bad signature.",        comment: "SecurityKit error description."),
        .decodingError  : NSLocalizedString("Decoding error.",       comment: "SecurityKit error description."),
        .failed         : NSLocalizedString("Failed",                comment: "SecurityKit error description."),
        .invalidData    : NSLocalizedString("Invalid data.",         comment: "SecurityKit error description."),
        .notInitialized : NSLocalizedString("Not initialized.",      comment: "SecurityKit error description."),
        .notFound       : NSLocalizedString("Not found",             comment: "SecurityKit error description."),
        .notPermitted   : NSLocalizedString("Not permitted",         comment: "SecurityKit error description."),
        .notSupported   : NSLocalizedString("Not supported",         comment: "SecurityKit error description.")
    ]
    
}


// End of File

