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
    case failed         =  2
    case notFound       =  3
    
    public var description      : String  { return "SecurityKit error \( rawValue ) (\( localizedDescription ))" }
    public var errorDescription : String? { return SecurityKitError.localizedDescriptions[self] }
}

extension SecurityKitError {
    
    /**
     Localizable description of error codes.
     */
    static let localizedDescriptions: [SecurityKitError : String] = [
        .badCredentials : NSLocalizedString("Bad credentials",       comment: "SecurityKit error description."),
        .failed         : NSLocalizedString("Failed",                comment: "SecurityKit error description."),
        .notFound       : NSLocalizedString("Not found",             comment: "SecurityKit error description.")
    ]
    
}


// End of File

