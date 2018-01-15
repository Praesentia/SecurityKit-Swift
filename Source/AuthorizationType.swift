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
 Credentials type.
 */
public enum AuthorizationType: String, Codable {
    case null = "null"
    
    /**
     Initialize instance from string.
     
     - Parameters:
        - string: String representation for the authorization type.
     */
    init?(string: String)
    {
        self.init(rawValue: string)
    }
    
    /**
     Get string representation.
     
     - Returns:
        Returns a string representation for the authorization type.
     */
    public var string: String { return rawValue }

}


// End of File
