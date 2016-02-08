/*
*     Copyright 2015 IBM Corp.
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*/
import Foundation

public class UserIdentity {
    static let ID = "id"
    static let AUTH_BY = "authBy"
    static let DISPLAY_NAME = "displayName"
    
    var jsonData : [String:String] = ([:])
    
    public init() {

    }
    public init(map: AnyObject?) {
        let json = map as? Dictionary<String, String>
        jsonData = json != nil ? json! : ([:])
    }
    
    public func getId() ->String? {
        return jsonData[UserIdentity.AUTH_BY]!
    }
    
    public func getAuthBy() ->String? {
        return jsonData[UserIdentity.ID]!
    }

    
    public func getDisplayName() -> String? {
        return jsonData[UserIdentity.DISPLAY_NAME]!
    }
}