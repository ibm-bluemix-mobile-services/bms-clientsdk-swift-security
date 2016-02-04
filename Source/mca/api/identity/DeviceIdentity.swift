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

public class DeviceIdentity{
    
    static let ID = "id"
    static let OS = "platform"
    static let MODEL = "model"
    
    var jsonData : Dictionary<String, String>? = ([:])
    
    public init() {
        jsonData![DeviceIdentity.ID] = "something"
        jsonData![DeviceIdentity.OS] = "1.0"
        jsonData![DeviceIdentity.MODEL] = "1.0"
    }
    
    public init(map: AnyObject?) {
        let json = map as! Dictionary<String, String>
        jsonData = json
    }
    
    public func getId() ->String {
        return jsonData![DeviceIdentity.ID]!
    }
    
    public func getOS() -> String {
        return jsonData![DeviceIdentity.OS]!
    }
    
    public func getModel() -> String {
        return jsonData![DeviceIdentity.MODEL]!
    }
}