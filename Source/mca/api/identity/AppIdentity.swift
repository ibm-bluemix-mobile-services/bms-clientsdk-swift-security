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


public class AppIdentity{
    
    private static let ID = "id"
    private static let VERSION = "version"
    
    private var jsonData : [String:String] = ([:])
    
    public init() {
        let appInfo = Utils.getApplicationDetails()
        jsonData[AppIdentity.ID] =  appInfo.name
        jsonData[AppIdentity.VERSION] =  appInfo.version
    }
    
    public func getAsJson() -> [String:String]{
        return jsonData
    }
    
    public init(map: AnyObject?) {
        let json = map as! Dictionary<String, String>
        jsonData = json
    }
    
    public func getId() ->String {
        return jsonData[AppIdentity.ID]!
    }
    
    public func getVersion() -> String {
        return jsonData[AppIdentity.VERSION]!
    }
    
}
