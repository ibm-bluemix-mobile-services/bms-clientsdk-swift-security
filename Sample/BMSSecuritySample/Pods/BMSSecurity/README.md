IBM Bluemix Mobile Services - Client SDK Swift Security
===================================================

This is the security component of the Swift SDK for IBM Bluemix Mobile Services.

https://console.ng.bluemix.net/solutions/mobilefirst

## Requirements
* iOS 8.0+
* Xcode 7


## Installation
The Bluemix Mobile Services Swift SDK is available via [Cocoapods](http://cocoapods.org/).
To install, add the `BMSSecurity` pod to your `Podfile`.

##### iOS
```ruby
use_frameworks!

target 'MyApp' do
    platform :ios, '8.0'
    pod 'BMSSecurity'
end
```
## Getting started

Connectivity and interaction between your mobile app and the Bluemix services depends on the application ID and application route that are associated with Bluemix application.

The BMSClient API is the entry point for interacting with the SDK. You must invoke the `initializeWithBluemixAppRoute: bluemixAppGUID: bluemixRegionSuffix:` method before any other API calls. BMSClient provides information about the current SDK level and access to service SDKs. This method is usually in the application delegate of your mobile app.

An example of initializing the MobileFirst Platform for iOS SDK follows:

Initialize SDK with IBM Bluemix application route, ID and the region where your Bluemix application is hosted.
```Swift
BMSClient.sharedInstance.initializeWithBluemixAppRoute(<app route>, bluemixAppGUID: <app guid>, bluemixRegionSuffix: BMSClient.<region>)
```

=======================
Copyright 2015 IBM Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
