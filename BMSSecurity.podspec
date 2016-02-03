Pod::Spec.new do |s|
    s.name         = "BMSSecurity"
    s.version      = '0.0.1'
    s.summary      = "The security component of the Swift client SDK for IBM Bluemix Mobile Services"
    s.description  = "The IBM MobileFirst platform for iOS SDK integrates with \n                       the IBM MobileFirst platform Cloud Services. The SDK has a modular design, \n                       so you can add add services that are required by your \n                       application as needed.   \n"
    s.homepage     = "https://github.com/ibm-bluemix-mobile-services/bms-clientsdk-swift-security"
    s.license      = 'Apache License, Version 2.0'
    s.author       = { "IBM Bluemix Services Mobile SDK" => "mobilsdk@us.ibm.com" }

    s.source       = { :git => 'https://github.com/ibm-bluemix-mobile-services/bms-clientsdk-swift-security.git', :tag => "v#{s.version}" }
    s.source_files = 'BMSSecurity/BMSSecurity/**/*.swift'
    s.requires_arc = true
    s.dependency 'BMSCore'
    s.source_files = 'BMSSecurity/BMSSecurity/**/*.swift', 'BMSSecurity/BMSSecurity/BMSSecurity.h'    
    s.ios.deployment_target = '8.0'
end
