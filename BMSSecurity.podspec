Pod::Spec.new do |s|
    s.name         = "BMSSecurity"
    s.version      = '1.1.4'
    s.summary      = "The security component of the Swift client SDK for IBM Bluemix Mobile Services"
    s.homepage     = "https://github.com/ibm-bluemix-mobile-services/bms-clientsdk-swift-security"
    s.license      = 'Apache License, Version 2.0'
    s.author       = { "IBM Bluemix Services Mobile SDK" => "mobilsdk@us.ibm.com" }

    s.source       = { :git => 'https://github.com/ibm-bluemix-mobile-services/bms-clientsdk-swift-security.git', :tag => "v#{s.version}" }
    s.requires_arc = true
    s.dependency 'BMSCore', '~> 1.0'
    s.dependency 'RNCryptor', '~> 4.0.0-beta'
    s.source_files = 'Source/**/*.swift', 'Source/Resources/BMSSecurity.h'
    s.ios.deployment_target = '8.0'
end
