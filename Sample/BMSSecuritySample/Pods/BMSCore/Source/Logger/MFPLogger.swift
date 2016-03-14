/*
*     Copyright 2016 IBM Corp.
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


/**
    Used in the `Logger` class, the `LogLevel` denotes the log severity.

    Lower integer raw values indicate higher severity.
 */
public enum LogLevel: Int {
    
    case None, Analytics, Fatal, Error, Warn, Info, Debug
    
    public var stringValue: String {
        get {
            switch self {
            case .None:
                return "NONE"
            case .Analytics:
                return "ANALYTICS"
            case .Fatal:
                return "FATAL"
            case .Error:
                return "ERROR"
            case .Warn:
                return "WARN"
            case .Info:
                return "INFO"
            case .Debug:
                return "DEBUG"
            }
        }
    }
}


// Stores logs on the device's file system
// This protocol is implemented in the BMSAnalytics framework
public protocol LogRecorderProtocol {
    
    func logMessageToFile(message: String, level: LogLevel, loggerName: String, calledFile: String, calledFunction: String, calledLineNumber: Int, additionalMetadata: [String: AnyObject]?)
}


/**
    `Logger` provides a wrapper to Swift's `print()` function, with additional information such as the file, function, and line where the log was called.
    It supports logging at different levels of verbosity (see the `LogLevel` enum) and filtering by `LogLevel` to limit the log output to the console.
    
    Multiple `Logger` instances can be created with different package names using the `getLoggerForName` method.
 
    - Important: All of the below functionality will be added to `Logger` if the `BMSAnalytics` framework is added to your project. `BMSAnalytics` extends `Logger` to allow storing log messages and sending them to an analytics server.

    When the `enabled` property is set to `true` (which is the default value), logs will be persisted to a file on the client device in the following JSON format:

        {
            "timestamp"    : "17-02-2013 13:54:27:123",   // "dd-MM-yyyy hh:mm:ss:S"
            "level"        : "ERROR",                     // FATAL || ERROR || WARN || INFO || DEBUG
            "name"         : "your_logger_name",          // The name of the Logger (typically a class name or app name)
            "msg"          : "the message",               // Some log message
            "metadata"     : {"some key": "some value"},  // Additional JSON metadata (only for Analytics logging)
        }

    Logs are accumulated persistently to the log file until the file size is greater than the `Logger.maxLogStoreSize` property. At this point, half of the old logs will be deleted to make room for new log data.

    Log file data is sent to the Bluemix server when the Logger `send()` method is called, provided that the file is not empty and the BMSClient was initialized via the `initializeWithBluemixAppRoute()` method. When the log data is successfully uploaded, the persisted local log data is deleted.

    - Note: The `Logger` class sets an uncaught exception handler to log application crashes. If you wish to set your own exception handler, do so **before** calling `Logger.getLoggerForName()` or the `Logger` exception handler will be overwritten.
*/
public class Logger {
    
    
    // MARK: Properties (Public)
    
    /// The name that identifies this Logger instance
    public let name: String
    
    /// Only logs that are at or above this level will be output to the console.
    /// Defaults to the `LogLevel.Debug`.
    ///
    /// Set the value to `LogLevel.None` to turn off all logging.
    public static var logLevelFilter: LogLevel = LogLevel.Debug
    
    /// If set to `false`, the internal BMSCore debug logs will not be displayed on the console.
    public static var sdkDebugLoggingEnabled: Bool = false
    
    // Used to persist all logs to the device's file system
    // Public access required by BMSAnalytics framework
    // This will obtain a value when the Analytics class from BMSAnalytics is initialized
    public static var logRecorder: LogRecorderProtocol?
    
    // Prefix for all internal logger names
    public static let mfpLoggerPrefix = "mfpsdk."
    
    
    
    // MARK: Properties (internal/private)
    
    // Each logger instance is distinguished only by its "name" property
    internal static var loggerInstances: [String: Logger] = [:]
    
    
    
    // MARK: Initializers
    
    /**
    Create a Logger instance that will be identified by the supplied name.
    If a Logger instance with that name already exists, the existing instance will be returned.
    
    - parameter loggerName: The name that identifies this Logger instance
    
    - returns: A Logger instance
    */
    public static func getLoggerForName(loggerName: String) -> Logger {
        
        if let existingLogger = Logger.loggerInstances[loggerName] {
            return existingLogger
        }
        else {
            let newLogger = Logger(name: loggerName)
            Logger.loggerInstances[loggerName] = newLogger
            
            return newLogger
        }
    }
    
    private init(name: String) {
        self.name = name
    }
    
    
    
    // MARK: Log methods (API)
    
    /**
    Log at the Debug LogLevel.
    
    - parameter message: The message to log
    
    - Note: Do not supply values for the `file`, `function`, or `line` parameters. These parameters take default values to automatically record the file, function, and line in which this method was called.
    */
    public func debug(message: String, file: String = __FILE__, function: String = __FUNCTION__, line: Int = __LINE__) {
        
        logMessage(message, level: LogLevel.Debug, calledFile: file, calledFunction: function, calledLineNumber: line)
    }
    
    /**
     Log at the Info LogLevel.
     
     - parameter message: The message to log
     
     - Note: Do not supply values for the `file`, `function`, or `line` parameters. These parameters take default values to automatically record the file, function, and line in which this method was called.
     */
    public func info(message: String, file: String = __FILE__, function: String = __FUNCTION__, line: Int = __LINE__) {
        
        logMessage(message, level: LogLevel.Info, calledFile: file, calledFunction: function, calledLineNumber: line)
    }
    
    /**
     Log at the Warn LogLevel.
     
     - parameter message: The message to log
     
     - Note: Do not supply values for the `file`, `function`, or `line` parameters. These parameters take default values to automatically record the file, function, and line in which this method was called.
     */
    public func warn(message: String, file: String = __FILE__, function: String = __FUNCTION__, line: Int = __LINE__) {
        
        logMessage(message, level: LogLevel.Warn, calledFile: file, calledFunction: function, calledLineNumber: line)
    }
    
    /**
     Log at the Error LogLevel.
     
     - parameter message: The message to log
     
     - Note: Do not supply values for the `file`, `function`, or `line` parameters. These parameters take default values to automatically record the file, function, and line in which this method was called.
     */
    public func error(message: String, file: String = __FILE__, function: String = __FUNCTION__, line: Int = __LINE__) {
        
        logMessage(message, level: LogLevel.Error, calledFile: file, calledFunction: function, calledLineNumber: line)
    }
    
    /**
     Log at the Fatal LogLevel.
     
     - parameter message: The message to log
     
     - Note: Do not supply values for the `file`, `function`, or `line` parameters. These parameters take default values to automatically record the file, function, and line in which this method was called.
     */
    public func fatal(message: String, file: String = __FILE__, function: String = __FUNCTION__, line: Int = __LINE__) {
        
        logMessage(message, level: LogLevel.Fatal, calledFile: file, calledFunction: function, calledLineNumber: line)
    }
    
    
    
    // MARK: Logging implementation
    
    // This is the master function that handles all of the logging, including level checking, printing to console, and writing to file
    // All other log functions below this one are helpers for this function
    public func logMessage(message: String, level: LogLevel, calledFile: String, calledFunction: String, calledLineNumber: Int, additionalMetadata: [String: AnyObject]? = nil) {
        
        // The level must exceed the Logger.logLevelFilter, or we do nothing
        guard level.rawValue <= Logger.logLevelFilter.rawValue else {
            return
        }
        
        if self.name.hasPrefix(Logger.mfpLoggerPrefix) && !Logger.sdkDebugLoggingEnabled && level == LogLevel.Debug {
            // Don't show our internal logs in the console.
        }
        else {
            // Print to console
            Logger.printLogToConsole(message, loggerName: self.name, level: level, calledFunction: calledFunction, calledFile: calledFile, calledLineNumber: calledLineNumber)
        }
        
        Logger.logRecorder?.logMessageToFile(message, level: level, loggerName: self.name, calledFile: calledFile, calledFunction: calledFunction, calledLineNumber: calledLineNumber, additionalMetadata: additionalMetadata)
    }
    
    // Format: [DEBUG] [mfpsdk.logger] logMessage in Logger.swift:234 :: "Some random message"
    public static func printLogToConsole(logMessage: String, loggerName: String, level: LogLevel, calledFunction: String, calledFile: String, calledLineNumber: Int) {
        
        // Suppress console log output for apps that are being released to the App Store
        #if DEBUG
            if level != LogLevel.Analytics {
                    print("[\(level.stringValue)] [\(loggerName)] \(calledFunction) in \(calledFile):\(calledLineNumber) :: \(logMessage)")
            }
        #endif
    }
}
