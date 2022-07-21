//
//  ZDeviceHelper.swift
//  ZDeviceHelper
//
//  Created by SV59349 on 19/07/22.
//
import Foundation
import NotificationCenter

#if os(watchOS)
import WatchKit
#else
import UIKit
#endif

public enum Device {
#if os(iOS)
    /// Device is an [iPod touch (5th generation)](https://support.apple.com/kb/SP657)
    case iPodTouch5
    /// Device is an [iPod touch (6th generation)](https://support.apple.com/kb/SP720)
    case iPodTouch6
    /// Device is an [iPod touch (7th generation)](https://support.apple.com/kb/SP796)
    case iPodTouch7
    /// Device is an [iPhone 4](https://support.apple.com/kb/SP587)
    case iPhone4
    /// Device is an [iPhone 4s](https://support.apple.com/kb/SP643)
    case iPhone4s
    /// Device is an [iPhone 5](https://support.apple.com/kb/SP655)
    case iPhone5
    /// Device is an [iPhone 5c](https://support.apple.com/kb/SP684)
    case iPhone5c
    /// Device is an [iPhone 5s](https://support.apple.com/kb/SP685)
    case iPhone5s
    /// Device is an [iPhone 6](https://support.apple.com/kb/SP705)
    case iPhone6
    /// Device is an [iPhone 6 Plus](https://support.apple.com/kb/SP706)
    case iPhone6Plus
    /// Device is an [iPhone 6s](https://support.apple.com/kb/SP726)
    case iPhone6s
    /// Device is an [iPhone 6s Plus](https://support.apple.com/kb/SP727)
    case iPhone6sPlus
    /// Device is an [iPhone 7](https://support.apple.com/kb/SP743)
    case iPhone7
    /// Device is an [iPhone 7 Plus](https://support.apple.com/kb/SP744)
    case iPhone7Plus
    /// Device is an [iPhone SE](https://support.apple.com/kb/SP738)
    case iPhoneSE
    /// Device is an [iPhone 8](https://support.apple.com/kb/SP767)
    case iPhone8
    /// Device is an [iPhone 8 Plus](https://support.apple.com/kb/SP768)
    case iPhone8Plus
    /// Device is an [iPhone X](https://support.apple.com/kb/SP770)
    case iPhoneX
    /// Device is an [iPhone Xs](https://support.apple.com/kb/SP779)
    case iPhoneXS
    /// Device is an [iPhone Xs Max](https://support.apple.com/kb/SP780)
    case iPhoneXSMax
    /// Device is an [iPhone Xʀ](https://support.apple.com/kb/SP781)
    case iPhoneXR
    /// Device is an [iPhone 11](https://support.apple.com/kb/SP804)
    case iPhone11
    /// Device is an [iPhone 11 Pro](https://support.apple.com/kb/SP805)
    case iPhone11Pro
    /// Device is an [iPhone 11 Pro Max](https://support.apple.com/kb/SP806)
    case iPhone11ProMax
    /// Device is an [iPhone SE 2nd gen](https://support.apple.com/kb/SP820)
    case iPhoneSE2
    /// Device is an [iPhone 12 Mini](https://support.apple.com/kb/SP829)
    case iPhone12Mini
    /// Device is an [iPhone 12](https://support.apple.com/kb/SP830)
    case iPhone12
    /// Device is an [iPhone 12 Pro](https://support.apple.com/kb/SP831)
    case iPhone12Pro
    /// Device is an [iPhone 12 Pro Max](https://support.apple.com/kb/SP832)
    case iPhone12ProMax
    /// Device is an [iPhone 13 Mini](https://support.apple.com/kb/SP847)
    case iPhone13Mini
    /// Device is an [iPhone 13](https://support.apple.com/kb/SP851)
    case iPhone13
    /// Device is an [iPhone 13 Pro](https://support.apple.com/kb/SP852)
    case iPhone13Pro
    /// Device is an [iPhone 13 Pro Max](https://support.apple.com/kb/SP848)
    case iPhone13ProMax
    /// Device is an [iPhone SE 3nd gen](https://support.apple.com/kb/SP867)
    case iPhoneSE3
    /// Device is an [iPad 2](https://support.apple.com/kb/SP622)
    case iPad2
    /// Device is an [iPad (3rd generation)](https://support.apple.com/kb/SP647)
    case iPad3
    /// Device is an [iPad (4th generation)](https://support.apple.com/kb/SP662)
    case iPad4
    /// Device is an [iPad Air](https://support.apple.com/kb/SP692)
    case iPadAir
    /// Device is an [iPad Air 2](https://support.apple.com/kb/SP708)
    case iPadAir2
    /// Device is an [iPad (5th generation)](https://support.apple.com/kb/SP751)
    case iPad5
    /// Device is an [iPad (6th generation)](https://support.apple.com/kb/SP774)
    case iPad6
    /// Device is an [iPad (7th generation)](https://support.apple.com/kb/SP807)
    case iPad7
    /// Device is an [iPad (8th generation)](https://support.apple.com/kb/SP822)
    case iPad8
    /// Device is an [iPad (9th generation)](https://support.apple.com/kb/SP849)
    case iPad9
    /// Device is an [iPad Air (3rd generation)](https://support.apple.com/kb/SP787)
    case iPadAir3
    /// Device is an [iPad Air (4rd generation)](https://support.apple.com/kb/SP828)
    case iPadAir4
    /// Device is an [iPad Air (5rd generation)](https://support.apple.com/kb/SP866)
    case iPadAir5
    /// Device is an [iPad Mini](https://support.apple.com/kb/SP661)
    case iPadMini
    /// Device is an [iPad Mini 2](https://support.apple.com/kb/SP693)
    case iPadMini2
    /// Device is an [iPad Mini 3](https://support.apple.com/kb/SP709)
    case iPadMini3
    /// Device is an [iPad Mini 4](https://support.apple.com/kb/SP725)
    case iPadMini4
    /// Device is an [iPad Mini (5th generation)](https://support.apple.com/kb/SP788)
    case iPadMini5
    /// Device is an [iPad Mini (6th generation)](https://support.apple.com/kb/SP850)
    case iPadMini6
    /// Device is an [iPad Pro 9.7-inch](https://support.apple.com/kb/SP739)
    case iPadPro9Inch
    /// Device is an [iPad Pro 12.9-inch](https://support.apple.com/kb/SP723)
    case iPadPro12Inch
    /// Device is an [iPad Pro 12.9-inch (2nd generation)](https://support.apple.com/kb/SP761)
    case iPadPro12Inch2
    /// Device is an [iPad Pro 10.5-inch](https://support.apple.com/kb/SP762)
    case iPadPro10Inch
    /// Device is an [iPad Pro 11-inch](https://support.apple.com/kb/SP784)
    case iPadPro11Inch
    /// Device is an [iPad Pro 11-inch (2nd generation)](https://support.apple.com/kb/SP814)
    case iPadPro11Inch2
    /// Device is an [iPad Pro, 11-inch (3rd generation)](https://support.apple.com/kb/SP843)
    case iPadPro11Inch3
    /// Device is an [iPad Pro 12.9-inch (3rd generation)](https://support.apple.com/kb/SP785)
    case iPadPro12Inch3
    /// Device is an [iPad Pro 12.9-inch (4th generation)](https://support.apple.com/kb/SP815)
    case iPadPro12Inch4
    /// Device is an [iPad Pro, 12.9-inch (5th generation)](https://support.apple.com/kb/SP844)
    case iPadPro12Inch5
    /// Device is a [HomePod](https://support.apple.com/kb/SP773)
    case homePod
#elseif os(tvOS)

#elseif os(watchOS)
    
#endif

    /// Device is [Simulator](https://developer.apple.com/library/ios/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)
    ///
    indirect case simulator(Device)

    /// Device is not yet known (implemented)
    /// You can still use this enum as before but the description equals the identifier (you can get multiple identifiers for the same product class
    /// (e.g. "iPhone6,1" or "iPhone 6,2" do both mean "iPhone 5s"))
    case unknown(String)

    /// Returns a `Device` representing the current device this software runs on.
    public static var current: Device {
        return Device.mapToDevice(identifier: Device.identifier)
    }

    /// Call for identifier from the system, such as "iPhone12,5".
    public static var identifier: String = {
        var systemInfo = utsname()
        uname(&systemInfo)
        let mirror = Mirror(reflecting: systemInfo.machine)

        let identifier = mirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }()

    /// Maps an identifier to a Device. If the identifier can not be mapped to an existing device, `UnknownDevice(identifier)` is returned.
    ///
    /// - parameter identifier: The device identifier, e.g. "iPhone12,5". Can be obtained from `Device.identifier`.
    ///
    /// - returns: An initialized `Device`.
    public static func mapToDevice(identifier: String) -> Device {
#if os(iOS)
        switch identifier {
        case "iPod5,1": return iPodTouch5
        case "iPod7,1": return iPodTouch6
        case "iPod9,1": return iPodTouch7
        case "iPhone3,1", "iPhone3,2", "iPhone3,3": return iPhone4
        case "iPhone4,1": return iPhone4s
        case "iPhone5,1", "iPhone5,2": return iPhone5
        case "iPhone5,3", "iPhone5,4": return iPhone5c
        case "iPhone6,1", "iPhone6,2": return iPhone5s
        case "iPhone7,2": return iPhone6
        case "iPhone7,1": return iPhone6Plus
        case "iPhone8,1": return iPhone6s
        case "iPhone8,2": return iPhone6sPlus
        case "iPhone9,1", "iPhone9,3": return iPhone7
        case "iPhone9,2", "iPhone9,4": return iPhone7Plus
        case "iPhone8,4": return iPhoneSE
        case "iPhone10,1", "iPhone10,4": return iPhone8
        case "iPhone10,2", "iPhone10,5": return iPhone8Plus
        case "iPhone10,3", "iPhone10,6": return iPhoneX
        case "iPhone11,2": return iPhoneXS
        case "iPhone11,4", "iPhone11,6": return iPhoneXSMax
        case "iPhone11,8": return iPhoneXR
        case "iPhone12,1": return iPhone11
        case "iPhone12,3": return iPhone11Pro
        case "iPhone12,5": return iPhone11ProMax
        case "iPhone12,8": return iPhoneSE2
        case "iPhone13,1": return iPhone12Mini
        case "iPhone13,2": return iPhone12
        case "iPhone13,3": return iPhone12Pro
        case "iPhone13,4": return iPhone12ProMax
        case "iPhone14,4": return iPhone13Mini
        case "iPhone14,5": return iPhone13
        case "iPhone14,2": return iPhone13Pro
        case "iPhone14,3": return iPhone13ProMax
        case "iPhone14,6": return iPhoneSE3
        case "iPad2,1", "iPad2,2", "iPad2,3", "iPad2,4": return iPad2
        case "iPad3,1", "iPad3,2", "iPad3,3": return iPad3
        case "iPad3,4", "iPad3,5", "iPad3,6": return iPad4
        case "iPad4,1", "iPad4,2", "iPad4,3": return iPadAir
        case "iPad5,3", "iPad5,4": return iPadAir2
        case "iPad6,11", "iPad6,12": return iPad5
        case "iPad7,5", "iPad7,6": return iPad6
        case "iPad7,11", "iPad7,12": return iPad7
        case "iPad11,6", "iPad11,7": return iPad8
        case "iPad12,1", "iPad12,2": return iPad9
        case "iPad11,3", "iPad11,4": return iPadAir3
        case "iPad13,1", "iPad13,2": return iPadAir4
        case "iPad13,16", "iPad13,17": return iPadAir5
        case "iPad2,5", "iPad2,6", "iPad2,7": return iPadMini
        case "iPad4,4", "iPad4,5", "iPad4,6": return iPadMini2
        case "iPad4,7", "iPad4,8", "iPad4,9": return iPadMini3
        case "iPad5,1", "iPad5,2": return iPadMini4
        case "iPad11,1", "iPad11,2": return iPadMini5
        case "iPad14,1", "iPad14,2": return iPadMini6
        case "iPad6,3", "iPad6,4": return iPadPro9Inch
        case "iPad6,7", "iPad6,8": return iPadPro12Inch
        case "iPad7,1", "iPad7,2": return iPadPro12Inch2
        case "iPad7,3", "iPad7,4": return iPadPro10Inch
        case "iPad8,1", "iPad8,2", "iPad8,3", "iPad8,4": return iPadPro11Inch
        case "iPad8,9", "iPad8,10": return iPadPro11Inch2
        case "iPad13,4", "iPad13,5", "iPad13,6", "iPad13,7": return iPadPro11Inch3
        case "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8": return iPadPro12Inch3
        case "iPad8,11", "iPad8,12": return iPadPro12Inch4
        case "iPad13,8", "iPad13,9", "iPad13,10", "iPad13,11": return iPadPro12Inch5
        case "AudioAccessory1,1": return homePod
        case "i386", "x86_64": return simulator(mapToDevice(identifier: ProcessInfo().environment["SIMULATOR_MODEL_IDENTIFIER"] ?? "iOS"))
        default: return unknown(identifier)
        }
#elseif os(tvOS)
       
#elseif os(watchOS)

#endif
    }

    /// Get the real device from a device.
    /// If the device is a an iPhone8Plus simulator this function returns .iPhone8Plus (the real device).
    /// If the parameter is a real device, this function returns just that passed parameter.
    ///
    /// - parameter device: A device.
    ///
    /// - returns: the underlying device If the `device` is a `simulator`,
    /// otherwise return the `device`.
    public static func realDevice(from device: Device) -> Device {
        if case let .simulator(model) = device {
            return model
        }
        return device
    }

#if os(iOS) || os(watchOS)
    /// Returns diagonal screen length in inches
    public var diagonal: Double {
#if os(iOS)
        switch self {
        case .iPodTouch5: return 4
        case .iPodTouch6: return 4
        case .iPodTouch7: return 4
        case .iPhone4: return 3.5
        case .iPhone4s: return 3.5
        case .iPhone5: return 4
        case .iPhone5c: return 4
        case .iPhone5s: return 4
        case .iPhone6: return 4.7
        case .iPhone6Plus: return 5.5
        case .iPhone6s: return 4.7
        case .iPhone6sPlus: return 5.5
        case .iPhone7: return 4.7
        case .iPhone7Plus: return 5.5
        case .iPhoneSE: return 4
        case .iPhone8: return 4.7
        case .iPhone8Plus: return 5.5
        case .iPhoneX: return 5.8
        case .iPhoneXS: return 5.8
        case .iPhoneXSMax: return 6.5
        case .iPhoneXR: return 6.1
        case .iPhone11: return 6.1
        case .iPhone11Pro: return 5.8
        case .iPhone11ProMax: return 6.5
        case .iPhoneSE2: return 4.7
        case .iPhone12Mini: return 5.4
        case .iPhone12: return 6.1
        case .iPhone12Pro: return 6.1
        case .iPhone12ProMax: return 6.7
        case .iPhone13Mini: return 5.4
        case .iPhone13: return 6.1
        case .iPhone13Pro: return 6.1
        case .iPhone13ProMax: return 6.7
        case .iPhoneSE3: return 4.7
        case .iPad2: return 9.7
        case .iPad3: return 9.7
        case .iPad4: return 9.7
        case .iPadAir: return 9.7
        case .iPadAir2: return 9.7
        case .iPad5: return 9.7
        case .iPad6: return 9.7
        case .iPad7: return 10.2
        case .iPad8: return 10.2
        case .iPad9: return 10.2
        case .iPadAir3: return 10.5
        case .iPadMini: return 7.9
        case .iPadMini2: return 7.9
        case .iPadMini3: return 7.9
        case .iPadMini4: return 7.9
        case .iPadMini5: return 7.9
        case .iPadMini6: return 8.3
        case .iPadPro9Inch: return 9.7
        case .iPadPro12Inch: return 12.9
        case .iPadPro12Inch2: return 12.9
        case .iPadPro10Inch: return 10.5
        case .iPadPro11Inch: return 11.0
        case .iPadPro12Inch3: return 12.9
        case .iPadAir4: return 10.9
        case .iPadAir5: return 10.9
        case .iPadPro11Inch2: return 11
        case .iPadPro11Inch3: return 11
        case .iPadPro12Inch4: return 12.9
        case .iPadPro12Inch5: return 12.9
        case .homePod: return -1
        case .simulator(let model): return model.diagonal
        case .unknown: return -1
        }
#elseif os(watchOS)
       
#endif
    }
#endif

    /// Returns screen ratio as a tuple
    public var screenRatio: (width: Double, height: Double) {
#if os(iOS)
        switch self {
        case .iPodTouch5: return (width: 9, height: 16)
        case .iPodTouch6: return (width: 9, height: 16)
        case .iPodTouch7: return (width: 9, height: 16)
        case .iPhone4: return (width: 2, height: 3)
        case .iPhone4s: return (width: 2, height: 3)
        case .iPhone5: return (width: 9, height: 16)
        case .iPhone5c: return (width: 9, height: 16)
        case .iPhone5s: return (width: 9, height: 16)
        case .iPhone6: return (width: 9, height: 16)
        case .iPhone6Plus: return (width: 9, height: 16)
        case .iPhone6s: return (width: 9, height: 16)
        case .iPhone6sPlus: return (width: 9, height: 16)
        case .iPhone7: return (width: 9, height: 16)
        case .iPhone7Plus: return (width: 9, height: 16)
        case .iPhoneSE: return (width: 9, height: 16)
        case .iPhone8: return (width: 9, height: 16)
        case .iPhone8Plus: return (width: 9, height: 16)
        case .iPhoneX: return (width: 9, height: 19.5)
        case .iPhoneXS: return (width: 9, height: 19.5)
        case .iPhoneXSMax: return (width: 9, height: 19.5)
        case .iPhoneXR: return (width: 9, height: 19.5)
        case .iPhone11: return (width: 9, height: 19.5)
        case .iPhone11Pro: return (width: 9, height: 19.5)
        case .iPhone11ProMax: return (width: 9, height: 19.5)
        case .iPhoneSE2: return (width: 9, height: 16)
        case .iPhone12Mini: return (width: 9, height: 19.5)
        case .iPhone12: return (width: 9, height: 19.5)
        case .iPhone12Pro: return (width: 9, height: 19.5)
        case .iPhone12ProMax: return (width: 9, height: 19.5)
        case .iPhone13Mini: return (width: 9, height: 19.5)
        case .iPhone13: return (width: 9, height: 19.5)
        case .iPhone13Pro: return (width: 9, height: 19.5)
        case .iPhone13ProMax: return (width: 9, height: 19.5)
        case .iPhoneSE3: return (width: 9, height: 16)
        case .iPad2: return (width: 3, height: 4)
        case .iPad3: return (width: 3, height: 4)
        case .iPad4: return (width: 3, height: 4)
        case .iPadAir: return (width: 3, height: 4)
        case .iPadAir2: return (width: 3, height: 4)
        case .iPad5: return (width: 3, height: 4)
        case .iPad6: return (width: 3, height: 4)
        case .iPad7: return (width: 3, height: 4)
        case .iPad8: return (width: 3, height: 4)
        case .iPad9: return (width: 3, height: 4)
        case .iPadAir3: return (width: 3, height: 4)
        case .iPadAir4: return (width: 3, height: 4)
        case .iPadAir5: return (width: 3, height: 4)
        case .iPadMini: return (width: 3, height: 4)
        case .iPadMini2: return (width: 3, height: 4)
        case .iPadMini3: return (width: 3, height: 4)
        case .iPadMini4: return (width: 3, height: 4)
        case .iPadMini5: return (width: 3, height: 4)
        case .iPadMini6: return (width: 4, height: 6.1)
        case .iPadPro9Inch: return (width: 3, height: 4)
        case .iPadPro12Inch: return (width: 3, height: 4)
        case .iPadPro12Inch2: return (width: 3, height: 4)
        case .iPadPro10Inch: return (width: 3, height: 4)
        case .iPadPro11Inch: return (width: 139, height: 199)
        case .iPadPro12Inch3: return (width: 512, height: 683)
        case .iPadPro11Inch2: return (width: 139, height: 199)
        case .iPadPro11Inch3: return (width: 139, height: 199)
        case .iPadPro12Inch4: return (width: 512, height: 683)
        case .iPadPro12Inch5: return (width: 512, height: 683)
        case .homePod: return (width: 4, height: 5)
        case .simulator(let model): return model.screenRatio
        case .unknown: return (width: -1, height: -1)
        }
#elseif os(watchOS)
        
#elseif os(tvOS)
        return (width: -1, height: -1)
#endif
    }

#if os(iOS)
    /// All iPods
    public static var allPods: [Device] {
        return [.iPodTouch5, .iPodTouch6, .iPodTouch7]
    }

    /// All iPhones
    public static var allPhones: [Device] {
        return [.iPhone4, .iPhone4s, .iPhone5, .iPhone5c, .iPhone5s, .iPhone6, .iPhone6Plus, .iPhone6s, .iPhone6sPlus, .iPhone7, .iPhone7Plus, .iPhoneSE, .iPhone8, .iPhone8Plus, .iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPhoneSE2, .iPhone12Mini, .iPhone12, .iPhone12Pro, .iPhone12ProMax, .iPhone13Mini, .iPhone13, .iPhone13Pro, .iPhone13ProMax, .iPhoneSE3]
    }

    /// All iPads
    public static var allPads: [Device] {
        return [.iPad2, .iPad3, .iPad4, .iPadAir, .iPadAir2, .iPad5, .iPad6, .iPad7, .iPad8, .iPad9, .iPadAir3, .iPadAir4, .iPadAir5, .iPadMini, .iPadMini2, .iPadMini3, .iPadMini4, .iPadMini5, .iPadMini6, .iPadPro9Inch, .iPadPro12Inch, .iPadPro12Inch2, .iPadPro10Inch, .iPadPro11Inch, .iPadPro12Inch3, .iPadPro11Inch2, .iPadPro11Inch3, .iPadPro12Inch4, .iPadPro12Inch5]
    }

    /// All X-Series Devices
    public static var allXSeriesDevices: [Device] {
        return [.iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR]
    }

    /// All Plus-Sized Devices
    public static var allPlusSizedDevices: [Device] {
        return [.iPhone6Plus, .iPhone6sPlus, .iPhone7Plus, .iPhone8Plus, .iPhoneXSMax, .iPhone11ProMax, .iPhone12Pro, .iPhone12ProMax, .iPhone13Pro, .iPhone13ProMax,]
    }

    /// All Pro Devices
    public static var allProDevices: [Device] {
        return [.iPhone11Pro, .iPhone11ProMax, .iPhone12Pro, .iPhone12ProMax, .iPhone13Pro, .iPhone13ProMax, .iPadPro9Inch, .iPadPro12Inch, .iPadPro12Inch2, .iPadPro10Inch, .iPadPro11Inch, .iPadPro12Inch3, .iPadPro11Inch2, .iPadPro11Inch3, .iPadPro12Inch4, .iPadPro12Inch5]
    }

    /// All mini Devices
    public static var allMiniDevices: [Device] {
        return [.iPhone12Mini, .iPhone13Mini, .iPadMini, .iPadMini2, .iPadMini3, .iPadMini4, .iPadMini5, .iPadMini6]
    }

    /// All simulator iPods
    public static var allSimulatorPods: [Device] {
        return allPods.map(Device.simulator)
    }

    /// All simulator iPhones
    public static var allSimulatorPhones: [Device] {
        return allPhones.map(Device.simulator)
    }

    /// All simulator iPads
    public static var allSimulatorPads: [Device] {
        return allPads.map(Device.simulator)
    }

    /// All simulator iPad mini
    public static var allSimulatorMiniDevices: [Device] {
        return allMiniDevices.map(Device.simulator)
    }

    /// All simulator Plus-Sized Devices
    public static var allSimulatorXSeriesDevices: [Device] {
        return allXSeriesDevices.map(Device.simulator)
    }

    /// All simulator Plus-Sized Devices
    public static var allSimulatorPlusSizedDevices: [Device] {
        return allPlusSizedDevices.map(Device.simulator)
    }

    /// All simulator Pro Devices
    public static var allSimulatorProDevices: [Device] {
        return allProDevices.map(Device.simulator)
    }

    /// Returns whether the device is an iPod (real or simulator)
    public var isPod: Bool {
        return isOneOf(Device.allPods) || isOneOf(Device.allSimulatorPods)
    }

    /// Returns whether the device is an iPhone (real or simulator)
    public var isPhone: Bool {
        return (isOneOf(Device.allPhones)
                || isOneOf(Device.allSimulatorPhones)
                || (UIDevice.current.userInterfaceIdiom == .phone && isCurrent)) && !isPod
    }

    /// Returns whether the device is an iPad (real or simulator)
    public var isPad: Bool {
        return isOneOf(Device.allPads)
        || isOneOf(Device.allSimulatorPads)
        || (UIDevice.current.userInterfaceIdiom == .pad && isCurrent)
    }

    /// Returns whether the device is any of the simulator
    /// Useful when there is a need to check and skip running a portion of code
    public var isSimulator: Bool {
        return isOneOf(Device.allSimulators)
    }

    /// If this device is a simulator return the underlying device,
    /// otherwise return `self`.
    public var realDevice: Device {
        return Device.realDevice(from: self)
    }

    public var isZoomed: Bool? {
        guard isCurrent else { return nil }
        if Int(UIScreen.main.scale.rounded()) == 3 {
            // Plus-sized
            return UIScreen.main.nativeScale > 2.7 && UIScreen.main.nativeScale < 3
        } else {
            return UIScreen.main.nativeScale > UIScreen.main.scale
        }
    }

    /// All Touch ID Capable Devices
    public static var allTouchIDCapableDevices: [Device] {
        return [.iPhone5s, .iPhone6, .iPhone6Plus, .iPhone6s, .iPhone6sPlus, .iPhone7, .iPhone7Plus, .iPhoneSE, .iPhone8, .iPhone8Plus, .iPhoneSE2, .iPhoneSE3, .iPadAir2, .iPad5, .iPad6, .iPad7, .iPad8, .iPad9, .iPadAir3, .iPadAir4, .iPadAir5, .iPadMini3, .iPadMini4, .iPadMini5, .iPadMini6, .iPadPro9Inch, .iPadPro12Inch, .iPadPro12Inch2, .iPadPro10Inch]
    }

    /// All Face ID Capable Devices
    public static var allFaceIDCapableDevices: [Device] {
        return [.iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPhone12Mini, .iPhone12, .iPhone12Pro, .iPhone12ProMax, .iPhone13Mini, .iPhone13, .iPhone13Pro, .iPhone13ProMax, .iPadPro11Inch, .iPadPro12Inch3, .iPadPro11Inch2, .iPadPro11Inch3, .iPadPro12Inch4, .iPadPro12Inch5]
    }

    /// Returns whether or not the device has Touch ID
    public var isTouchIDCapable: Bool {
        return isOneOf(Device.allTouchIDCapableDevices)
    }

    /// Returns whether or not the device has Face ID
    public var isFaceIDCapable: Bool {
        return isOneOf(Device.allFaceIDCapableDevices)
    }

    /// Returns whether or not the device has any biometric sensor (i.e. Touch ID or Face ID)
    public var hasBiometricSensor: Bool {
        return isTouchIDCapable || isFaceIDCapable
    }

    /// All devices that feature a sensor housing in the screen
    public static var allDevicesWithSensorHousing: [Device] {
        return [.iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPhone12Mini, .iPhone12, .iPhone12Pro, .iPhone12ProMax, .iPhone13Mini, .iPhone13, .iPhone13Pro, .iPhone13ProMax]
    }

    /// Returns whether or not the device has a sensor housing
    public var hasSensorHousing: Bool {
        return isOneOf(Device.allDevicesWithSensorHousing)
    }

    /// All devices that feature a screen with rounded corners.
    public static var allDevicesWithRoundedDisplayCorners: [Device] {
        return [.iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPhone12Mini, .iPhone12, .iPhone12Pro, .iPhone12ProMax, .iPhone13Mini, .iPhone13, .iPhone13Pro, .iPhone13ProMax, .iPadPro11Inch, .iPadPro12Inch3, .iPadPro11Inch2, .iPadPro11Inch3, .iPadPro12Inch4, .iPadPro12Inch5]
    }

    /// Returns whether or not the device has a screen with rounded corners.
    public var hasRoundedDisplayCorners: Bool {
        return isOneOf(Device.allDevicesWithRoundedDisplayCorners)
    }

    /// All devices that have 3D Touch support.
    public static var allDevicesWith3dTouchSupport: [Device] {
        return [.iPhone6s, .iPhone6sPlus, .iPhone7, .iPhone7Plus, .iPhoneSE, .iPhone8, .iPhone8Plus, .iPhoneX, .iPhoneXS, .iPhoneXSMax]
    }

    /// Returns whether or not the device has 3D Touch support.
    public var has3dTouchSupport: Bool {
        return isOneOf(Device.allDevicesWith3dTouchSupport)
    }
#elseif os(tvOS)
  
#elseif os(watchOS)
    
#endif

    /// All real devices
    public static var allRealDevices: [Device] {
#if os(iOS)
        return allPods + allPhones + allPads
#elseif os(tvOS)
        
#elseif os(watchOS)
        
#endif
    }

    /// All simulators
    public static var allSimulators: [Device] {
        return allRealDevices.map(Device.simulator)
    }

    public func isOneOf(_ devices: [Device]) -> Bool {
        return devices.contains(self)
    }

    /// Whether or not the current device is the current device.
    private var isCurrent: Bool {
        return self == Device.current
    }

    /// The name identifying the device (e.g. "Zoe' iPhone").
    public var name: String? {
        guard isCurrent else { return nil }
#if os(watchOS)
    
#else
        return UIDevice.current.name
#endif
    }

    /// The name of the operating system running on the device represented by the receiver (e.g. "iOS" or "tvOS").
    public var systemName: String? {
        guard isCurrent else { return nil }
#if os(watchOS)
        return WKInterfaceDevice.current().systemName
#else
        return UIDevice.current.systemName
#endif
    }

    /// The current version of the operating system (e.g. 8.4 or 9.2).
    public var systemVersion: String? {
        guard isCurrent else { return nil }
#if os(watchOS)
        return WKInterfaceDevice.current().systemVersion
#else
        return UIDevice.current.systemVersion
#endif
    }

    /// The model of the device (e.g. "iPhone" or "iPod Touch").
    public var model: String? {
        guard isCurrent else { return nil }
#if os(watchOS)
        return WKInterfaceDevice.current().model
#else
        return UIDevice.current.model
#endif
    }

    /// The model of the device as a localized string.
    public var localizedModel: String? {
        guard isCurrent else { return nil }
#if os(watchOS)
        return WKInterfaceDevice.current().localizedModel
#else
        return UIDevice.current.localizedModel
#endif
    }

    /// PPI (Pixels per Inch) on the current device's screen (if applicable). When the device is not applicable this property returns nil.
    public var ppi: Int? {
#if os(iOS)
        switch self {
        case .iPodTouch5: return 326
        case .iPodTouch6: return 326
        case .iPodTouch7: return 326
        case .iPhone4: return 326
        case .iPhone4s: return 326
        case .iPhone5: return 326
        case .iPhone5c: return 326
        case .iPhone5s: return 326
        case .iPhone6: return 326
        case .iPhone6Plus: return 401
        case .iPhone6s: return 326
        case .iPhone6sPlus: return 401
        case .iPhone7: return 326
        case .iPhone7Plus: return 401
        case .iPhoneSE: return 326
        case .iPhone8: return 326
        case .iPhone8Plus: return 401
        case .iPhoneX: return 458
        case .iPhoneXS: return 458
        case .iPhoneXSMax: return 458
        case .iPhoneXR: return 326
        case .iPhone11: return 326
        case .iPhone11Pro: return 458
        case .iPhone11ProMax: return 458
        case .iPhoneSE2: return 326
        case .iPhone12Mini: return 476
        case .iPhone12: return 460
        case .iPhone12Pro: return 460
        case .iPhone12ProMax: return 458
        case .iPhone13Mini: return 476
        case .iPhone13: return 460
        case .iPhone13Pro: return 460
        case .iPhone13ProMax: return 458
        case .iPhoneSE3: return 326
        case .iPad2: return 132
        case .iPad3: return 264
        case .iPad4: return 264
        case .iPadAir: return 264
        case .iPadAir2: return 264
        case .iPad5: return 264
        case .iPad6: return 264
        case .iPad7: return 264
        case .iPad8: return 264
        case .iPad9: return 264
        case .iPadAir3: return 264
        case .iPadAir4: return 264
        case .iPadAir5: return 264
        case .iPadMini: return 163
        case .iPadMini2: return 326
        case .iPadMini3: return 326
        case .iPadMini4: return 326
        case .iPadMini5: return 326
        case .iPadMini6: return 326
        case .iPadPro9Inch: return 264
        case .iPadPro12Inch: return 264
        case .iPadPro12Inch2: return 264
        case .iPadPro10Inch: return 264
        case .iPadPro11Inch: return 264
        case .iPadPro12Inch3: return 264
        case .iPadPro11Inch2: return 264
        case .iPadPro11Inch3: return 264
        case .iPadPro12Inch4: return 264
        case .iPadPro12Inch5: return 264
        case .homePod: return -1
        case .simulator(let model): return model.ppi
        case .unknown: return nil
        }
#elseif os(watchOS)
        
#elseif os(tvOS)
        return nil
#endif
    }

    /// True when a Guided Access session is currently active; otherwise, false.
    public var isGuidedAccessSessionActive: Bool {
#if os(iOS)
#if swift(>=4.2)
        return UIAccessibility.isGuidedAccessEnabled
#else
        return UIAccessibilityIsGuidedAccessEnabled()
#endif
#else
        return false
#endif
    }

    /// The brightness level of the screen.
    public var screenBrightness: Int {
#if os(iOS)
        return Int(UIScreen.main.brightness * 100)
#else
        return 100
#endif
    }
}
   
// MARK: - CustomStringConvertible
extension Device: CustomStringConvertible {
    
    /// A textual representation of the device.
    public var description: String {
#if os(iOS)
        switch self {
        case .iPodTouch5: return "iPod touch (5th generation)"
        case .iPodTouch6: return "iPod touch (6th generation)"
        case .iPodTouch7: return "iPod touch (7th generation)"
        case .iPhone4: return "iPhone 4"
        case .iPhone4s: return "iPhone 4s"
        case .iPhone5: return "iPhone 5"
        case .iPhone5c: return "iPhone 5c"
        case .iPhone5s: return "iPhone 5s"
        case .iPhone6: return "iPhone 6"
        case .iPhone6Plus: return "iPhone 6 Plus"
        case .iPhone6s: return "iPhone 6s"
        case .iPhone6sPlus: return "iPhone 6s Plus"
        case .iPhone7: return "iPhone 7"
        case .iPhone7Plus: return "iPhone 7 Plus"
        case .iPhoneSE: return "iPhone SE"
        case .iPhone8: return "iPhone 8"
        case .iPhone8Plus: return "iPhone 8 Plus"
        case .iPhoneX: return "iPhone X"
        case .iPhoneXS: return "iPhone Xs"
        case .iPhoneXSMax: return "iPhone Xs Max"
        case .iPhoneXR: return "iPhone Xʀ"
        case .iPhone11: return "iPhone 11"
        case .iPhone11Pro: return "iPhone 11 Pro"
        case .iPhone11ProMax: return "iPhone 11 Pro Max"
        case .iPhoneSE2: return "iPhone SE (2nd generation)"
        case .iPhone12Mini: return "iPhone 12 mini"
        case .iPhone12: return "iPhone 12"
        case .iPhone12Pro: return "iPhone 12 Pro"
        case .iPhone12ProMax: return "iPhone 12 Pro Max"
        case .iPhone13Mini: return "iPhone 13 mini"
        case .iPhone13: return "iPhone 13"
        case .iPhone13Pro: return "iPhone 13 Pro"
        case .iPhone13ProMax: return "iPhone 13 Pro Max"
        case .iPhoneSE3: return "iPhone SE (3rd generation)"
        case .iPad2: return "iPad 2"
        case .iPad3: return "iPad (3rd generation)"
        case .iPad4: return "iPad (4th generation)"
        case .iPadAir: return "iPad Air"
        case .iPadAir2: return "iPad Air 2"
        case .iPad5: return "iPad (5th generation)"
        case .iPad6: return "iPad (6th generation)"
        case .iPad7: return "iPad (7th generation)"
        case .iPad8: return "iPad (8th generation)"
        case .iPad9: return "iPad (9th generation)"
        case .iPadAir3: return "iPad Air (3rd generation)"
        case .iPadAir4: return "iPad Air (4th generation)"
        case .iPadAir5: return "iPad Air (5th generation)"
        case .iPadMini: return "iPad Mini"
        case .iPadMini2: return "iPad Mini 2"
        case .iPadMini3: return "iPad Mini 3"
        case .iPadMini4: return "iPad Mini 4"
        case .iPadMini5: return "iPad Mini (5th generation)"
        case .iPadMini6: return "iPad mini (6th generation)"
        case .iPadPro9Inch: return "iPad Pro (9.7-inch)"
        case .iPadPro12Inch: return "iPad Pro (12.9-inch)"
        case .iPadPro12Inch2: return "iPad Pro (12.9-inch) (2nd generation)"
        case .iPadPro10Inch: return "iPad Pro (10.5-inch)"
        case .iPadPro11Inch: return "iPad Pro (11-inch)"
        case .iPadPro12Inch3: return "iPad Pro (12.9-inch) (3rd generation)"
        case .iPadPro11Inch2: return "iPad Pro 11-inch (2nd generation)"
        case .iPadPro11Inch3: return "iPad Pro, 11-inch (3rd generation)"
        case .iPadPro12Inch4: return "iPad Pro 12.9-inch (4th generation)"
        case .iPadPro12Inch5: return "iPad Pro, 12.9-inch (5th generation)"
        case .homePod: return "HomePod"
        case .simulator(let model): return "Simulator (\(model))"
        case .unknown(let identifier): return identifier
        }
#elseif os(watchOS)
       
#elseif os(tvOS)
       
#endif
    }
}

// MARK: - Equatable
extension Device: Equatable {
    /// Compares two devices
    ///
    /// - parameter lhs: A device.
    /// - parameter rhs: Another device.
    ///
    /// - returns: `true` iff the underlying identifier is the same.
    public static func == (lhs: Device, rhs: Device) -> Bool {
        return lhs.description == rhs.description
    }
    
}

// MARK: - Battery
#if os(iOS) || os(watchOS)
@available(iOS 8.0, watchOS 4.0, *)
extension Device {
    /**
     This enum describes the state of the battery.
     
     - Full:      The device is plugged into power and the battery is 100% charged or the device is the iOS Simulator.
     - Charging:  The device is plugged into power and the battery is less than 100% charged.
     - Unplugged: The device is not plugged into power; the battery is discharging.
     */
    public enum BatteryState: CustomStringConvertible, Equatable {
        /// The device is plugged into power and the battery is 100% charged or the device is the iOS Simulator.
        case full
        /// The device is plugged into power and the battery is less than 100% charged.
        /// The associated value is in percent (0-100).
        case charging(Int)
        /// The device is not plugged into power; the battery is discharging.
        /// The associated value is in percent (0-100).
        case unplugged(Int)
        
#if os(iOS)
        fileprivate init() {
            let wasBatteryMonitoringEnabled = UIDevice.current.isBatteryMonitoringEnabled
            UIDevice.current.isBatteryMonitoringEnabled = true
            let batteryLevel = Int(round(UIDevice.current.batteryLevel * 100)) // round() is actually not needed anymore since -[batteryLevel] seems to always return a two-digit precision number
            // but maybe that changes in the future.
            switch UIDevice.current.batteryState {
            case .charging: self = .charging(batteryLevel)
            case .full: self = .full
            case .unplugged: self = .unplugged(batteryLevel)
            case .unknown: self = .full // Should never happen since `batteryMonitoring` is enabled.
            @unknown default:
                self = .full // To cover any future additions for which DeviceKit might not have updated yet.
            }
            UIDevice.current.isBatteryMonitoringEnabled = wasBatteryMonitoringEnabled
        }
#elseif os(watchOS)

#endif
        
        /// The user enabled Low Power mode
        public var lowPowerMode: Bool {
            if #available(iOS 9.0, *) {
                return ProcessInfo.processInfo.isLowPowerModeEnabled
            } else {
                return false
            }
        }
        
        /// Provides a textual representation of the battery state.
        /// Examples:
        /// ```
        /// Battery level: 90%, device is plugged in.
        /// Battery level: 100 % (Full), device is plugged in.
        /// Battery level: \(batteryLevel)%, device is unplugged.
        /// ```
        public var description: String {
            switch self {
            case .charging(let batteryLevel): return "Battery level: \(batteryLevel)%, device is plugged in."
            case .full: return "Battery level: 100 % (Full), device is plugged in."
            case .unplugged(let batteryLevel): return "Battery level: \(batteryLevel)%, device is unplugged."
            }
        }
        
    }
    
    /// The state of the battery
    public var batteryState: BatteryState? {
        guard isCurrent else { return nil }
        return BatteryState()
    }
    
    /// Battery level ranges from 0 (fully discharged) to 100 (100% charged).
    public var batteryLevel: Int? {
        guard isCurrent else { return nil }
        switch BatteryState() {
        case .charging(let value): return value
        case .full: return 100
        case .unplugged(let value): return value
        }
    }
    
}
#endif

#if os(iOS)
// MARK: - CPUInfo
extension Device {
    //  CPUinfo:
    //  Returns a dictionary of the name of the Current devices chip and processor.
    public var cpuInfo: Dictionary<String, String> {
        switch self {
        case .iPodTouch5: return ["A5":"800 MHz"]
        case .iPodTouch6: return ["A8":"1.4 GHz"]
        case .iPodTouch7: return ["A10":"1.63 GHz"]
        case .iPhone4: return ["A4":"800 MHz"]
        case .iPhone4s: return ["A5":"800 MHz"]
        case .iPhone5: return ["A6":"1.3 GHz"]
        case .iPhone5c: return ["A6":"1.3 GHz"]
        case .iPhone5s: return ["A7":"1.3 GHz"]
        case .iPhone6: return ["A8":"1.4 GHz"]
        case .iPhone6Plus: return ["A8":"1.4 GHz"]
        case .iPhone6s: return ["A9":"1.85 GHz"]
        case .iPhone6sPlus: return ["A9":"1.85 GHz"]
        case .iPhone7: return ["A10":"2.34 GHz"]
        case .iPhone7Plus: return ["A10":"2.34 GHz"]
        case .iPhoneSE: return ["A9":"1.85 GHz"]
        case .iPhone8: return ["A11":"2.39 GHz"]
        case .iPhone8Plus: return ["A11":"2.39 GHz"]
        case .iPhoneX: return ["A11":"2.39 GHz"]
        case .iPhoneXS: return ["A12":"2.5 GHz"]
        case .iPhoneXSMax: return ["A12":"2.5 GHz"]
        case .iPhoneXR: return ["A12":"2.5 GHz"]
        case .iPhone11: return ["A13":"2650 GHz"]
        case .iPhone11Pro: return ["A13":"2650 GHz"]
        case .iPhone11ProMax: return ["A13":"2650 GHz"]
        case .iPhoneSE2: return["A13":"2.65 GHz"]
        case .iPhone12Mini: return ["A14":"2.99 GHz"]
        case .iPhone12: return ["A14":"2.99 GHz"]
        case .iPhone12Pro: return ["A14":"2.99 GHz"]
        case .iPhone12ProMax: return ["A14":"3.1 GHz"]
        case .iPhone13Mini: return ["A15":"2x3.22 GHz"]
        case .iPhone13: return ["A15":"2x3.22 GHz"]
        case .iPhone13Pro: return ["A15":"2x3.22 GHz"]
        case .iPhone13ProMax: return ["A15":"2x3.22 GHz"]
        case .iPhoneSE3: return ["A15":"2x3.22 GHz"]
        case .iPad2: return ["A5":"1.0 GHz"]
        case .iPad3: return ["A5X":"1.0 GHz"]
        case .iPad4: return ["A6X":"1.4 GHz"]
        case .iPadAir: return ["A7":"1.4 GHz"]
        case .iPadAir2: return ["A8X":"1.5 GHz"]
        case .iPad5: return ["A9":"1.85 GHz"]
        case .iPad6: return ["A10 Fusion":"2.34 GHz"]
        case .iPad7: return ["A10 Fusion":"2.32 GHz"]
        case .iPad8: return ["A12":"2x2.5 GHz"]
        case .iPad9: return ["A13":"2x2.65 GHz"]
        case .iPadAir3: return ["A12":"2.49 GHz"]
        case .iPadAir4: return ["A14":"3.1 GHz"]
        case .iPadAir5: return ["M1":"3.1 GHz"]
        case .iPadMini: return ["A5":"1.0 GHz"]
        case .iPadMini2: return ["A7":"1.3 GHz"]
        case .iPadMini3: return ["A7":"1.3 GHz"]
        case .iPadMini4: return ["A8":"1.5 GHz"]
        case .iPadMini5: return ["A12":"2.49 GHz"]
        case .iPadMini6: return ["A15":"2.93 GHz"]
        case .iPadPro9Inch: return ["A9X":"2.16 GHz"]
        case .iPadPro12Inch: return ["A9X":"2.24 GHz"]
        case .iPadPro12Inch2: return ["A10X Fusion":"2.34 GHz"]
        case .iPadPro10Inch: return ["A10X Fusion":"2.34 GHz"]
        case .iPadPro11Inch: return ["A12X":"2.5 GHz"]
        case .iPadPro12Inch3: return ["A12Z":"2.5 GHz"]
        case .iPadPro11Inch2: return ["A12Z":"2.5 GHz"]
        case .iPadPro11Inch3: return ["M1":"3.1 GHz"]
        case .iPadPro12Inch4: return ["A12Z":"2.5 GHz"]
        case .iPadPro12Inch5: return ["M1":"3.1 GHz"]
        case .homePod: return ["A8":"1.4 GHz"]
        case .simulator(let model): return ["SIMULATOR_MODEL_IDENTIFIER": "\(model)"]
        case .unknown(let identifier): return ["\(identifier)": "Unknown"]
        }
    }
    
    /// All devices Chip name
    public var getChipName: String {
        let processorNames = Array(cpuInfo.keys)
        return processorNames[0]
    }
    
    /// All devices Processor
    public var getCpuProcessor: String {
        let processorNames = Array(cpuInfo.values)
        return processorNames[0]
    }
}
#endif


// MARK: - Device.Batterystate: Comparable
#if os(iOS) || os(watchOS)

#endif

#if os(iOS)
extension Device {
    // MARK: - Orientation
    /**
     This enum describes the state of the orientation.
     - Landscape: The device is in Landscape Orientation
     - Portrait:  The device is in Portrait Orientation
     */
    public enum Orientation {
        case landscape
        case portrait
    }
    
    public var orientation: Orientation {
        if UIDevice.current.orientation.isLandscape {
            return .landscape
        } else {
            return .portrait
        }
    }
}
#endif

#if os(iOS)
// MARK: - DiskSpace
extension Device {
    
    /// Return the root url
    ///
    /// - returns: the NSHomeDirectory() url
    private static let rootURL = URL(fileURLWithPath: NSHomeDirectory())
    
    /// The volume’s total capacity in bytes.
    public static var volumeTotalCapacity: Int? {
        return (try? Device.rootURL.resourceValues(forKeys: [.volumeTotalCapacityKey]))?.volumeTotalCapacity
    }
    
    /// The volume’s available capacity in bytes.
    public static var volumeAvailableCapacity: Int? {
        return (try? rootURL.resourceValues(forKeys: [.volumeAvailableCapacityKey]))?.volumeAvailableCapacity
    }
    
    /// The volume’s available capacity in bytes for storing important resources.
    @available(iOS 11.0, *)
    public static var volumeAvailableCapacityForImportantUsage: Int64? {
        return (try? rootURL.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]))?.volumeAvailableCapacityForImportantUsage
    }
    
    /// The volume’s available capacity in bytes for storing nonessential resources.
    @available(iOS 11.0, *)
    public static var volumeAvailableCapacityForOpportunisticUsage: Int64? {
        return (try? rootURL.resourceValues(forKeys: [.volumeAvailableCapacityForOpportunisticUsageKey]))?.volumeAvailableCapacityForOpportunisticUsage
    }
    
    /// All volumes capacity information in bytes.
    @available(iOS 11.0, *)
    public static var volumes: [URLResourceKey: Int64]? {
        do {
            let values = try rootURL.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey,
                                                              .volumeAvailableCapacityKey,
                                                              .volumeAvailableCapacityForOpportunisticUsageKey,
                                                              .volumeTotalCapacityKey
                                                             ])
            return values.allValues.mapValues {
                if let int = $0 as? Int64 {
                    return int
                }
                if let int = $0 as? Int {
                    return Int64(int)
                }
                return 0
            }
        } catch {
            return nil
        }
    }
}
#endif


#if os(iOS)
// MARK: - Cameras
extension Device {
    
    public enum CameraTypes {
        case normal
        case telephoto
        case ultraWide
    }
    
    /// Returns an array of the types of cameras the device has
    public var cameras: [CameraTypes] {
        switch self {
        case .iPodTouch5: return [.normal]
        case .iPodTouch6: return [.normal]
        case .iPodTouch7: return [.normal]
        case .iPhone4: return [.normal]
        case .iPhone4s: return [.normal]
        case .iPhone5: return [.normal]
        case .iPhone5c: return [.normal]
        case .iPhone5s: return [.normal]
        case .iPhone6: return [.normal]
        case .iPhone6Plus: return [.normal]
        case .iPhone6s: return [.normal]
        case .iPhone6sPlus: return [.normal]
        case .iPhone7: return [.normal]
        case .iPhoneSE: return [.normal]
        case .iPhone8: return [.normal]
        case .iPhoneXR: return [.normal]
        case .iPad2: return [.normal]
        case .iPad3: return [.normal]
        case .iPad4: return [.normal]
        case .iPadAir: return [.normal]
        case .iPadAir2: return [.normal]
        case .iPad5: return [.normal]
        case .iPad6: return [.normal]
        case .iPadAir3: return [.normal]
        case .iPadMini: return [.normal]
        case .iPadMini2: return [.normal]
        case .iPadMini3: return [.normal]
        case .iPadMini4: return [.normal]
        case .iPadMini5: return [.normal]
        case .iPadPro9Inch: return [.normal]
        case .iPadPro12Inch: return [.normal]
        case .iPadPro12Inch2: return [.normal]
        case .iPadPro10Inch: return [.normal]
        case .iPadPro11Inch: return [.normal]
        case .iPadPro12Inch3: return [.normal]
        case .iPhone7Plus: return [.normal, .telephoto]
        case .iPhone8Plus: return [.normal, .telephoto]
        case .iPhoneX: return [.normal, .telephoto]
        case .iPhoneXS: return [.normal, .telephoto]
        case .iPhoneXSMax: return [.normal, .telephoto]
        case .iPhone11: return [.normal, .ultraWide]
        case .iPhone11Pro: return [.normal, .telephoto, .ultraWide]
        case .iPhone11ProMax: return [.normal, .telephoto, .ultraWide]
        default: return []
        }
    }
    
    /// All devices that feature a camera
    public static var allDevicesWithCamera: [Device] {
        return [.iPodTouch5, .iPodTouch6, .iPodTouch7, .iPhone4, .iPhone4s, .iPhone5, .iPhone5c, .iPhone5s, .iPhone6, .iPhone6Plus, .iPhone6s, .iPhone6sPlus, .iPhone7, .iPhone7Plus, .iPhoneSE, .iPhone8, .iPhone8Plus, .iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPad2, .iPad3, .iPad4, .iPadAir, .iPadAir2, .iPad5, .iPad6, .iPadAir3, .iPadMini, .iPadMini2, .iPadMini3, .iPadMini4, .iPadMini5, .iPadPro9Inch, .iPadPro12Inch, .iPadPro12Inch2, .iPadPro10Inch, .iPadPro11Inch, .iPadPro12Inch3]
    }
    
    /// All devices that feature a normal camera
    public static var allDevicesWithNormalCamera: [Device] {
        return [.iPodTouch5, .iPodTouch6, .iPodTouch7, .iPhone4, .iPhone4s, .iPhone5, .iPhone5c, .iPhone5s, .iPhone6, .iPhone6Plus, .iPhone6s, .iPhone6sPlus, .iPhone7, .iPhone7Plus, .iPhoneSE, .iPhone8, .iPhone8Plus, .iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhoneXR, .iPhone11, .iPhone11Pro, .iPhone11ProMax, .iPad2, .iPad3, .iPad4, .iPadAir, .iPadAir2, .iPad5, .iPad6, .iPadAir3, .iPadMini, .iPadMini2, .iPadMini3, .iPadMini4, .iPadMini5, .iPadPro9Inch, .iPadPro12Inch, .iPadPro12Inch2, .iPadPro10Inch, .iPadPro11Inch, .iPadPro12Inch3]
    }
    
    /// All devices that feature a telephoto camera
    public static var allDevicesWithTelephotoCamera: [Device] {
        return [.iPhone7Plus, .iPhone8Plus, .iPhoneX, .iPhoneXS, .iPhoneXSMax, .iPhone11Pro, .iPhone11ProMax]
    }
    
    /// All devices that feature an ultra wide camera
    public static var allDevicesWithUltraWideCamera: [Device] {
        return [.iPhone11, .iPhone11Pro, .iPhone11ProMax]
    }
    
    /// Returns whether or not the current device has a camera
    public var hasCamera: Bool {
        return !self.cameras.isEmpty
    }
    
    /// Returns whether or not the current device has a normal camera
    public var hasNormalCamera: Bool {
        return self.cameras.contains(.normal)
    }
    
    /// Returns whether or not the current device has a telephoto camera
    public var hasTelephotoCamera: Bool {
        return self.cameras.contains(.telephoto)
    }
    
    /// Returns whether or not the current device has an ultra wide camera
    public var hasUltraWideCamera: Bool {
        return self.cameras.contains(.ultraWide)
    }
    
}
#endif

extension Device {
    
    /// This will check is the Device is X Series device or not.
    public var isXSeriesDevice: Bool {
        return (isOneOf(Device.allXSeriesDevices)
                || isOneOf(Device.allSimulatorXSeriesDevices))
    }
    
    /// Screen size
    public var size: CGSize {
        return UIScreen.main.bounds.size
    }
    
    /// Screen Bounds
    public var bounds: CGRect {
        return UIScreen.main.bounds
    }
    
    /// Screen width
    public var width: CGFloat {
        return UIScreen.main.bounds.size.width
    }
    
    /// Screen height
    public var height: CGFloat {
        return UIScreen.main.bounds.size.height
    }

}

public class ZDeviceHelper {
        
    public static var ram: UInt64 {
        return ProcessInfo.processInfo.physicalMemory/1073741824
    }
    
    public static var hostName: String {
        return ProcessInfo.processInfo.hostName
    }
    
}
