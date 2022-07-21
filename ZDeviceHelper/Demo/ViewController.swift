//
//  ViewController.swift
//  Demo
//
//  Created by SV59349 on 19/07/22.
//

import UIKit
import ZDeviceHelper

class ViewController: UIViewController {
    let device = Device.current
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // eg :- "iPhone 11 Pro"
        print(device)
        
        //Print system version (15.0)
        print(device.systemVersion)
        
        //Print system name (iOS)
        print(device.systemName)
        
        //Print device width
        print(device.width)
        
        //Print device height
        print(device.height)
        
        //Print device screen ratio (16:9)
        print(device.screenRatio)
        
        //Print true or false
        print(device.isZoomed)
        
        //Get current battery state
        print(device.batteryState)
        
        //Get current battery level
        print(device.batteryLevel)
        
        //Return device has camera has camera
        print(device.hasCamera)
        
        //Return device has camera has camera
        print(device.hasTelephotoCamera)
        
        //Return device has camera has camera
        print(device.hasUltraWideCamera)

        //Return device is capable of 3d Touch
        print(device.has3dTouchSupport)
        
        //Return device is capable of TouchId
        print(device.isTouchIDCapable)
        
        //Return device is capable of faceId
        print(device.isFaceIDCapable)
                        
        //Return device volume TotalCapacity in bytes
        print(Device.volumeTotalCapacity!)
        
        //Return device volume AvailableCapacity in bytes
        print(Device.volumeAvailableCapacity!)
        
        //Return current device chip name
        print(device.getChipName)
        
        //Return current device processor
        print(device.getCpuProcessor)
            
        //Return current device RAM
        print(ZDeviceHelper.ram)
        
        //Return current device hostName
        print(ZDeviceHelper.hostName)
    }
}

