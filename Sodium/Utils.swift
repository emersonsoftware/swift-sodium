//
//  Utils.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class Utils {
    open func zero(_ data: NSMutableData) {
        sodium_memzero(UnsafeMutableRawPointer(data.mutableBytes), data.length)
        data.length = 0
    }
    
    open func equals(_ b1: Data, _ b2: Data) -> Bool {
        if b1.count != b2.count {
            return false
        }
        
        let bytes1 = b1.withUnsafeBytes{ (bytes: UnsafePointer<UInt8>) in
            return bytes
        }
        
        let bytes2 = b2.withUnsafeBytes{ (bytes: UnsafePointer<UInt8>) in
            return bytes
        }
        
        let res = sodium_memcmp(bytes1, bytes2, b1.count)
        return res == 0;
    }
    
    open func compare(_ b1: Data, _ b2: Data) -> Int? {
        if b1.count != b2.count {
            return nil
        }
        let res = sodium_compare(b1.bytesPtr(), b2.bytesPtr(), b1.count)
        return Int(res);
    }
    
    open func bin2hex(bin: Data) -> String? {
        guard let hexData = NSMutableData(length: bin.count * 2 + 1) else {
            return nil
        }
        if sodium_bin2hex(hexData.mutableBytesPtr(), hexData.length, bin.bytesPtr(), bin.count) == nil {
            return nil
        }
        return String.init(validatingUTF8: hexData.mutableBytesPtr())
    }
    
    open func hex2bin(hex: String, ignore: String? = nil) -> Data? {
        guard let hexData = hex.data(using: String.Encoding.utf8, allowLossyConversion: false) else {
            return nil
        }
        let hexDataLen = hexData.count
        let binDataCapacity = hexDataLen / 2
        guard let binData = NSMutableData(length: binDataCapacity) else {
            return nil
        }
        var binDataLen: size_t = 0
        let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil
        if sodium_hex2bin(binData.mutableBytesPtr(), binDataCapacity,hexData.bytesPtr(), hexDataLen, ignore_cstr, &binDataLen, nil) != 0 {
            return nil
        }
        binData.length = Int(binDataLen)
        return binData as Data
    }
}
