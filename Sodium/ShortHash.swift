//
//  ShortHash.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class ShortHash {
    open let Bytes = Int(crypto_shorthash_bytes())
    open let KeyBytes = Int(crypto_shorthash_keybytes())
    
    open func hash(_ message: Data, key: Data) -> Data? {
        if key.count != KeyBytes {
            return nil
        }
        guard let output = NSMutableData(length: Bytes) else {
            return nil
        }
        if crypto_shorthash(output.mutableBytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), key.bytesPtr()) != 0 {
            return nil
        }
        return output as Data
    }
}
