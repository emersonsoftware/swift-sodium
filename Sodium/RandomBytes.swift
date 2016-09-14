//
//  RandomBytes.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class RandomBytes {
    open func buf(_ length: Int) -> Data? {
        if length < 0 {
            return nil
        }
        guard let output = NSMutableData(length: length) else {
            return nil
        }
        randombytes_buf(output.mutableBytesPtr(), output.length)
        return output as Data
    }
    
    open func random() -> UInt32 {
        return randombytes_random()
    }
    
    open func uniform(_ upperBound: UInt32) -> UInt32 {
        return randombytes_uniform(upperBound)
    }
}
