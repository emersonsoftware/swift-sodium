//
//  GenericHash.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class GenericHash {
    open let BytesMin = Int(crypto_generichash_bytes_min())
    open let BytesMax = Int(crypto_generichash_bytes_max())
    open let Bytes = Int(crypto_generichash_bytes())
    open let KeybytesMin = Int(crypto_generichash_keybytes_min())
    open let KeybytesMax = Int(crypto_generichash_keybytes_max())
    open let Keybytes = Int(crypto_generichash_keybytes())
    open let Primitive = String.init(validatingUTF8:crypto_generichash_primitive())
    
    open func hash(_ message: Data, key: Data? = nil) -> Data? {
        return hash(message, key: key, outputLength: Bytes)
    }
    
    open func hash(_ message: Data, key: Data?, outputLength: Int) -> Data? {
        guard let output = NSMutableData(length: outputLength) else {
            return nil
        }
        var ret: CInt;
        if let key = key {
            ret = crypto_generichash(output.mutableBytesPtr(), output.length, message.bytesPtr(), CUnsignedLongLong(message.count), key.bytesPtr(), key.count)
        } else {
            ret = crypto_generichash(output.mutableBytesPtr(), output.length, message.bytesPtr(), CUnsignedLongLong(message.count), nil, 0)
        }
        if ret != 0 {
            return nil
        }
        return output as Data
    }

    open func hash(_ message: Data, outputLength: Int) -> Data? {
        return hash(message, key: Data(), outputLength: outputLength)
    }
    
    open func initStream(_ key: Data? = nil) -> Stream? {
        return Stream(key: key, outputLength: Bytes)
    }
    
    open func initStream(_ key: Data?, outputLength: Int) -> Stream? {
        return Stream(key: key, outputLength: outputLength)
    }
    
    open func initStream(_ outputLength: Int) -> Stream? {
        return Stream(key: nil, outputLength: outputLength)
    }

    open class Stream {
        open var outputLength: Int = 0
        fileprivate var state: UnsafeMutablePointer<crypto_generichash_state>?

        init?(key: Data?, outputLength: Int) {
            state = UnsafeMutablePointer<crypto_generichash_state>.allocate(capacity: 1)
            guard let state = state else {
                return nil
            }
            var ret: CInt
            if let key = key {
                ret = crypto_generichash_init(state, key.bytesPtr(), key.count, outputLength)
            } else {
                ret = crypto_generichash_init(state, nil, 0, outputLength)
            }
            if ret != 0 {
                return nil
            }
            self.outputLength = outputLength;
        }
    
        deinit {
            state?.deallocate(capacity: 1)
        }
    
        open func update(_ input: Data) -> Bool {
            return crypto_generichash_update(state!, input.bytesPtr(), CUnsignedLongLong(input.count)) == 0
        }
    
        open func final() -> Data? {
            guard let output = NSMutableData(length: outputLength) else {
                return nil
            }
            if crypto_generichash_final(state!, output.mutableBytesPtr(), output.length) != 0 {
                return nil
            }
            return output as Data
        }
    }
}
