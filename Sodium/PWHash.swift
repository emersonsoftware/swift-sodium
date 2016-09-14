//
//  PWHash.swift
//  Sodium
//
//  Created by Frank Denis on 4/29/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

open class PWHash {
    open let SaltBytes = Int(crypto_pwhash_saltbytes())
    open let StrBytes = Int(crypto_pwhash_strbytes()) - (1 as Int)
    open let StrPrefix = String.init(validatingUTF8: crypto_pwhash_strprefix())
    open let OpsLimitInteractive = Int(crypto_pwhash_opslimit_interactive())
    open let OpsLimitModerate = Int(crypto_pwhash_opslimit_moderate())
    open let OpsLimitSensitive = Int(crypto_pwhash_opslimit_sensitive())
    open let MemLimitInteractive = Int(crypto_pwhash_memlimit_interactive())
    open let MemLimitModerate = Int(crypto_pwhash_memlimit_moderate())
    open let MemLimitSensitive = Int(crypto_pwhash_memlimit_sensitive())

    open func str(_ passwd: Data, opsLimit: Int, memLimit: Int) -> String? {
        guard let output = NSMutableData(length: StrBytes) else {
            return nil
        }
        if crypto_pwhash_str(output.mutableBytesPtr(), passwd.bytesPtr(), CUnsignedLongLong(passwd.count), CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
            return nil
        }
        return NSString(data: output as Data, encoding: String.Encoding.utf8.rawValue) as String?
    }

    open func strVerify(_ hash: String, passwd: Data) -> Bool {
        guard let hashData = (hash + "\0").data(using: String.Encoding.utf8, allowLossyConversion: false) else {
                return false
        }
        
        return crypto_pwhash_str_verify(hashData.bytesPtr(), passwd.bytesPtr(), CUnsignedLongLong(passwd.count)) == 0
    }

    open func hash(_ outputLength: Int, passwd: Data, salt: Data, opsLimit: Int, memLimit: Int) -> Data? {
        if salt.count != SaltBytes {
            return nil
        }
        guard let output = NSMutableData(length: outputLength) else {
            return nil
        }
        if crypto_pwhash(output.mutableBytesPtr(), CUnsignedLongLong(outputLength), passwd.bytesPtr(), CUnsignedLongLong(passwd.count), salt.bytesPtr(), CUnsignedLongLong(opsLimit), size_t(memLimit), crypto_pwhash_ALG_DEFAULT) != 0 {
            return nil
        }
        return output as Data
    }

    open var scrypt = SCrypt()

    open class SCrypt {
        open let SaltBytes = Int(crypto_pwhash_scryptsalsa208sha256_saltbytes())
        open let StrBytes = Int(crypto_pwhash_scryptsalsa208sha256_strbytes()) - (1 as Int)
        open let StrPrefix = String.init(validatingUTF8: crypto_pwhash_scryptsalsa208sha256_strprefix())
        open let OpsLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
        open let OpsLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
        open let MemLimitInteractive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
        open let MemLimitSensitive = Int(crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())

        open func str(_ passwd: Data, opsLimit: Int, memLimit: Int) -> String? {
            guard let output = NSMutableData(length: StrBytes) else {
                return nil
            }
            if crypto_pwhash_scryptsalsa208sha256_str(output.mutableBytesPtr(), passwd.bytesPtr(), CUnsignedLongLong(passwd.count), CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
                return nil
            }
            return NSString(data: output as Data, encoding: String.Encoding.utf8.rawValue) as String?
        }

        open func strVerify(_ hash: String, passwd: Data) -> Bool {
            guard let hashData = (hash + "\0").data(using: String.Encoding.utf8, allowLossyConversion: false) else {
                return false
            }
            return crypto_pwhash_scryptsalsa208sha256_str_verify(hashData.bytesPtr(), passwd.bytesPtr(), CUnsignedLongLong(passwd.count)) == 0
        }

        open func hash(_ outputLength: Int, passwd: Data, salt: Data, opsLimit: Int, memLimit: Int) -> Data? {
            if salt.count != SaltBytes {
                return nil
            }
            guard let output = NSMutableData(length: outputLength) else {
                return nil
            }
            if crypto_pwhash_scryptsalsa208sha256(output.mutableBytesPtr(), CUnsignedLongLong(outputLength), passwd.bytesPtr(), CUnsignedLongLong(passwd.count), salt.bytesPtr(), CUnsignedLongLong(opsLimit), size_t(memLimit)) != 0 {
                return nil
            }
            return output as Data
        }
    }
}
