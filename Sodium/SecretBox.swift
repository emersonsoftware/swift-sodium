//
//  SecretBox.swift
//  Sodium
//
//  Created by Devin Chalmers on 1/4/15.
//  Copyright (c) 2015 Frank Denis. All rights reserved.
//

import Foundation

open class SecretBox {
    open let KeyBytes = Int(crypto_secretbox_keybytes())
    open let NonceBytes = Int(crypto_secretbox_noncebytes())
    open let MacBytes = Int(crypto_secretbox_macbytes())
    
    public typealias Key = Data
    public typealias Nonce = Data
    public typealias MAC = Data
    
    open func key() -> Key? {
        guard let k = NSMutableData(length: KeyBytes) else {
            return nil
        }
        randombytes_buf(k.mutableBytesPtr(), k.length)
        return k as SecretBox.Key
    }
    
    open func nonce() -> Nonce? {
        guard let n = NSMutableData(length: NonceBytes) else {
            return nil
        }
        randombytes_buf(n.mutableBytesPtr(), n.length)
        return n as SecretBox.Nonce
    }
    
    open func seal(_ message: Data, secretKey: Key) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message, secretKey: secretKey) else {
            return nil
        }
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce as Data)
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText as Data)
        return nonceAndAuthenticatedCipherText as Data
    }
    
    open func seal(_ message: Data, secretKey: Key) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if secretKey.count != KeyBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.count + MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_secretbox_easy(authenticatedCipherText.mutableBytesPtr(), message.bytesPtr(), UInt64(message.count), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText as Data, nonce: nonce)
    }
    
    open func seal(_ message: Data, secretKey: Key) -> (cipherText: Data, nonce: Nonce, mac: MAC)? {
        if secretKey.count != KeyBytes {
            return nil
        }
        guard let cipherText = NSMutableData(length: message.count) else {
            return nil
        }
        guard let mac = NSMutableData(length: MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_secretbox_detached(cipherText.mutableBytesPtr(), mac.mutableBytesPtr(), message.bytesPtr(), UInt64(message.count), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return (cipherText: cipherText as Data, nonce: nonce, mac: mac as SecretBox.MAC)
    }
    
    open func open(_ nonceAndAuthenticatedCipherText: Data, secretKey: Key) -> Data? {
        if nonceAndAuthenticatedCipherText.count < MacBytes + NonceBytes {
            return nil
        }
        guard let _ = NSMutableData(length: nonceAndAuthenticatedCipherText.count - MacBytes - NonceBytes) else {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes as Range<Int>) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count as Range<Int>) as Data
        return open(authenticatedCipherText, secretKey: secretKey, nonce: nonce)
    }
    
    open func open(_ authenticatedCipherText: Data, secretKey: Key, nonce: Nonce) -> Data? {
        if authenticatedCipherText.count < MacBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.count - MacBytes) else {
            return nil
        }
        if crypto_secretbox_open_easy(message.mutableBytesPtr(), authenticatedCipherText.bytesPtr(), UInt64(authenticatedCipherText.count), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }
    
    open func open(_ cipherText: Data, secretKey: Key, nonce: Nonce, mac: MAC) -> Data? {
        if nonce.count != NonceBytes || mac.count != MacBytes {
            return nil
        }
        if secretKey.count != KeyBytes {
            return nil
        }
        guard let message = NSMutableData(length: cipherText.count) else {
            return nil
        }
        if crypto_secretbox_open_detached(message.mutableBytesPtr(), cipherText.bytesPtr(), mac.bytesPtr(), UInt64(cipherText.count), nonce.bytesPtr(), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }
}
