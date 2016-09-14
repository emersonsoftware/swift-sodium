//
//  Sign.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class Sign {
    open let SeedBytes = Int(crypto_sign_seedbytes())
    open let PublicKeyBytes = Int(crypto_sign_publickeybytes())
    open let SecretKeyBytes = Int(crypto_sign_secretkeybytes())
    open let Bytes = Int(crypto_sign_bytes())
    open let Primitive = String.init(validatingUTF8:crypto_sign_primitive())
    
    public typealias PublicKey = Data
    public typealias SecretKey = Data
    
    public struct KeyPair {
        public let publicKey: PublicKey
        public let secretKey: SecretKey

        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
    
    open func keyPair() -> KeyPair? {
        guard let pk = NSMutableData(length: PublicKeyBytes) else {
            return nil
        }
        guard let sk = NSMutableData(length: SecretKeyBytes) else {
            return nil
        }
        if crypto_sign_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr()) != 0 {
            return nil
        }
        return KeyPair(publicKey: pk as PublicKey, secretKey: sk as SecretKey)
    }
    
    open func keyPair(_ seed: Data) -> KeyPair? {
        if seed.count != SeedBytes {
            return nil
        }
        guard let pk = NSMutableData(length: PublicKeyBytes) else {
            return nil
        }
        guard let sk = NSMutableData(length: SecretKeyBytes) else {
            return nil
        }
        if crypto_sign_seed_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr(), seed.bytesPtr()) != 0 {
            return nil
        }
        return KeyPair(publicKey: pk as PublicKey, secretKey: sk as SecretKey)
    }
    
    open func sign(_ message: Data, secretKey: SecretKey) -> Data? {
        if secretKey.count != SecretKeyBytes {
            return nil
        }
        guard let signedMessage = NSMutableData(length: message.count + Bytes) else {
            return nil
        }
        if crypto_sign(signedMessage.mutableBytesPtr(), nil, message.bytesPtr(), CUnsignedLongLong(message.count), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return signedMessage as Data
    }

    open func signature(_ message: Data, secretKey: SecretKey) -> Data? {
        if secretKey.count != SecretKeyBytes {
            return nil
        }
        guard let signature = NSMutableData(length: Bytes) else {
            return nil
        }
        if crypto_sign_detached(signature.mutableBytesPtr(), nil, message.bytesPtr(), CUnsignedLongLong(message.count), secretKey.bytesPtr()) != 0 {
            return nil
        }
        return signature as Data
    }
    
    open func verify(_ signedMessage: Data, publicKey: PublicKey) -> Bool {
        let signature = signedMessage.subdata(in:0..<Bytes as Range<Int>) as Data
        let message = signedMessage.subdata(in: Bytes..<signedMessage.count as Range<Int>) as Data
        return verify(message, publicKey: publicKey, signature: signature)
    }
    
    open func verify(_ message: Data, publicKey: PublicKey, signature: Data) -> Bool {
        if publicKey.count != PublicKeyBytes {
            return false
        }
        return crypto_sign_verify_detached(signature.bytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), publicKey.bytesPtr()) == 0
    }
    
    open func open(_ signedMessage: Data, publicKey: PublicKey) -> Data? {
        if publicKey.count != PublicKeyBytes || signedMessage.count < Bytes {
            return nil
        }
        guard let message = NSMutableData(length: signedMessage.count - Bytes) else {
            return nil
        }
        var mlen: CUnsignedLongLong = 0;
        if crypto_sign_open(message.mutableBytesPtr(), &mlen, signedMessage.bytesPtr(), CUnsignedLongLong(signedMessage.count), publicKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }
}
