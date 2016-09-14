//
//  Box.swift
//  Sodium
//
//  Created by Frank Denis on 12/28/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class Box {
    open let SeedBytes = Int(crypto_box_seedbytes())
    open let PublicKeyBytes = Int(crypto_box_publickeybytes())
    open let SecretKeyBytes = Int(crypto_box_secretkeybytes())
    open let NonceBytes = Int(crypto_box_noncebytes())
    open let MacBytes = Int(crypto_box_macbytes())
    open let Primitive = String.init(validatingUTF8:crypto_box_primitive())
    open let BeforenmBytes = Int(crypto_box_beforenmbytes())
    open let SealBytes = Int(crypto_box_sealbytes())
    
    public typealias PublicKey = Data
    public typealias SecretKey = Data
    public typealias Nonce = Data
    public typealias MAC = Data
    public typealias Beforenm = Data

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
        if crypto_box_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr()) != 0 {
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
        if crypto_box_seed_keypair(pk.mutableBytesPtr(), sk.mutableBytesPtr(), seed.bytesPtr()) != 0 {
            return nil
        }
        return KeyPair(publicKey: pk as PublicKey, secretKey: sk as SecretKey)
    }
    
    open func nonce() -> Nonce? {
        guard let nonce = NSMutableData(length: NonceBytes) else {
            return nil
        }
        randombytes_buf(nonce.mutableBytesPtr(), nonce.length)
        return nonce as Nonce
    }
    
    open func seal(_ message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message, recipientPublicKey: recipientPublicKey, senderSecretKey: senderSecretKey) else {
            return nil
        }
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce as Data)
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText as Data)
        return nonceAndAuthenticatedCipherText as Data
    }
    
    open func seal(_ message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if recipientPublicKey.count != PublicKeyBytes || senderSecretKey.count != SecretKeyBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.count + MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_easy(authenticatedCipherText.mutableBytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), nonce.bytesPtr(), recipientPublicKey.bytesPtr(), senderSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText as Data, nonce: nonce)
    }

    open func seal(_ message: Data, recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> (authenticatedCipherText: Data, nonce: Nonce, mac: MAC)? {
        if recipientPublicKey.count != PublicKeyBytes || senderSecretKey.count != SecretKeyBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.count) else {
            return nil
        }
        guard let mac = NSMutableData(length: MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_detached(authenticatedCipherText.mutableBytesPtr(), mac.mutableBytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), nonce.bytesPtr(), recipientPublicKey.bytesPtr(), senderSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText as Data, nonce: nonce as Nonce, mac: mac as MAC)
    }
    
    open func open(_ nonceAndAuthenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        if nonceAndAuthenticatedCipherText.count < NonceBytes + MacBytes {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes as Range<Int>) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count as Range<Int>) as Data
        return open(authenticatedCipherText, senderPublicKey: senderPublicKey, recipientSecretKey: recipientSecretKey, nonce: nonce)
    }
    
    open func open(_ authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> Data? {
        if nonce.count != NonceBytes || authenticatedCipherText.count < MacBytes {
            return nil
        }
        if senderPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.count - MacBytes) else {
            return nil
        }
        if crypto_box_open_easy(message.mutableBytesPtr(), authenticatedCipherText.bytesPtr(), CUnsignedLongLong(authenticatedCipherText.count), nonce.bytesPtr(), senderPublicKey.bytesPtr(), recipientSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }
    
    open func open(_ authenticatedCipherText: Data, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce, mac: MAC) -> Data? {
        if nonce.count != NonceBytes || mac.count != MacBytes {
            return nil
        }
        if senderPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.count) else {
            return nil
        }
        if crypto_box_open_detached(message.mutableBytesPtr(), authenticatedCipherText.bytesPtr(), mac.bytesPtr(), CUnsignedLongLong(authenticatedCipherText.count), nonce.bytesPtr(), senderPublicKey.bytesPtr(), recipientSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }
    
    open func beforenm(_ recipientPublicKey: PublicKey, senderSecretKey: SecretKey) -> Data? {
        let key = NSMutableData(length: BeforenmBytes)
        if crypto_box_beforenm(key!.mutableBytesPtr(), recipientPublicKey.bytesPtr(), senderSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return key as Data?
    }
    
    open func seal(_ message: Data, beforenm: Beforenm) -> (authenticatedCipherText: Data, nonce: Nonce)? {
        if beforenm.count != BeforenmBytes {
            return nil
        }
        guard let authenticatedCipherText = NSMutableData(length: message.count + MacBytes) else {
            return nil
        }
        guard let nonce = self.nonce() else {
            return nil
        }
        if crypto_box_easy_afternm(authenticatedCipherText.mutableBytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), nonce.bytesPtr(), beforenm.bytesPtr()) != 0 {
            return nil
        }
        return (authenticatedCipherText: authenticatedCipherText as Data, nonce: nonce)
    }
    
    open func open(_ nonceAndAuthenticatedCipherText: Data, beforenm: Beforenm) -> Data? {
        if nonceAndAuthenticatedCipherText.count < NonceBytes + MacBytes {
            return nil
        }
        let nonce = nonceAndAuthenticatedCipherText.subdata(in: 0..<NonceBytes as Range<Int>) as Nonce
        let authenticatedCipherText = nonceAndAuthenticatedCipherText.subdata(in: NonceBytes..<nonceAndAuthenticatedCipherText.count as Range<Int>) as Data
        return  open(authenticatedCipherText, beforenm: beforenm, nonce: nonce)
    }

    open func open(_ authenticatedCipherText: Data, beforenm: Beforenm, nonce: Nonce) -> Data? {
        if nonce.count != NonceBytes || authenticatedCipherText.count < MacBytes {
            return nil
        }
        if beforenm.count != BeforenmBytes {
            return nil
        }
        guard let message = NSMutableData(length: authenticatedCipherText.count - MacBytes) else {
            return nil
        }
        if crypto_box_open_easy_afternm(message.mutableBytesPtr(), authenticatedCipherText.bytesPtr(), CUnsignedLongLong(authenticatedCipherText.count), nonce.bytesPtr(), beforenm.bytesPtr()) != 0 {
            return nil
        }
        return message as Data
    }

    open func seal(_ message: Data, beforenm: Beforenm) -> Data? {
        guard let (authenticatedCipherText, nonce): (Data, Nonce) = seal(message, beforenm: beforenm) else {
            return nil
        }
        let nonceAndAuthenticatedCipherText = NSMutableData(data: nonce as Data)
        nonceAndAuthenticatedCipherText.append(authenticatedCipherText as Data)
        return nonceAndAuthenticatedCipherText as Data
    }
    
    open func seal(_ message: Data, recipientPublicKey: Box.PublicKey) -> Data? {
        if recipientPublicKey.count != PublicKeyBytes {
            return nil
        }
        guard let anonymousCipherText = NSMutableData(length: SealBytes + message.count) else {
            return nil
        }
        if crypto_box_seal(anonymousCipherText.mutableBytesPtr(), message.bytesPtr(), CUnsignedLongLong(message.count), recipientPublicKey.bytesPtr()) != 0 {
            return nil
        }
        return anonymousCipherText as Data
    }
    
    open func open(_ anonymousCipherText: Data, recipientPublicKey: PublicKey, recipientSecretKey: SecretKey) -> Data? {
        if recipientPublicKey.count != PublicKeyBytes || recipientSecretKey.count != SecretKeyBytes || anonymousCipherText.count < SealBytes {
            return nil
        }
        let message = NSMutableData(length: anonymousCipherText.count - SealBytes)
        if message == nil {
            return nil
        }
        if crypto_box_seal_open(message!.mutableBytesPtr(), anonymousCipherText.bytesPtr(), CUnsignedLongLong(anonymousCipherText.count), recipientPublicKey.bytesPtr(), recipientSecretKey.bytesPtr()) != 0 {
            return nil
        }
        return message as Data?
    }
}
