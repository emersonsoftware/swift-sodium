//
//  Sodium.swift
//  Sodium
//
//  Created by Frank Denis on 12/27/14.
//  Copyright (c) 2014 Frank Denis. All rights reserved.
//

import Foundation

open class Sodium {
    open var box = Box()
    open var secretBox = SecretBox()
    open var genericHash = GenericHash()
    open var pwHash = PWHash()
    open var randomBytes = RandomBytes()
    open var shortHash = ShortHash()
    open var sign = Sign()
    open var utils = Utils()
    
    public init?() {
        struct Once {
            static var once : () = {
                if sodium_init() == -1 {
                    abort()
                }
            }()
        }
    }
}
