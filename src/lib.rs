// Copyright 2020 David Egan
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0

//! # Hex Utilties
//!
//! hex_utilities is a crate that contains (wait for it) hex utilities.
//! Utilties for converting bytes into hexadecimal strings and vice versa.

#![allow(dead_code)]

use core::fmt;

pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl<T: fmt::LowerHex> ToHex for T {
    fn to_hex(&self) -> String {
        format!("{:x}", self)
    }
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        use core::fmt::Write;
        let mut ret = String::with_capacity(2 * self.len());

        for ch in self {
            write!(ret, "{:02x}", ch).expect("writing to string");
        }
        ret
    }
}

/// Return an integer from a hex character.
fn hex_char_to_int(c: char) -> Result<u8, &'static str> {
    let digit: u8 = c.to_ascii_lowercase() as u8;
    if digit >= '0' as u8 && digit <= '9' as u8 {
        return Ok(digit - ('0' as u8))
    } else if digit >= 'a' as u8 && digit <= 'f' as u8 {
        return Ok(digit - ('1' as u8) - ('0' as u8) + 10)
    }
    Err("Invalid character in hexstring.")
} 

/// Makes a vector of bytes from a valid hexstring.
/// Walks through characters pairwise - for each pair, the leftmost char
/// represents a factor of 16. The rightmost byte represents units.
/// Therefore (L * 16) + R is equal to the integer value of the 
/// byte represented by the LR pair of hexadecimal digits.
pub fn hexstring_to_bytes(str: String) -> Result<Vec<u8>, &'static str> {
    if str.len() % 2 != 0 {
        return Err("Wrong size hexstring.");
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut current_byte: u8;
    for (i, c) in str.chars().step_by(2).enumerate() {
        current_byte = hex_char_to_int(c).unwrap() * 16;
        current_byte += hex_char_to_int(str.chars().nth(i * 2 + 1).unwrap()).unwrap();
        bytes.push(current_byte);
    }
    Ok(bytes)
}

/// Return a hexstring representation of a slice of bytes
pub fn bytes_to_hexstring(bytes: &[u8], form: Option<&str>) -> String {
    let mut caps = false;
    if let Some(f) = form {
        if f == "X" {
            caps = true;
        } 
    }

    let mut result: String = "".to_string();
    for el in bytes {
        let s = match caps {
            false => format!("{:02x}", el),
            true => format!("{:02X}", el),
        };
        result.push_str(&s);
    }
    return result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_capital_hexstring() {
        let ans: String = "DEADBEEF".to_string();
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(ans, bytes_to_hexstring(&bytes, Some("X")));
    }

    #[test]
    fn test_trait_extension() {
        let ans: String = "64617262".to_string();
        let bytes = vec![0x64, 0x61, 0x72, 0x62];
        assert_eq!(ans, bytes.to_hex());
    }
}
