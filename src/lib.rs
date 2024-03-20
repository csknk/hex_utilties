// Copyright 2024 David Egan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! # Hex Utilities
//!
//! hex_utilities is a crate that contains (wait for it) hex utilities.
//! Utilties for converting bytes into hexadecimal strings and vice versa.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

use core::fmt;
use std::error;
use std::vec;

/// Define Errors
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StringError {
    /// Not a valid hex character
    InvalidHexChar(u8),
    /// Odd length - invalid
    InvalidStringLength(usize),
    /// Invalid base 64 character present
    InvalidBase64Char(u8),
    /// Wrong length for base 64 string
    InvalidBase64StringLength(usize),
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StringError::InvalidHexChar(c) => write!(f, "Invalid hex character: {}", c),
            StringError::InvalidStringLength(len) => write!(f, "Invalid hexstring length: {}", len),
            StringError::InvalidBase64Char(c) => write!(f, "Invalid base64 character: {}", c),
            StringError::InvalidBase64StringLength(len) => {
                write!(f, "Invalid base 64 length: {}", len)
            }
        }
    }
}
impl error::Error for StringError {}

/// An extension trait to allow collection objects to be represented as a hexadecimal string.
pub trait ToHexExt {
    /// Return a hexadecimal string representation
    fn to_hexstring(&self) -> String;
}

/// Implement extension trait for a generic type, with the fmt::LowerHex trait implemented on the type.
impl<T: fmt::LowerHex> ToHexExt for T {
    fn to_hexstring(&self) -> String {
        format!("{:x}", self)
    }
}

/// Implement the extension trait for a slice of u8
impl ToHexExt for [u8] {
    /// Return a hexadecimal String representation of the collection
    fn to_hexstring(&self) -> String {
        use core::fmt::Write;
        let mut ret = String::with_capacity(2 * self.len());

        for ch in self {
            write!(ret, "{:02x}", ch).expect("writing to string");
        }
        ret
    }
}

/// Implement the extension trait on Vec<u8>
//impl HexToBytesExt for Vec<u8> {
//    /// Bytes collection from e.g. String
//    fn to_bytes() -> Result<Self, Error> {
//        hexstring_to_bytes(Self)
//    }
//}

/// Return an integer from a hex character.
fn hex_char_to_int(c: char) -> Result<u8, &'static str> {
    let digit: u8 = c.to_ascii_lowercase() as u8;
    if digit >= '0' as u8 && digit <= '9' as u8 {
        return Ok(digit - ('0' as u8));
    } else if digit >= 'a' as u8 && digit <= 'f' as u8 {
        return Ok(digit - ('a' as u8) + 10);
    }
    Err("Invalid character in hexstring.")
}

/// Makes a vector of bytes from a valid hexstring. Walks through characters pairwise. For each pair, the
/// leftmost char represents a factor of 16. The rightmost char represents units. Therefore (L * 16) + R is
/// equal to the integer value of the byte represented by the LR pair of hexadecimal digits.
pub fn hexstring_to_bytes(str: String) -> Result<Vec<u8>, StringError> {
    if str.len() % 2 != 0 {
        return Err(StringError::InvalidStringLength(str.len()));
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

/// Returns false and an appropriate error if the provided String is either an odd length or
/// contains an invalid character
pub fn is_valid_hexstring(input: String) -> Result<bool, StringError> {
    if input.len() % 2 != 0 {
        return Err(StringError::InvalidStringLength(input.len()));
    }
    if let Err(err) = contains_allowed_hex_characters(input) {
        return Err(err);
    }

    Ok(true)
}

/// Returns false if any character in the provided string is not a valid hex character
pub fn contains_allowed_hex_characters(input: String) -> Result<bool, StringError> {
    let allowed_hex_chars: [u8; 22] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F', b'a', b'b', b'c', b'd', b'e', b'f',
    ];
    for c in input.chars() {
        let c_byte: u8 = c as u8;
        if !allowed_hex_chars.iter().any(|&x| c_byte == x) {
            return Err(StringError::InvalidHexChar(c_byte));
        }
    }
    Ok(true)
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

/// See: /home/david/Learning/c/radix-64-encoding/base64.c
pub fn bytes_to_b64(bytes: Vec<u8>) -> String {
    if bytes.len() == 0 {
        return "".to_string();
    }
    let encoding_table = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', // 7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', // 31
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', // 39
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', // 47
        'w', 'x', 'y', 'z', '0', '1', '2', '3', // 55
        '4', '5', '6', '7', '8', '9', '+', '/', // 63
    ];

    let mut buf = vec![];
    let mut carry_byte: u8 = 0; // = bytes[0] & (0xFF >> 6);
    let mut mask: u8; // = 0xFF << 2; // bitwise not (!) is same as ~ in c
    let mut divider: u8;
    let mut byte_index: u8 = 0;
    let mut lookup_index: u8;
    for byte in &bytes {
        divider = 6 - 2 * (byte_index % 3);
        lookup_index = carry_byte << divider;

        mask = !(0xFF >> divider);
        let mut most_sig_bits: u8 = byte & mask;
        most_sig_bits >>= 8 - divider;
        lookup_index ^= most_sig_bits; // combine the carried bits and the current bits
        buf.push(encoding_table[lookup_index as usize]);

        if divider == 2 {
            buf.push(encoding_table[(byte & (0xFF >> divider)) as usize]);
            carry_byte = 0;
        } else {
            carry_byte = byte & (0xFF >> divider);
        }
        byte_index += 1;
    }
    if carry_byte > 0 {
        divider = 6 - 2 * (byte_index % 3);
        carry_byte = carry_byte << divider;
        buf.push(encoding_table[carry_byte as usize]);
    }
    let output_len: usize = len_chars_base64(bytes.len());
    while buf.len() < output_len {
        buf.push('=');
    }
    let s: String = buf.into_iter().collect();
    return s;
}

/// returns the number of base 64 characters required to represent the given number of bytes
pub fn len_chars_base64(input_length: usize) -> usize {
    let ret: usize;
    if (input_length % 3) != 0 {
        ret = ((input_length / 3) + 1) * 4;
    } else {
        ret = (input_length / 3) * 4;
    }
    return ret;
}

/// returns a byte slice from the given base 64 string
pub fn b64_to_bytes(b64_string: String) -> Result<Vec<u8>, StringError> {
    let bytes = b64_string.into_bytes();
    for b in &bytes {
        println!("{:?}", b);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_to_bytes_test() {
        let _ = b64_to_bytes("david".to_string());
    }

    #[test]
    fn len_chars_base64_test() {
        let correct: [usize; 7] = [4, 4, 4, 8, 8, 8, 8];
        for n in 1..6 {
            assert_eq!(correct[n - 1], len_chars_base64(n));
        }
    }

    #[test]
    fn bytes_to_b64_test() {
        let test_vectors = vec![
            (vec![], ""),
            (vec![0x66], "Zg=="),
            (vec!['f' as u8, 'o' as u8], "Zm8="),
            (vec!['f' as u8, 'o' as u8, 'o' as u8], "Zm9v"),
            (vec!['f' as u8, 'o' as u8, 'o' as u8, 'b' as u8], "Zm9vYg=="),
            (
                vec!['f' as u8, 'o' as u8, 'o' as u8, 'b' as u8, 'a' as u8],
                "Zm9vYmE=",
            ),
            (
                vec![
                    'f' as u8, 'o' as u8, 'o' as u8, 'b' as u8, 'a' as u8, 'r' as u8,
                ],
                "Zm9vYmFy",
            ),
        ];
        for test in test_vectors {
            println!("compare test vec {:?} with result {}", test.0, test.1);
            assert_eq!(test.1.to_string(), bytes_to_b64(test.0))
        }
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!("3q2+7w==".to_string(), bytes_to_b64(bytes))
    }

    #[test]
    fn test_valid_hexstring() {
        assert_eq!(is_valid_hexstring("abcdef".to_string()), Ok(true));
    }

    #[test]
    fn test_invalid_length() {
        assert_eq!(
            is_valid_hexstring("abc".to_string()),
            Err(StringError::InvalidStringLength(3))
        );
    }

    #[test]
    fn test_invalid_characters() {
        assert_eq!(
            is_valid_hexstring("ghijkl".to_string()),
            Err(StringError::InvalidCharacter('g'))
        );
    }

    #[test]
    fn test_contains_allowed_hex_characters_valid_input() {
        let input = String::from("0123456789ABCDEFabcdef");
        assert_eq!(contains_allowed_hex_characters(input), Ok(true));
    }

    #[test]
    fn test_contains_allowed_hex_characters_invalid_input() {
        let input = String::from("G");
        assert_eq!(
            contains_allowed_hex_characters(input),
            Err(StringError::InvalidHexChar(b'G'))
        );
    }

    #[test]
    fn correct_hex_char_to_int_test() -> Result<(), String> {
        let test_string: &str = "0123456789aBcdEf";
        let correct_results = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        for (i, c) in test_string.chars().enumerate() {
            assert_eq!(correct_results[i], hex_char_to_int(c)?);
        }
        Ok(())
    }

    #[test]
    fn correct_capital_hexstring() {
        let ans: String = "DEADBEEF".to_string();
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(ans, bytes_to_hexstring(&bytes, Some("X")));
    }

    #[test]
    fn correct_trait_extension_bytes_to_hexstring() {
        let ans: String = "64617262".to_string();
        let bytes = vec![0x64, 0x61, 0x72, 0x62];
        assert_eq!(ans, bytes.to_hexstring());
    }

    #[test]
    fn correct_single_byte_to_hexstring() {
        let ans: String = "ff".to_string();
        let input_val: u8 = 255;
        let res = input_val.to_hexstring();
        assert_eq!(ans, res);
    }

    #[test]
    fn correct_hexstring_to_bytes() {
        let ans: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let bytes = hexstring_to_bytes("deadbeef".to_string()).unwrap();
        assert_eq!(ans, bytes);
    }

    #[test]
    fn wrong_length_hexstring() {
        assert_eq!(
            hexstring_to_bytes("deadbee".to_string()),
            Err(StringError::InvalidStringLength(7))
        );
    }
}
