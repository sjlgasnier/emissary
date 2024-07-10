// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// TODO: dx of `Str` needs a lot of work!

use crate::{primitives::LOG_TARGET, Error};

use nom::{bytes::complete::take, number::complete::be_u8, IResult};

use alloc::{vec, vec::Vec};
use core::{fmt, str::FromStr};

/// String.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Str {
    /// String as byte vector.
    string: Vec<u8>,
}

impl fmt::Display for Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", core::str::from_utf8(&self.string).unwrap_or("..."))
    }
}

impl FromStr for Str {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 255 {
            tracing::warn!(
                target: LOG_TARGET,
                len = ?s.len(),
                "string is too large",
            );
            return Err(Error::InvalidData);
        }

        Ok(Str {
            string: s.as_bytes().to_vec(),
        })
    }
}

impl Str {
    /// Create new [`Str`].
    pub fn new(string: Vec<u8>) -> Self {
        Self { string }
    }

    /// Serialize [`Str`] into a byte vector.
    pub fn serialize(self) -> Vec<u8> {
        let mut out = vec![0u8; self.string.len() + 1];

        out[0] = self.string.len() as u8;
        out[1..].copy_from_slice(&self.string);

        out
    }

    /// Parse [`Str`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Str> {
        let (rest, size) = be_u8(input)?;
        let (rest, string) = take(size)(rest)?;

        Ok((
            rest,
            Str {
                string: string.to_vec(),
            },
        ))
    }

    /// Try to convert `bytes` into a [`Str`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Str> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to inner string.
    pub fn string(&self) -> &[u8] {
        &self.string
    }

    /// Get length of inner string.
    pub fn len(&self) -> usize {
        self.string.len()
    }

    /// Get serialized length of [`Str`].
    pub fn serialized_len(&self) -> usize {
        self.string.len() + 1
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use nom::AsBytes;

    use super::*;

    #[test]
    fn empty_string() {
        assert!(Str::from_bytes(Vec::new()).is_none());
    }

    #[test]
    fn valid_string() {
        let mut string: VecDeque<u8> = String::from("hello, world!")
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();
        string.push_front(string.len() as u8);
        let string: Vec<u8> = string.into();

        assert_eq!(
            Str::from_bytes(string),
            Some(Str {
                string: String::from("hello, world!").as_bytes().to_vec()
            })
        );
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut string: VecDeque<u8> = String::from("hello, world!")
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();
        string.push_front(string.len() as u8);
        string.push_back(1);
        string.push_back(2);
        string.push_back(3);
        string.push_back(4);
        let string: Vec<u8> = string.into();

        assert_eq!(
            Str::from_bytes(string),
            Some(Str {
                string: String::from("hello, world!").as_bytes().to_vec()
            })
        );
    }

    #[test]
    fn extra_bytes_returned() {
        let mut string: VecDeque<u8> = String::from("hello, world!")
            .as_bytes()
            .to_vec()
            .try_into()
            .unwrap();
        string.push_front(string.len() as u8);
        string.push_back(1);
        string.push_back(2);
        string.push_back(3);
        string.push_back(4);
        let string: Vec<u8> = string.into();

        let (rest, string) = Str::parse_frame(&string).unwrap();

        assert_eq!(
            string,
            Str {
                string: String::from("hello, world!").as_bytes().to_vec()
            }
        );
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn serialize_works() {
        let bytes = Str::new("hello, world!".as_bytes().to_vec()).serialize();

        assert_eq!(
            Str::from_bytes(bytes),
            Some(Str {
                string: "hello, world!".as_bytes().to_vec()
            })
        );
    }
}
