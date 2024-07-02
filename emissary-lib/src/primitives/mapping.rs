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

use crate::primitives::Str;

use nom::{
    bytes::complete::{take, take_till1, take_until},
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u64, be_u8},
    sequence::tuple,
    Err, IResult,
};

/// Key-value mapping
#[derive(Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Key
    key: Str,

    /// Value.
    value: Str,
}

impl Mapping {
    /// Create new [`Mapping`].
    pub fn new(key: Str, value: Str) -> Self {
        Self { key, value }
    }

    /// Serialize [`Mapping`] into a byte vector.
    pub fn serialize(self) -> Vec<u8> {
        let key = self.key.serialize();
        let value = self.value.serialize();

        // key length + value length + length field + `=` + `;`
        let size = key.len() + value.len() + 2;
        let mut out = vec![0u8; size];

        out[..key.len()].copy_from_slice(&key);
        out[key.len()] = '=' as u8;
        out[1 + key.len()..1 + key.len() + value.len()].copy_from_slice(&value);
        out[1 + key.len() + value.len()] = ';' as u8;

        out
    }

    /// Parse [`Mapping`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Mapping> {
        let (rest, key) = Str::parse_frame(input)?;
        let (rest, _) = be_u8(rest)?; // ignore `=`
        let (rest, value) = Str::parse_frame(rest)?;
        let (rest, _) = be_u8(rest)?; // ignore `;`

        Ok((rest, Mapping { key, value }))
    }

    /// Try to convert `bytes` into a [`Mapping`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Mapping> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to inner key-value mapping.
    pub fn mapping(&self) -> (&Str, &Str) {
        (&self.key, &self.value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn empty_mapping() {
        assert!(Str::from_bytes(Vec::new()).is_none());
    }

    #[test]
    fn valid_mapping() {
        let mapping = Mapping::new(
            Str::new("hello".as_bytes().to_vec()),
            Str::new("world".as_bytes().to_vec()),
        )
        .serialize();

        assert_eq!(
            Mapping::from_bytes(mapping),
            Some(Mapping {
                key: Str::new("hello".as_bytes().to_vec()),
                value: Str::new("world".as_bytes().to_vec()),
            })
        );
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut mapping = Mapping::new(
            Str::new("hello".as_bytes().to_vec()),
            Str::new("world".as_bytes().to_vec()),
        )
        .serialize();
        mapping.push(1);
        mapping.push(2);
        mapping.push(3);
        mapping.push(4);

        assert_eq!(
            Mapping::from_bytes(mapping),
            Some(Mapping {
                key: Str::new("hello".as_bytes().to_vec()),
                value: Str::new("world".as_bytes().to_vec()),
            })
        );
    }

    #[test]
    fn extra_bytes_returned() {
        let mut mapping = Mapping::new(
            Str::new("hello".as_bytes().to_vec()),
            Str::new("world".as_bytes().to_vec()),
        )
        .serialize();
        mapping.push(1);
        mapping.push(2);
        mapping.push(3);
        mapping.push(4);

        let (rest, mapping) = Mapping::parse_frame(&mapping).unwrap();

        assert_eq!(
            mapping,
            Mapping {
                key: Str::new("hello".as_bytes().to_vec()),
                value: Str::new("world".as_bytes().to_vec()),
            }
        );
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn multiple_mappings() {
        let mut mapping1 = Mapping::new(
            Str::new("hello".as_bytes().to_vec()),
            Str::new("world".as_bytes().to_vec()),
        )
        .serialize();
        let mapping2 = Mapping::new(
            Str::new("foo".as_bytes().to_vec()),
            Str::new("bar".as_bytes().to_vec()),
        )
        .serialize();
        let mapping3 = Mapping::new(
            Str::new("siip".as_bytes().to_vec()),
            Str::new("huup".as_bytes().to_vec()),
        )
        .serialize();

        mapping1.extend_from_slice(&mapping2);
        mapping1.extend_from_slice(&mapping3);

        let (rest, mapping) = Mapping::parse_frame(&mapping1).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::new("hello".as_bytes().to_vec()),
                value: Str::new("world".as_bytes().to_vec()),
            }
        );

        let (rest, mapping) = Mapping::parse_frame(rest).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::new("foo".as_bytes().to_vec()),
                value: Str::new("bar".as_bytes().to_vec()),
            }
        );

        let (rest, mapping) = Mapping::parse_frame(rest).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::new("siip".as_bytes().to_vec()),
                value: Str::new("huup".as_bytes().to_vec()),
            }
        );
    }
}
