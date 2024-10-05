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

use hashbrown::HashMap;
use nom::{
    number::complete::{be_u16, be_u8},
    IResult,
};

use alloc::{vec, vec::Vec};
use core::fmt;

/// Key-value mapping
#[derive(Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Key
    key: Str,

    /// Value.
    value: Str,
}

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
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

    /// Parse multiple [`Mapping`]s from `input`.
    pub fn parse_multi_frame(input: &[u8]) -> IResult<&[u8], Vec<Mapping>> {
        if input.is_empty() {
            return Ok((&[], Vec::new()));
        }

        let (mut rest, mut num_option_bytes) = be_u16(input)?;
        let mut options = Vec::<Mapping>::new();

        while num_option_bytes > 0 {
            let (_rest, mapping) = Mapping::parse_frame(rest)?;
            rest = _rest;

            num_option_bytes = num_option_bytes.saturating_sub(mapping.serialized_len() as u16);
            options.push(mapping);
        }

        Ok((rest, options))
    }

    /// Try to convert `bytes` into a [`Mapping`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Mapping> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to inner key-value mapping.
    pub fn mapping(&self) -> (&Str, &Str) {
        (&self.key, &self.value)
    }

    /// Get serialized length of [`Mapping`].
    pub fn serialized_len(&self) -> usize {
        self.key.serialized_len() + self.value.serialized_len() + 2
    }

    /// Convert a vector of [`Mapping`]s into a hashmap.
    pub fn into_hashmap(mappings: Vec<Mapping>) -> HashMap<Str, Str> {
        mappings.into_iter().map(|mapping| (mapping.key, mapping.value)).collect()
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
        let mapping = Mapping::new(Str::from("hello"), Str::from("world")).serialize();

        assert_eq!(
            Mapping::from_bytes(mapping),
            Some(Mapping {
                key: Str::from("hello"),
                value: Str::from("world"),
            })
        );
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut mapping = Mapping::new(Str::from("hello"), Str::from("world")).serialize();
        mapping.push(1);
        mapping.push(2);
        mapping.push(3);
        mapping.push(4);

        assert_eq!(
            Mapping::from_bytes(mapping),
            Some(Mapping {
                key: Str::from("hello"),
                value: Str::from("world"),
            })
        );
    }

    #[test]
    fn extra_bytes_returned() {
        let mut mapping = Mapping::new(Str::from("hello"), Str::from("world")).serialize();
        mapping.push(1);
        mapping.push(2);
        mapping.push(3);
        mapping.push(4);

        let (rest, mapping) = Mapping::parse_frame(&mapping).unwrap();

        assert_eq!(
            mapping,
            Mapping {
                key: Str::from("hello"),
                value: Str::from("world"),
            }
        );
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn multiple_mappings() {
        let mut mapping1 = Mapping::new(Str::from("hello"), Str::from("world")).serialize();
        let mapping2 = Mapping::new(Str::from("foo"), Str::from("bar")).serialize();
        let mapping3 = Mapping::new(Str::from("siip"), Str::from("huup")).serialize();

        mapping1.extend_from_slice(&mapping2);
        mapping1.extend_from_slice(&mapping3);

        let (rest, mapping) = Mapping::parse_frame(&mapping1).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::from("hello"),
                value: Str::from("world"),
            }
        );

        let (rest, mapping) = Mapping::parse_frame(rest).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::from("foo"),
                value: Str::from("bar"),
            }
        );

        let (rest, mapping) = Mapping::parse_frame(rest).unwrap();
        assert_eq!(
            mapping,
            Mapping {
                key: Str::from("siip"),
                value: Str::from("huup"),
            }
        );
    }

    #[test]
    fn parse_multi_frame() {
        let mapping1 = Mapping::new(Str::from("hello"), Str::from("world")).serialize();
        let mapping2 = Mapping::new(Str::from("foo"), Str::from("bar")).serialize();
        let mapping3 = Mapping::new(Str::from("siip"), Str::from("huup")).serialize();

        let mut mappings = ((mapping1.len() + mapping2.len() + mapping3.len()) as u16)
            .to_be_bytes()
            .to_vec();

        mappings.extend_from_slice(&mapping1);
        mappings.extend_from_slice(&mapping2);
        mappings.extend_from_slice(&mapping3);

        let (rest, mappings) = Mapping::parse_multi_frame(&mappings).unwrap();

        assert!(rest.is_empty());
        assert_eq!(mappings.len(), 3);

        assert_eq!(
            mappings[0],
            Mapping {
                key: Str::from("hello"),
                value: Str::from("world"),
            }
        );
        assert_eq!(
            mappings[1],
            Mapping {
                key: Str::from("foo"),
                value: Str::from("bar"),
            }
        );
        assert_eq!(
            mappings[2],
            Mapping {
                key: Str::from("siip"),
                value: Str::from("huup"),
            }
        );
    }
}
