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

use nom::{number::complete::be_u64, IResult};

/// Date.
#[derive(Debug, PartialEq, Eq)]
pub struct Date {
    /// Date in milliseconds UNIX epoch.
    date: u64,
}

impl Date {
    /// Parse [`Date`] from `input`, returning rest of `input` and parsed date.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Date> {
        let (rest, date) = be_u64(input)?;

        Ok((rest, Date { date }))
    }

    /// Try to convert `bytes` into a [`Date`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Date> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get reference to inner date.
    pub fn date(&self) -> &u64 {
        &self.date
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_date() {
        let time = 1719940343u64;
        let time = time.to_be_bytes();

        assert_eq!(
            Date::from_bytes(time),
            Some(Date {
                date: 1719940343u64
            })
        );
    }

    #[test]
    fn valid_date_with_extra_bytes() {
        let time = 1719940343u64;
        let mut time = time.to_be_bytes().to_vec();
        time.push(1);
        time.push(2);
        time.push(3);
        time.push(4);

        assert_eq!(
            Date::from_bytes(time),
            Some(Date {
                date: 1719940343u64
            })
        );
    }

    #[test]
    fn extra_bytes_returned() {
        let time = 1719940343u64;
        let mut time = time.to_be_bytes().to_vec();
        time.push(1);
        time.push(2);
        time.push(3);
        time.push(4);

        let (rest, date) = Date::parse_frame(&time).unwrap();

        assert_eq!(
            date,
            Date {
                date: 1719940343u64
            }
        );
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn empty_date() {
        assert!(Date::from_bytes(Vec::<u8>::new()).is_none());
    }

    #[test]
    fn incomplete_date() {
        for i in 0..7 {
            let empty = vec![1 as u8; i];
            assert!(Date::from_bytes(empty).is_none());
        }
    }
}
