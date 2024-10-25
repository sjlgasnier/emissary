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

use hashbrown::HashMap;
use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0},
    combinator::{map, opt, recognize},
    error::{make_error, ErrorKind},
    multi::{many0, many0_count},
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    Err, IResult, Parser,
};

use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::parser";

/// Parsed command.
///
/// Represent a command that had value form but isn't necessarily
/// a command that `yosemite` recognizes.
struct ParsedCommand<'a> {
    /// Command
    ///
    /// Supported values: `HELLO`, `STATUS` and `STREAM`.
    command: &'a str,

    /// Subcommand.
    ///
    /// Supported values: `REPLY` for `HELLO`, `STATUS` for `SESSION`/`STREAM`.
    subcommand: Option<&'a str>,

    /// Parsed key-value pairs.
    key_value_pairs: HashMap<&'a str, &'a str>,
}

/// Supported SAM versions.
#[derive(Debug, PartialEq, Eq)]
pub enum SamVersion {
    /// v3.1
    V31,

    /// V3.2
    V32,

    /// V3.3
    V33,
}

impl TryFrom<&str> for SamVersion {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "3.1" => Ok(SamVersion::V31),
            "3.2" => Ok(SamVersion::V32),
            "3.3" => Ok(SamVersion::V33),
            _ => Err(()),
        }
    }
}

impl fmt::Display for SamVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V31 => write!(f, "3.1"),
            Self::V32 => write!(f, "3.2"),
            Self::V33 => write!(f, "3.3"),
        }
    }
}

/// SAMv3 commands received from the client.
#[derive(Debug, PartialEq, Eq)]
pub enum SamCommand {
    /// `HELLO VERSION` message.
    Hello {
        /// Minimum supported version, if specified.
        min: Option<SamVersion>,

        /// Maximum supported version, if specified.
        max: Option<SamVersion>,
    },
}

impl<'a> TryFrom<ParsedCommand<'a>> for SamCommand {
    type Error = ();

    fn try_from(value: ParsedCommand<'a>) -> Result<Self, Self::Error> {
        match (value.command, value.subcommand) {
            ("HELLO", Some("VERSION")) => Ok(Self::Hello {
                min: value
                    .key_value_pairs
                    .get("MIN")
                    .map(|value| SamVersion::try_from(*value).ok())
                    .flatten(),
                max: value
                    .key_value_pairs
                    .get("MAX")
                    .map(|value| SamVersion::try_from(*value).ok())
                    .flatten(),
            }),
            (command, subcommand) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %command,
                    ?subcommand,
                    "unrecognized command",
                );

                Err(())
            }
        }
    }
}

impl SamCommand {
    /// Attempt to parse `input` into `Response`.
    //
    // Non-public method returning `IResult` for cleaner error handling.
    fn parse_inner(input: &str) -> IResult<&str, Self> {
        let (rest, (command, _, subcommand, _, key_value_pairs)) = tuple((
            alt((tag("HELLO"), tag("SESSION"), tag("STREAM"))),
            opt(char(' ')),
            opt(alt((tag("VERSION"), tag("STATUS")))),
            opt(char(' ')),
            opt(parse_key_value_pairs),
        ))(input)?;

        Ok((
            rest,
            SamCommand::try_from(ParsedCommand {
                command,
                subcommand,
                key_value_pairs: key_value_pairs.unwrap_or(HashMap::new()),
            })
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
        ))
    }

    /// Attempt to parse `input` into `Response`.
    pub fn parse(input: &str) -> Option<Self> {
        Some(Self::parse_inner(input).ok()?.1)
    }
}

fn parse_key_value_pairs(input: &str) -> IResult<&str, HashMap<&str, &str>> {
    let (input, key_value_pairs) = many0(preceded(multispace0, parse_key_value))(input)?;
    Ok((input, key_value_pairs.into_iter().collect()))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(parse_key, char('='), parse_value)(input)
}

fn parse_key(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))
    .parse(input)
}

fn parse_value(input: &str) -> IResult<&str, &str> {
    alt((
        parse_quoted_value,
        map(take_while1(|c: char| !c.is_whitespace()), |s: &str| s),
    ))(input)
}

fn parse_quoted_value(input: &str) -> IResult<&str, &str> {
    delimited(
        char('"'),
        escaped(is_not("\\\""), '\\', alt((tag("\""), tag("\\")))),
        char('"'),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hello() {
        // min and max are the same
        match SamCommand::parse("HELLO VERSION MIN=3.3 MAX=3.3") {
            Some(SamCommand::Hello {
                min: Some(SamVersion::V33),
                max: Some(SamVersion::V33),
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // no version defined
        match SamCommand::parse("HELLO VERSION") {
            Some(SamCommand::Hello {
                min: None,
                max: None,
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // invalid subcommand
        assert!(SamCommand::parse("HELLO REPLY").is_none());
    }

    #[test]
    fn unrecognized_command() {
        assert!(SamCommand::parse("TEST COMMAND KEY=VALUE").is_none());
    }
}
