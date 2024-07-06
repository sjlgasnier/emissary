use crate::error::Error;

use nom::{
    do_parse, named,
    number::streaming::{be_u16, be_u64, be_u8},
    switch, tag, take, value, AsBytes,
};

/// SU3 magic.
const SU3_MAGIC: &'static str = "I2Psu3";

/// Signature type.
#[derive(Debug, PartialEq)]
pub enum SignatureType {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    RsaSha256_2048,
    RsaSha384_3072,
    RsaSha512_4096,
    EdDsaSha512Ed25519ph,
}

/// File type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Zip,
    Xml,
    Html,
    XmlGz,
    TxtGz,
    Dmg,
    Exe,
}

/// Content type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    Unknown,
    RouterUpdate,
    PluginUpdate,
    ReseedData,
    NewsFeed,
    BlocklistFeed,
}

/// Software update.
pub struct Su3 {
    // Signature type.
    pub _sign_type: SignatureType,

    /// Signature length.
    pub _sign_len: u16,

    /// Version length.
    pub _version_len: u8,

    /// Signer ID length.
    pub _signer_id_len: u8,

    /// Content length.
    pub _content_len: u64,

    /// File type.
    pub file_type: FileType,

    /// Content type.
    pub content_type: ContentType,

    /// Version.
    pub _version: Vec<u8>,

    /// Signer ID.
    pub _signer_id: Vec<u8>,

    /// Content.
    pub content: Vec<u8>,

    /// Signature.
    pub _signature: Vec<u8>,
}

impl Su3 {
    /// Create [`Su3`] from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Su3> {
        parse_su3(bytes)
            .map(|(_, su3)| su3)
            .map_err(|error| Error::Custom(error.to_string()))
    }
}

named!(
    parse_su3<Su3>,
    do_parse!(
        tag!(SU3_MAGIC) >>
        take!(2u8)      >>
        sign_type: switch!(be_u16,
            0x00 => value!(SignatureType::DsaSha1) |
            0x01 => value!(SignatureType::EcdsaSha256P256) |
            0x02 => value!(SignatureType::EcdsaSha384P384) |
            0x03 => value!(SignatureType::EcdsaSha512P521) |
            0x04 => value!(SignatureType::RsaSha256_2048) |
            0x05 => value!(SignatureType::RsaSha384_3072) |
            0x06 => value!(SignatureType::RsaSha512_4096) |
            0x08 => value!(SignatureType::EdDsaSha512Ed25519ph)
        ) >>
        sign_len: be_u16 >>
        take!(1u8) >>
        version_len: be_u8 >>
        take!(1u8) >>
        signer_id_len: be_u8 >>
        content_len:   be_u64 >>
        take!(1u8) >>
        file_type: switch!(be_u8,
            0x00 => value!(FileType::Zip) |
            0x01 => value!(FileType::Xml) |
            0x02 => value!(FileType::Html) |
            0x03 => value!(FileType::XmlGz) |
            0x04 => value!(FileType::TxtGz) |
            0x05 => value!(FileType::Dmg) |
            0x06 => value!(FileType::Exe)
        ) >>
        take!(1u8) >>
        content_type: switch!(be_u8,
            0x00 => value!(ContentType::Unknown) |
            0x01 => value!(ContentType::RouterUpdate) |
            0x02 => value!(ContentType::PluginUpdate) |
            0x03 => value!(ContentType::ReseedData) |
            0x04 => value!(ContentType::NewsFeed) |
            0x05 => value!(ContentType::BlocklistFeed)
        ) >>
        take!(12u8) >>
        version:   take!(version_len)   >>
        signer_id: take!(signer_id_len) >>
        content:   take!(content_len)   >>
        signature: take!(sign_len)      >>
        (Su3 {
            _sign_type:     sign_type,
            _sign_len:      sign_len,
            _version_len:   version_len,
            _signer_id_len: signer_id_len,
            _content_len:   content_len,
            file_type:      file_type,
            content_type:   content_type,
            _version:       version.to_vec(),
            _signer_id:     signer_id.to_vec(),
            content:        content.to_vec(),
            _signature:     signature.to_vec(),
        })
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    // test that the i2p reseed file is parsed correctly
    #[test]
    fn test_parse_su3() {
        const ROUTER_INFO: &'static [u8] = include_bytes!("../assets/i2pseeds.su3");

        let parsed = Su3::from_bytes(ROUTER_INFO).unwrap();

        assert_eq!(parsed.file_type, FileType::Zip);
        assert_eq!(parsed.content_type, ContentType::ReseedData);

        println!("content len = {}", parsed.content.len());
    }
}
