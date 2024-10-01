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

use crate::{
    crypto::{hmac::Hmac, StaticPrivateKey, StaticPublicKey},
    runtime::Runtime,
};

use bytes::{Bytes, BytesMut};

use alloc::vec::Vec;

/// Pending tag set.
///
/// Local router has sent `NextKey` message to remote and is waiting to receive
/// remote's public key so the session can be ratcheted.
pub struct PendingTagSet {
    /// Private key for the pending tag set.
    private_key: StaticPrivateKey,

    /// Key index.
    key_index: u16,
}

impl PendingTagSet {
    /// Create new [`PendingTagSet`].
    pub fn new<R: Runtime>(key_index: u16) -> Self {
        Self {
            key_index,
            private_key: StaticPrivateKey::new(R::rng()),
        }
    }

    /// Get [`StaticPublicKey`] of the [`PendingTagSet`].
    pub fn public_key(&self) -> StaticPublicKey {
        self.private_key.public()
    }
}

/// Session tag entry.
pub struct TagSetEntry {
    /// Index.
    pub index: u16,

    /// Session key.
    pub key: Bytes,

    /// Session tag.
    pub tag: Bytes,
}

/// Tag set.
///
/// https://geti2p.net/spec/ecies#sample-implementation
pub struct TagSet {
    /// Next root key.
    next_root_key: Vec<u8>,

    /// Session key data.
    session_key_data: Bytes,

    /// Session key constant.
    session_tag_constant: Vec<u8>,

    /// Session tag key.
    session_tag_key: Vec<u8>,

    /// Symmetric key.
    symmetric_key: Vec<u8>,

    /// Next tag index.
    tag_index: u16,
}

impl TagSet {
    /// Create new [`TagSet`].
    pub fn new(root_key: impl AsRef<[u8]>, tag_set_key: impl AsRef<[u8]>) -> Self {
        let mut temp_key = Hmac::new(root_key.as_ref()).update(tag_set_key.as_ref()).finalize();
        let next_root_key =
            Hmac::new(&temp_key).update(&b"KDFDHRatchetStep").update(&[0x01]).finalize();
        let ratchet_key = Hmac::new(&temp_key)
            .update(&next_root_key)
            .update(&b"KDFDHRatchetStep")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ratchet_key).update(&[]).finalize();
        let session_tag_key =
            Hmac::new(&temp_key).update(&b"TagAndKeyGenKeys").update(&[0x01]).finalize();
        let symmetric_key = Hmac::new(&temp_key)
            .update(&session_tag_key)
            .update(&b"TagAndKeyGenKeys")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&session_tag_key).update(&[]).finalize();
        let session_key_data =
            Hmac::new(&temp_key).update(&b"STInitialization").update(&[0x01]).finalize();
        let session_tag_constant = Hmac::new(&temp_key)
            .update(&session_key_data)
            .update(&b"STInitialization")
            .update(&[0x02])
            .finalize();

        Self {
            next_root_key,
            session_tag_key,
            symmetric_key,
            session_key_data: Bytes::from(session_key_data),
            session_tag_constant,
            tag_index: 0u16,
        }
    }

    /// Extend [`TagSet`] with `num_tags` many tags.
    pub fn extend(&mut self, num_tags: usize) {}

    /// Remove tags and keys that are too old.
    pub fn expire(&mut self) {}

    /// Calculate next session tag based on the previous session tag.
    pub fn ratchet_tag(&mut self) {}

    /// Calculate next session key based on the previouis session key.
    ///
    /// https://geti2p.net/spec/ecies#dh-ratchet-kdf
    pub fn ratchet_key(&mut self) {
        // TODO: return `PendingTagSet`?
    }

    /// Get next [`TagSetEntry`].
    ///
    /// Returns `None` if all tags have been used.
    pub fn next_entry(&mut self) -> Option<TagSetEntry> {
        // TODO: fix, can only be used for `MAX_TAGS - 1` many tags
        let tag_index = {
            let tag_index = self.tag_index;
            self.tag_index = self.tag_index.checked_add(1)?;

            tag_index
        };

        // ratchet next tag
        let garlic_tag = {
            let mut temp_key =
                Hmac::new(&self.session_key_data).update(&self.session_tag_constant).finalize();

            // store session key data for the next session tag ratchet
            self.session_key_data = Bytes::from(
                Hmac::new(&temp_key).update(&b"SessionTagKeyGen").update(&[0x01]).finalize(),
            );

            let session_tag_key_data = Hmac::new(&temp_key)
                .update(&self.session_key_data)
                .update(&b"SessionTagKeyGen")
                .update(&[0x02])
                .finalize();

            BytesMut::from(&session_tag_key_data[0..8]).freeze()
        };

        let symmetric_key = {
            let mut temp_key = Hmac::new(&self.symmetric_key).update(&[]).finalize();

            // store symmetric key for the next key ratchet
            self.symmetric_key =
                Hmac::new(&temp_key).update(&b"SymmetricRatchet").update(&[0x01]).finalize();

            let symmetric_key = Hmac::new(&temp_key)
                .update(&self.symmetric_key)
                .update(&b"SymmetricRatchet")
                .update(&[0x02])
                .finalize();

            BytesMut::from(&symmetric_key[..]).freeze()
        };

        Some(TagSetEntry {
            index: tag_index,
            key: symmetric_key,
            tag: garlic_tag,
        })
    }

    /// Get session key for for a session `tag`.
    pub fn session_key(&mut self, tag: Bytes) -> Option<StaticPrivateKey> {
        None
    }
}
