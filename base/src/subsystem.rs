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

use crate::{i2np::RawI2npMessage, primitives::RouterId, Error};

use thingbuf::mpsc::{Receiver, Sender};

use alloc::vec::Vec;

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum SubsystemKind {
    /// NetDB subsystem.
    NetDb,

    /// Tunneling subsystem.
    Tunnel,
}

#[derive(Clone)]
pub enum SubsystemCommand {
    /// Send I2NP to router.
    SendMessage {
        /// Serialized I2NP message.
        message: Vec<u8>,
    },
    Dummy,
}

// TODO: get rid of thingbuf
impl Default for SubsystemCommand {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Inner subsystem event.
#[derive(Clone)]
pub enum InnerSubsystemEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router: RouterId,

        /// TX channel for sending commands to the transport.
        tx: Sender<SubsystemCommand>,
    },

    /// Connection closed.
    ConnectionClosed {
        /// Router ID.
        router: RouterId,
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP message.
        message: RawI2npMessage,
    },

    Dummy,
}

impl Default for InnerSubsystemEvent {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Subsystem event.
#[derive(Debug, Clone)]
pub enum SubsystemEvent {
    /// Connection established.
    ConnectionEstablished {
        /// Router ID.
        router: RouterId,
    },

    /// Connection closed.
    ConnectionClosed {
        /// Router ID.
        router: RouterId,
    },

    /// I2NP message.
    I2Np {
        /// Raw, unparsed I2NP message.
        message: RawI2npMessage,
    },

    Dummy,
}

impl Default for SubsystemEvent {
    fn default() -> Self {
        Self::Dummy
    }
}

#[derive(Clone)]
pub struct SubsystemHandle {
    subsystems: Vec<Sender<InnerSubsystemEvent>>,
}

impl SubsystemHandle {
    /// Create new [`SubsystemHandle`].
    pub fn new() -> Self {
        Self {
            subsystems: Vec::new(),
        }
    }

    // TODO: make private!
    pub fn register_subsystem(&mut self, event_tx: Sender<InnerSubsystemEvent>) {
        self.subsystems.push(event_tx);
    }

    // TODO: could definitely be better lol
    pub async fn report_connection_established(
        &mut self,
        router: RouterId,
        tx: Sender<SubsystemCommand>,
    ) {
        for subsystem in &mut self.subsystems {
            let _ = subsystem
                .send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router.clone(),
                    tx: tx.clone(),
                })
                .await;
        }
    }

    // TODO: fix error
    pub fn dispatch_message(&mut self, message: RawI2npMessage) -> crate::Result<()> {
        match message.destination() {
            SubsystemKind::NetDb => self.subsystems[0]
                .try_send(InnerSubsystemEvent::I2Np { message })
                .map_err(|_| Error::NotSupported),
            SubsystemKind::Tunnel => self.subsystems[1]
                .try_send(InnerSubsystemEvent::I2Np { message })
                .map_err(|_| Error::NotSupported),
        }
    }
}
