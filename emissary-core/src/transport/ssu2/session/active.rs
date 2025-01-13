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
    crypto::chachapoly::{ChaCha, ChaChaPoly},
    primitives::RouterId,
    runtime::Runtime,
    subsystem::{SubsystemCommand, SubsystemHandle},
    transport::ssu2::{
        message::{
            Block, DataMessageBuilder, HeaderBuilder, MessageBuilder, MessageType, ShortHeaderFlag,
        },
        Packet,
    },
};

use thingbuf::mpsc::{channel, Receiver, Sender};

use core::{
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::active";

/// Key context for an active session.
pub struct KeyContext {
    /// Key for encrypting/decrypting `Data` payloads.
    pub k_data: [u8; 32],

    /// Key for encrypting/decrypting second part of the header.
    pub k_header_2: [u8; 32],
}

impl KeyContext {
    /// Create new [`KeyContext`].
    pub fn new(k_data: [u8; 32], k_header_2: [u8; 32]) -> Self {
        Self { k_data, k_header_2 }
    }
}

/// SSU2 active session context.
pub struct Ssu2SessionContext {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    pub intro_key: [u8; 32],

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pub pkt_rx: Receiver<Packet>,

    /// Key context for inbound packets.
    pub recv_key_ctx: KeyContext,

    /// ID of the remote router.
    pub router_id: RouterId,

    /// Key context for outbound packets.
    pub send_key_ctx: KeyContext,
}

/// Active SSU2 session.
pub struct Ssu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// RX channel for receiving messages from subsystems.
    cmd_rx: Receiver<SubsystemCommand>,

    /// TX channel for sending commands for this connection.
    cmd_tx: Sender<SubsystemCommand>,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key of remote router.
    ///
    /// Used for encrypting the first part of the header.
    intro_key: [u8; 32],

    /// Next packet number.
    pkt_num: u32,

    /// RX channel for receiving inbound packets from [`Ssu2Socket`].
    pkt_rx: Receiver<Packet>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: `R::UdpSocket` should be clonable
    pkt_tx: Sender<Packet>,

    /// Key context for inbound packets.
    recv_key_ctx: KeyContext,

    /// ID of the remote router.
    router_id: RouterId,

    /// Key context for outbound packets.
    send_key_ctx: KeyContext,

    /// Highest seen packet number.
    //
    // TODO: move to separate ack context
    pkt_highest_seen: u32,
    num_unacked: u8,

    /// Subsystem handle.
    subsystem_handle: SubsystemHandle,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> Ssu2Session<R> {
    /// Create new [`Ssu2Session`].
    pub fn new(
        context: Ssu2SessionContext,
        pkt_tx: Sender<Packet>,
        subsystem_handle: SubsystemHandle,
    ) -> Self {
        let (cmd_tx, cmd_rx) = channel(666usize);

        tracing::debug!(
            target: LOG_TARGET,
            dst_id = ?context.dst_id,
            address = ?context.address,
            "starting active session",
        );

        Self {
            address: context.address,
            cmd_rx,
            cmd_tx,
            dst_id: context.dst_id,
            pkt_highest_seen: 0u32,
            num_unacked: 0u8,
            intro_key: context.intro_key,
            pkt_num: 1u32, // TODO: may not be correct for outbound sessions
            pkt_rx: context.pkt_rx,
            pkt_tx,
            recv_key_ctx: context.recv_key_ctx,
            router_id: context.router_id,
            send_key_ctx: context.send_key_ctx,
            subsystem_handle,
            _runtime: Default::default(),
        }
    }

    /// Handle received `pkt` for this session.
    fn on_packet(&mut self, pkt: Packet) {
        let Packet { mut pkt, address } = pkt;

        // TODO: upate address if it has changed
        // TODO: handle duplicate pkts correctly

        let iv2 = TryInto::<[u8; 12]>::try_into(&pkt[pkt.len() - 12..]).expect("to succeed");
        ChaCha::with_iv(self.recv_key_ctx.k_header_2, iv2)
            .decrypt([0u8; 8])
            .into_iter()
            .zip(&mut pkt[8..])
            .for_each(|(a, b)| {
                *b ^= a;
            });

        match MessageType::try_from(pkt[12]) {
            Ok(msg_type) => tracing::trace!("msg type = {msg_type:?}"),
            Err(()) => {
                tracing::error!("unknown message");
            }
        }

        let pkt_num = u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&pkt[8..12]).unwrap());

        // TODO: unnecessary memory copy
        let mut payload = pkt[16..].to_vec();
        ChaChaPoly::with_nonce(&self.recv_key_ctx.k_data, pkt_num as u64)
            .decrypt_with_ad(&pkt[..16], &mut payload)
            .unwrap();

        let Some(blocks) = Block::parse(&payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to parse ssu2 message blocks",
            );
            debug_assert!(false);
            return;
        };

        // TODO: shut down the sesssion
        // TODO: iterate only once?
        if let Some(Block::Termination { reason, .. }) =
            blocks.iter().find(|message| core::matches!(message, Block::Termination { .. }))
        {
            tracing::debug!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?reason,
                "session terminated by remote router",
            );
            return;
        }

        let messages = blocks
            .into_iter()
            .filter_map(|message| match message {
                Block::I2Np { message } =>
                    if message.is_expired::<R>() {
                        tracing::trace!(
                            target: LOG_TARGET,
                            router_id = %self.router_id,
                            message_type = ?message.message_type,
                            message_id = ?message.message_id,
                            expiration = ?message.expiration,
                            "discarding expired message",
                        );
                        None
                    } else {
                        Some(message)
                    },
                Block::Padding { .. } => None,
                message => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        router_id = %self.router_id,
                        ?message,
                        "ignoring message",
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        if let Err(error) = self.subsystem_handle.dispatch_messages(messages) {
            tracing::warn!(
                target: LOG_TARGET,
                router_id = %self.router_id,
                ?error,
                "failed to dispatch messages to subsystems",
            );
        }

        self.pkt_highest_seen = pkt_num;
        self.num_unacked += 1;

        // TODO: handle fragments
        // TODO: start ack timer?
    }

    /// Handle outbound `message`.
    fn on_send_message(&mut self, message: Vec<u8>) {
        debug_assert!(message.len() < 1000);

        for message in DataMessageBuilder::default()
            .with_dst_id(self.dst_id)
            .with_pkt_num(&mut self.pkt_num)
            .with_key_context(self.intro_key, &self.send_key_ctx)
            .with_i2np(message)
            .with_ack(
                self.pkt_highest_seen,
                self.num_unacked.saturating_sub(1), // TODO: explain
                None,
            )
            .build()
        {
            tracing::error!(target: LOG_TARGET, "send message, len = {}", message.len());

            if let Err(error) = self.pkt_tx.try_send(Packet {
                pkt: message.to_vec(),
                address: self.address,
            }) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send packet",
                );
            }
        }

        self.pkt_num += 1;
        self.num_unacked = 0;
    }

    /// Run the event loop of an active SSU2 session.
    pub async fn run(mut self) -> (RouterId, u64) {
        tracing::trace!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            "start ntcp2 event loop",
        );

        self.subsystem_handle
            .report_connection_established(self.router_id.clone(), self.cmd_tx.clone())
            .await;

        // run the event loop until it returns which happens only when
        // the peer has disconnected or an error was encoutered
        //
        // inform other subsystems of the disconnection
        let result = (&mut self).await;

        tracing::debug!(
            target: LOG_TARGET,
            router_id = %self.router_id,
            "connnection closed",
        );

        self.subsystem_handle.report_connection_closed(self.router_id.clone()).await;
        (self.router_id, self.dst_id)
    }
}

impl<R: Runtime> Future for Ssu2Session<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.pkt_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(pkt)) => self.on_packet(pkt),
            }
        }

        loop {
            match self.cmd_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(SubsystemCommand::SendMessage { message })) =>
                    self.on_send_message(message),
                Poll::Ready(Some(SubsystemCommand::Dummy)) => {}
            }
        }

        Poll::Pending
    }
}
