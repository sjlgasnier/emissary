#![no_main]

use arbitrary::Arbitrary;
use emissary::i2np::{Message, MessageBuilder, MessageType};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy, Debug, Arbitrary)]
enum GeneratedMessageType {
    DatabaseStore,
    DatabaseLookup,
    DatabaseSearchReply,
    DeliveryStatus,
    Garlic,
    TunnelData,
    TunnelGateway,
    Data,
    TunnelBuild,
    TunnelBuildReply,
    VariableTunnelBuild,
    VariableTunnelBuildReply,
    ShortTunnelBuild,
    OutboundTunnelBuildReply,
}

impl Into<MessageType> for GeneratedMessageType {
    fn into(self) -> MessageType {
        match self {
            GeneratedMessageType::DatabaseStore => MessageType::DatabaseStore,
            GeneratedMessageType::DatabaseLookup => MessageType::DatabaseLookup,
            GeneratedMessageType::DatabaseSearchReply => MessageType::DatabaseSearchReply,
            GeneratedMessageType::DeliveryStatus => MessageType::DeliveryStatus,
            GeneratedMessageType::Garlic => MessageType::Garlic,
            GeneratedMessageType::TunnelData => MessageType::TunnelData,
            GeneratedMessageType::TunnelGateway => MessageType::TunnelGateway,
            GeneratedMessageType::Data => MessageType::Data,
            GeneratedMessageType::TunnelBuild => MessageType::TunnelBuild,
            GeneratedMessageType::TunnelBuildReply => MessageType::TunnelBuildReply,
            GeneratedMessageType::VariableTunnelBuild => MessageType::VariableTunnelBuild,
            GeneratedMessageType::VariableTunnelBuildReply => MessageType::VariableTunnelBuildReply,
            GeneratedMessageType::ShortTunnelBuild => MessageType::ShortTunnelBuild,
            GeneratedMessageType::OutboundTunnelBuildReply => MessageType::OutboundTunnelBuildReply,
        }
    }
}

fuzz_target!(|buffer: Vec<(GeneratedMessageType, u32, u64, Vec<u8>)>| {
    for values in buffer {
        {
            let message = MessageBuilder::standard()
                .with_message_type(values.0.into())
                .with_message_id(values.1)
                .with_expiration(values.2)
                .with_payload(&values.3)
                .build();

            assert!(Message::parse_standard(&message).is_some());
        }

        {
            let message = MessageBuilder::short()
                .with_message_type(values.0.into())
                .with_message_id(values.1)
                .with_expiration(values.2)
                .with_payload(&values.3)
                .build();

            assert!(Message::parse_short(&message).is_some());
        }
    }
});
