use util::*;

use futures::{AsyncReadExt, AsyncWriteExt};
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use yosemite::{style::Stream, Session, SessionOptions};

use std::time::Duration;

#[tokio::main]
async fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    let sam_params_1 = get_sam_parameters(&args[1]).await;
    let sam_params_2 = get_sam_parameters(&args[2]).await;

    let mut session1 = Session::<Stream>::new(SessionOptions {
        samv3_tcp_port: sam_params_1.tcp_port,
        samv3_udp_port: sam_params_1.udp_port,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut session2 = Session::<Stream>::new(SessionOptions {
        samv3_tcp_port: sam_params_2.tcp_port,
        samv3_udp_port: sam_params_2.udp_port,
        ..Default::default()
    })
    .await
    .unwrap();

    let destination = session1.destination().to_owned();

    // generate random 8KB buffer and calculate a checksum for it
    let (data, digest_out) = {
        let mut data = vec![0u8; 8192];
        thread_rng().fill_bytes(&mut data);

        let mut hasher = Sha256::new();
        hasher.update(&data);

        (data, hasher.finalize())
    };

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut stream = session2.connect(&destination).await.unwrap();

        for chunk in data.chunks(1024) {
            stream.write_all(&chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut stream = tokio::time::timeout(Duration::from_secs(5 * 60), session1.accept())
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut data_in = [0u8; 8192];
    tokio::time::timeout(Duration::from_secs(3 * 60), stream.read_exact(&mut data_in))
        .await
        .expect("no timeout")
        .expect("to succeed");

    let mut hasher = Sha256::new();
    hasher.update(&data_in);
    let digest_in = hasher.finalize();

    assert_eq!(digest_out, digest_in);

    handle.await.unwrap();
}
