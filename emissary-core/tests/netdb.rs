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

use emissary_core::{router::Router, Config, Ntcp2Config, SamConfig, TransitConfig};
use emissary_util::runtime::tokio::Runtime;
use futures::StreamExt;
use rand::{thread_rng, RngCore};
use yosemite::{style::Stream, Session, SessionOptions};

use std::time::Duration;

async fn make_router(
    floodfill: bool,
    net_id: u8,
    routers: Vec<Vec<u8>>,
) -> (Router<Runtime>, Vec<u8>) {
    let config = Config {
        net_id: Some(net_id),
        floodfill,
        insecure_tunnels: true,
        allow_local: true,
        metrics: None,
        ntcp2: Some(Ntcp2Config {
            port: 0u16,
            iv: {
                let mut iv = [0u8; 16];
                thread_rng().fill_bytes(&mut iv);
                iv
            },
            key: {
                let mut key = [0u8; 32];
                thread_rng().fill_bytes(&mut key);
                key
            },
            host: Some("127.0.0.1".parse().unwrap()),
            publish: true,
        }),
        routers,
        samv3_config: Some(SamConfig {
            tcp_port: 0u16,
            udp_port: 0u16,
            host: "127.0.0.1".to_string(),
        }),
        transit: Some(TransitConfig {
            max_tunnels: Some(5000),
        }),
        ..Default::default()
    };

    Router::<Runtime>::new(config).await.unwrap()
}

#[tokio::test]
async fn router_exploration() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let mut router_infos = Vec::<Vec<u8>>::new();
    let net_id = (thread_rng().next_u32() % 255) as u8;

    for i in 0..6 {
        let (mut router, router_info) = make_router(i < 3, net_id, router_infos.clone()).await;

        router_infos.push(router_info);
        tokio::spawn(async move { while let Some(_) = router.next().await {} });
    }

    // wait a moment to give other routers a chance to publish their router infos
    // and for floodfills to flood them
    tokio::time::sleep(Duration::from_secs(15)).await;

    // create the sam router and fetch the random sam tcp port from the router
    let mut router = make_router(false, net_id, vec![router_infos[0].clone()]).await.0;
    let sam_tcp = router.protocol_address_info().sam_tcp.unwrap().port();

    // spawn the router inte background and wait a moment for the network to boot
    tokio::spawn(async move { while let Some(_) = router.next().await {} });
    tokio::time::sleep(Duration::from_secs(15)).await;

    let _session = tokio::time::timeout(
        Duration::from_secs(30),
        Session::<Stream>::new(SessionOptions {
            samv3_tcp_port: sam_tcp,
            ..Default::default()
        }),
    )
    .await
    .expect("no timeout")
    .expect("to succeed");
}
