#![allow(unused)]

use bollard::{
    secret::{ContainerInspectResponse, NetworkSettings},
    Docker,
};

/// SAMv3 parameters.
#[derive(Debug, Clone, Copy)]
pub struct SamParameters {
    /// TCP port.
    pub tcp_port: u16,

    /// UDP port.
    pub udp_port: u16,
}

/// Fetch exposed SAMv3 parameters for `router`.
///
/// Panics if `router` doesn't exist or the parameters couldn't be found.
pub async fn get_sam_parameters(router: &str) -> SamParameters {
    let mut docker = Docker::connect_with_local_defaults().unwrap();

    let Ok(ContainerInspectResponse {
        network_settings: Some(NetworkSettings {
            ports: Some(ports), ..
        }),
        ..
    }) = docker.inspect_container(router, None).await
    else {
        panic!("failed to fetch port mappings");
    };

    let udp_port = ports
        .get("7655/udp")
        .expect("udp port to exist")
        .as_ref()
        .unwrap()
        .iter()
        .find_map(|binding| {
            (binding.host_ip == Some("0.0.0.0".to_string()))
                .then_some(binding.host_port.as_ref().unwrap().parse::<u16>().unwrap())
        })
        .unwrap();

    let tcp_port = ports
        .get("7656/tcp")
        .expect("tcp port to exist")
        .as_ref()
        .unwrap()
        .iter()
        .find_map(|binding| {
            (binding.host_ip == Some("0.0.0.0".to_string()))
                .then_some(binding.host_port.as_ref().unwrap().parse::<u16>().unwrap())
        })
        .unwrap();

    SamParameters { tcp_port, udp_port }
}
