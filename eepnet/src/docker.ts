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

import axios from "axios";
import { promises as fs } from "fs";

export class Network {
  address: null | string;
  log?: boolean;

  constructor(log?: boolean) {
    this.address = null;
    this.log = log;
  }

  async create() {
    let response = await axios.get("http://localhost/networks", {
      socketPath: "/var/run/docker.sock",
    });

    // check if the network already exists and if so,
    // parse start address of the subnet and create `AddressAssigner`
    let network = response.data.filter(
      (config: any) => config.Name == "eepnet",
    );
    if (network[0]) {
      let subnet = network[0]["IPAM"]["Config"][0]["Subnet"];

      if (this.log) console.log(`eepnet already exists (${subnet})`);

      let octets = subnet.split("/")[0].split(".").map(Number);
      octets[3] += 2;

      this.address = octets.join(".");
      return;
    }

    if (this.log) console.log("create eepnet bridge network");

    let config = {
      Name: "eepnet",
      Internal: false,
      IPAM: {
        Config: [
          {
            Subnet: "172.20.0.0/16",
          },
        ],
        Options: {},
      },
      Options: {
        "com.docker.network.bridge.default_bridge": "true",
        "com.docker.network.bridge.enable_icc": "true",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
        "com.docker.network.driver.mtu": "1500",
      },
    };

    try {
      await axios.post("http://localhost/networks/create", config, {
        socketPath: "/var/run/docker.sock",
      });

      this.address = "172.20.0.2";
    } catch (error) {
      console.log(error);
    }
  }

  async destroy() {
    if (this.log) console.log("destroy eepnet bridge network");

    await axios.delete("http://localhost/networks/eepnet", {
      socketPath: "/var/run/docker.sock",
    });
  }

  nextAddress(): string {
    if (!this.address) throw new Error("network doesn't exist");

    const currentAddress = this.address;
    const octets = this.address?.split(".").map(Number);

    octets[3] += 1;
    if (octets[3] >= 255) {
      throw "addresses exhausted";
    }

    this.address = octets.join(".");

    return currentAddress;
  }
}

export class Image {
  path: string;
  name: string;

  constructor(name: string, path: string) {
    this.path = path;
    this.name = name;
  }

  async build(file?: string) {
    console.log(`building docker image for ${this.name}`);

    await axios.post(
      `http://localhost/build?t=${this.name}${file ? `&dockerfile=${file}` : ""}`,
      await fs.readFile(this.path),
      {
        headers: {
          "Content-Type": "application/tar",
        },
        maxRedirects: 0,
        timeout: 60000,
        socketPath: "/var/run/docker.sock",
      },
    );

    console.log(`docker image for ${this.name} ready`);
  }
}

export class Container {
  name: string;
  image: string;
  path: string;
  address: string;

  constructor(image: string, name: string, path: string, address: string) {
    this.name = name;
    this.image = image;
    this.path = path;
    this.address = address;
  }

  async create(
    binds: string[],
    ports: { [key: string]: any[] },
    exposedPorts: { [key: string]: any },
    command: string[],
  ) {
    let body = {
      Hostname: this.name,
      Image: this.image,
      Cmd: command,
      AttachStdout: true,
      AttachStderr: true,
      ExposedPorts: exposedPorts,
      User: "1000:1000",
      HostConfig: {
        Binds: binds,
        AutoRemove: false,
        NetworkMode: "eepnet",
        PortBindings: ports,
        LogConfig: {
          Type: "json-file",
        },
      },
      NetworkingConfig: {
        EndpointsConfig: {
          eepnet: {
            IPAMConfig: {
              IPv4Address: this.address,
            },
          },
        },
      },
    };

    await axios.post(
      `http://localhost/containers/create?name=${this.name}`,
      body,
      {
        socketPath: "/var/run/docker.sock",
      },
    );

    await axios.post(
      `http://localhost/containers/${this.name}/start`,
      {},
      {
        socketPath: "/var/run/docker.sock",
      },
    );
  }

  async destroy() {
    try {
      await axios.delete(
        `http://localhost/containers/${this.name}?v=true&force=true`,
        {
          socketPath: "/var/run/docker.sock",
        },
      );
    } catch (error) {
      console.log(error);
    }
  }

  async inspect(): Promise<any> {
    return (
      await axios.get(`http://localhost/containers/${this.name}/json`, {
        socketPath: "/var/run/docker.sock",
      })
    ).data;
  }

  async logs(): Promise<any> {
    return (
      await axios.get(
        `http://localhost/containers/${this.name}/logs?stdout=true&stderr=true`,
        {
          socketPath: "/var/run/docker.sock",
        },
      )
    ).data;
  }
}
