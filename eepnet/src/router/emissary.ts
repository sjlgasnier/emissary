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

import { create } from "tar";
import { promises as fs } from "fs";
import * as toml from "@iarna/toml";

import { Router, RouterInfo } from "../config";
import { Container, Image } from "../docker";
import { getRouterHash } from "./util";

export class Emissary implements Router {
  name: string;
  log: string;
  floodfill: boolean;
  hash: null | string;
  host: null | string;
  path: null | string;
  container: null | Container;

  constructor(name: string, log: string, floodfill: boolean) {
    this.name = name;
    this.log = log;
    this.floodfill = floodfill;

    this.hash = null;
    this.host = null;
    this.path = null;
    this.container = null;
  }

  getName(): string {
    return this.name;
  }

  setHost(host: string): void {
    console.log(`assign ${host} for ${this.name}`);

    this.host = host;
  }

  async generateRouterInfo(path: string): Promise<RouterInfo> {
    this.path = path;

    if (!this.host) throw new Error("host not specified");

    let config = toml.stringify({
      floodfill: this.floodfill,
      caps: this.floodfill ? "XfR" : "LR",
      ntcp2: {
        enabled: true,
        host: this.host,
        port: 9999,
      },
      i2cp: {
        enabled: true,
        port: 7654,
      },
      sam: {
        enabled: true,
        udp_port: 7655,
        tcp_port: 7656,
      },
    });

    await fs.writeFile(`${path}/router.toml`, config);
    await fs.mkdir(`${path}/routers`, {
      recursive: true,
    });

    // create new container which starts up a fresh router
    //
    // this router generates itself keys and a router info file which,
    // after waiting for 2 secons for initialization finish, is collected
    // from `this.path` and returned to the caller
    const container = new Container("emissary", this.name, path, this.host);
    await container.create([`${path}:/var/lib/emissary`], {}, {}, [
      "emissary-cli",
      "-lemissary=trace",
      "--base-path",
      "/var/lib/emissary",
    ]);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    await container.destroy();

    let routerInfo = new Uint8Array(
      await fs.readFile(`${path}/routerInfo.dat`),
    );
    this.hash = getRouterHash(routerInfo.subarray(0, 391));

    return { name: this.name, hash: this.hash, info: routerInfo };
  }

  async populateNetDb(routerInfos: RouterInfo[]): Promise<void> {
    // filter out our own router info
    routerInfos
      .filter((info: RouterInfo) => info.name != this.name)
      .map((info: RouterInfo) => info)
      .forEach(
        async (info: RouterInfo) =>
          await fs.writeFile(
            `${this.path}/routers/routerInfo-${info.hash}.dat`,
            info.info,
          ),
      );
  }

  async start(): Promise<void> {
    if (!this.path || !this.host) throw new Error("path or host not set");

    console.log(`starting ${this.name} (${this.hash})`);

    this.container = new Container("emissary", this.name, this.path, this.host);
    await this.container.create(
      [`${this.path}:/var/lib/emissary`],
      { ["12842/tcp"]: [{}] },
      { ["12842/tcp"]: {} },
      ["emissary-cli", "-lemissary=trace", "--base-path", "/var/lib/emissary"],
    );
  }

  async stop(): Promise<void> {
    if (this.container) await this.container.destroy();
  }

  async getScrapeEndpoint(): Promise<any> {
    if (!this.container) throw new Error("container is not running");

    // fetch port mapping for prometheus on host
    let info = await this.container.inspect();

    return {
      targets: [
        `0.0.0.0:${info["NetworkSettings"]["Ports"]["12842/tcp"][0]["HostPort"]}`,
      ],
      labels: {
        router: info["Name"].substring(1),
      },
    };
  }
}

export async function buildEmissary() {
  await create(
    {
      gzip: true,
      file: "/tmp/eepnet/emissary.tar",
      cwd: "..",
    },
    ["Dockerfile", "Cargo.toml", "Cargo.lock", "emissary-core", "emissary-cli"],
  );

  await new Image("emissary", "/tmp/eepnet/emissary.tar").build();
}
