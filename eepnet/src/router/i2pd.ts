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

import { Container, Image } from "../docker";
import { Router, RouterInfo } from "../config";
import { getRouterHash } from "./util";

export class I2pd implements Router {
  name: string;
  log: string;
  floodfill: boolean;
  sam: boolean;
  hash: null | string;
  host: null | string;
  config: null | string;
  path: null | string;
  container: null | Container;

  constructor(name: string, log: string, floodfill: boolean, sam: boolean) {
    this.name = name;
    this.log = log;
    this.floodfill = floodfill;
    this.sam = sam;

    this.hash = null;
    this.host = null;
    this.config = null;
    this.path = null;
    this.container = null;
  }

  getName(): string {
    return this.name;
  }

  getRouterHash(): string {
    if (!this.hash) throw new Error("router hash not set");
    return this.hash;
  }

  setHost(host: string): void {
    this.host = host;
  }

  async generateRouterInfo(path: string): Promise<RouterInfo> {
    this.path = path;

    if (!this.host)
      return Promise.reject(new Error(`host missing for ${this.name}`));

    let config = toml
      .stringify({
        host: this.host,
        reservedrange: false,
        loglevel: this.log,
        floodfill: this.floodfill,
        ipv4: true,
        ipv6: false,
        ntcp2: {
          enabled: true,
          published: true,
          port: 9999,
        },
        sam: {
          enabled: true,
          address: "0.0.0.0",
          port: 7656,
          portudp: 7655,
        },
        reseed: {
          urls: "",
          verify: false,
        },
      })
      // the format isn't strictly toml so some modification have to be made
      // so i2pd is able to parse the configuration correctly
      .replace("9_999", "9999")
      .replace("7_656", "7656")
      .replace("7_655", "7655")
      .replace(`"0.0.0.0"`, `0.0.0.0`)
      .replace(`\"${this.host}\"`, `${this.host}`);

    await fs.writeFile(`${path}/i2pd.conf`, config);

    const container = new Container("i2pd", this.name, path, this.host);
    await container.create([`${path}:/var/lib/i2pd`], {}, {}, [
      "i2pd",
      "--datadir",
      "/var/lib/i2pd",
    ]);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    await container.destroy();

    let routerInfo = new Uint8Array(await fs.readFile(`${path}/router.info`));
    this.hash = getRouterHash(routerInfo.subarray(0, 391));

    return { name: this.name, hash: this.hash, info: routerInfo };
  }

  async populateNetDb(routerInfos: RouterInfo[]): Promise<void> {
    routerInfos
      .filter((info: RouterInfo) => info.name != this.name)
      .map((info: RouterInfo) => info)
      .forEach(async (info: RouterInfo) => {
        await fs.writeFile(
          `${this.path}/netDb/r${info.hash[0]}/routerInfo-${info.hash}.dat`,
          info.info,
        );
      });
  }

  async start(): Promise<void> {
    if (!this.path || !this.host) throw new Error("path or host not set");

    let ports: { [key: string]: any[] } = {};
    let exposedPorts: { [key: string]: any } = {};

    // if sam was enabled, expose the ports and map them to random host ports
    if (this.sam) {
      ports["7656/tcp"] = [{}];
      exposedPorts["7656/tcp"] = {};

      ports["7655/udp"] = [{}];
      exposedPorts["7655/udp"] = {};
    }

    this.container = new Container("i2pd", this.name, this.path, this.host);
    await this.container.create(
      [`${this.path}:/var/lib/i2pd`],
      ports,
      exposedPorts,
      [
        "i2pd",
        "--loglevel",
        this.log,
        "--datadir",
        "/var/lib/i2pd",
        "--reseed.urls",
        "",
      ],
    );
  }

  async stop(): Promise<void> {
    if (this.container) await this.container.destroy();
  }

  async getLogs(): Promise<any> {
    if (!this.container) throw new Error("container doesn't exist");

    return await this.container.logs();
  }
}

export async function buildI2pd() {
  await create(
    {
      gzip: true,
      file: "/tmp/eepnet/i2pd.tar",
      cwd: "resources/",
    },
    ["Dockerfile.i2pd", "i2pd.patch"],
  );

  await new Image("i2pd", "/tmp/eepnet/i2pd.tar").build("Dockerfile.i2pd");
}
