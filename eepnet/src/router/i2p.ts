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

import { Container, Image } from "../docker";
import { Router, RouterInfo } from "../config";
import { getRouterHash } from "./util";

export class I2p implements Router {
  name: string;
  floodfill: boolean;
  hash: null | string;
  host: null | string;
  config: null | string;
  path: null | string;
  container: null | Container;

  constructor(name: string, floodfill: boolean) {
    this.name = name;
    this.floodfill = floodfill;

    this.hash = null;
    this.host = null;
    this.config = null;
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

    if (!this.host)
      return Promise.reject(new Error(`host missing for ${this.name}`));

    // router config
    {
      let config = `
i2np.allowLocal=true
i2np.ipv4.firewalled=false
i2np.ipv6.firewalled=false
i2np.lastIPv6Firewalled=false
i2np.upnp.enable=false
i2p.insecureFiles=true
i2p.reseedURL=https://localhost:3333/foo
router.blocklist.enable=false
router.floodfillParticipant=false
router.networkID=2
router.newsRefreshFrequency=0
router.rebuildKeys=false
router.rejectStartupTime=1000
router.reseedDisable=true
router.sharePercentage=80
router.sybilFrequency=0
routerconsole.advanced=true
routerconsole.welcomeWizardComplete=true
stat.full=true
time.disabled=true
time.sntpServerList=localhost
router.updateDisabled=true
i2np.ntcp.autoport=false
i2np.ntcp.autoip=false
i2np.ntcp.port=9999
i2np.udp.internalPort=9999
i2np.udp.port=9999
port=9999
i2np.ntcp.hostname=${this.host}
      `;
      await fs.writeFile(`${path}/router.config`, config);
    }

    // logger confiig
    {
      let config = `
logger.consoleBufferSize=20
logger.dateFormat=
logger.defaultLevel=DEBUG
logger.displayOnScreen=true
logger.dropDuplicates=true
logger.dropOnOverflow=false
logger.flushInterval=29
logger.format=d p [t] c: m
logger.gzip=false
logger.logBufferSize=1024
logger.logFileName=logs/log-router-@.txt
logger.logFileSize=10m
logger.logRotationLimit=2
logger.minGzipSize=0
logger.minimumOnScreenLevel=CRIT
      `;
      await fs.writeFile(`${path}/logger.config`, config);
    }

    const container = new Container("i2p", this.name, path, this.host);
    await container.create([`${path}:/i2p/.i2p`], {}, {}, []);
    await new Promise((resolve) => setTimeout(resolve, 5000));
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

    console.log(`starting ${this.name} (${this.hash})`);

    this.container = new Container("i2p", this.name, this.path, this.host);
    await this.container.create([`${this.path}:/i2p/.i2p`], {}, {}, []);
  }

  async stop(): Promise<void> {
    if (this.container) await this.container.destroy();
  }
}

export async function buildI2p() {
  await create(
    {
      gzip: true,
      file: "/tmp/eepnet/i2p.tar",
      cwd: "resources/",
    },
    ["Dockerfile.i2p", "i2p.patch"],
  );

  await new Image("i2p", "/tmp/eepnet/i2p.tar").build("Dockerfile.i2p");
}
