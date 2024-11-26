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

import { identity } from "cmd-ts/dist/cjs/from";
import { Router, RouterInfo } from "../config";

export class I2pd implements Router {
  name: string;
  log: string;
  caps: string;
  host: null | string;
  config: null | string;

  constructor(name: string, log: string, caps: string) {
    this.name = name;
    this.log = log;
    this.caps = caps;

    this.host = null;
    this.config = null;
  }

  getName(): string {
    return this.name;
  }

  setHost(host: string): void {
    this.host = host;
  }

  generateRouterInfo(path: string): Promise<RouterInfo> {
    if (!this.host)
      return Promise.reject(new Error(`host missing for ${this.name}`));

    let config = {
      host: this.host,
      reservedrange: false,
      loglevel: this.log,
      ipv4: true,
      ipv6: false,
      ntcp2: {
        enabled: true,
        published: true,
        port: 8888,
      },
      reseed: {
        urls: "",
      },
    };

    // TODO: map datadir to host
    // TODO: start i2pd
    // TODO: stop i2pd
    // TODO: copy generated routerinfo
    // TODO: verify it's valid

    return Promise.resolve({
      name: this.name,
      hash: "",
      info: new Uint8Array(),
    });
  }

  async populateNetDb(routerInfos: RouterInfo[]): Promise<void> {}
  async start(): Promise<string | null> {
    return null;
  }
  async stop(): Promise<void> {}
}
