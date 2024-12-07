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

import * as toml from "toml";
import { promises as fs } from "fs";

import { Emissary } from "./router/emissary";
import { I2pd } from "./router/i2pd";
import { I2p } from "./router/i2p";

export interface RouterInfo {
  name: string;
  hash: string;
  info: Uint8Array;
}

export interface Router {
  getName(): string;
  getRouterHash(): string;
  getLogs(): Promise<any>;
  setHost(host: string): void;
  generateRouterInfo(path: string): Promise<RouterInfo>;
  populateNetDb(routerInfos: RouterInfo[]): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
}

export interface Config {
  emissary: Emissary[];
  i2pd: I2pd[];
  i2p: I2p[];
}

// Parse TOML `config` into `Config`.
export async function parseConfig(config: string): Promise<Config> {
  let data = await fs.readFile(config, "utf-8");
  const parsedData = toml.parse(data);
  const grouped: Config = { emissary: [], i2pd: [], i2p: [] };

  parsedData.routers.forEach((router: any) => {
    switch (router.type) {
      case "emissary": {
        grouped.emissary.push(
          ...Array.from(
            { length: router.count ?? 1 },
            (_, index) =>
              new Emissary(
                router.name ?? `${router.type}-${index}`,
                router.log ?? "-lemissary=trace",
                router.floodfill ?? false,
                router.sam ?? false,
              ),
          ),
        );
        break;
      }
      case "i2pd": {
        grouped.i2pd.push(
          ...Array.from(
            { length: router.count ?? 1 },
            (_, index) =>
              new I2pd(
                router.name ?? `${router.type}-${index}`,
                router.log,
                router.floodfill ?? false,
                router.sam ?? false,
              ),
          ),
        );
        break;
      }
      case "i2p": {
        grouped.i2p.push(
          ...Array.from(
            { length: router.count ?? 1 },
            (_, index) =>
              new I2p(
                router.name ?? `${router.type}-${index}`,
                router.floodfill ?? false,
                router.sam ?? false,
              ),
          ),
        );
        break;
      }
      default:
        throw new Error(`unrecognized router type ${router.type}`);
    }
  });

  return grouped;
}
