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

import { command, run, string, option, subcommands, flag } from "cmd-ts";
import { promises as fs } from "fs";

import { Network } from "./docker";
import { parseConfig, Router, RouterInfo } from "./config";
import { buildEmissary, Emissary } from "./router/emissary";
import { waitForExit } from "./router/util";
import { buildI2pd } from "./router/i2pd";

const spawn = command({
  name: "spawn",
  args: {
    path: option({
      type: string,
      long: "path",
    }),
    no_rebuild: flag({
      long: "no-rebuild",
    }),
    no_purge: flag({
      long: "no-purge",
    }),
    remove_network: flag({
      long: "remove-network",
    }),
  },
  handler: async ({ path, no_rebuild, no_purge, remove_network }) => {
    let network = new Network();
    await network.create();

    let { emissary, i2pd } = await parseConfig(path);

    await fs.mkdir("/tmp/i2p-simnet", {
      recursive: true,
    });

    if (!no_rebuild) {
      await buildI2pd();
      await buildEmissary();
    }

    // assign ip address for each router
    [emissary, i2pd].flat().map((router: Router) => {
      router.setHost(network.nextAddress());
    });

    // generate router infos for all routers
    console.log(
      `generating router infos (emissary: ${emissary.length}, i2pd: ${i2pd.length})`,
    );

    let routerInfos = (
      await Promise.allSettled(
        [emissary, i2pd].flat().map(async (router: Router) => {
          await fs.mkdir(`/tmp/i2p-simnet/${router.getName()}`, {
            recursive: true,
          });
          return await router.generateRouterInfo(
            `/tmp/i2p-simnet/${router.getName()}`,
          );
        }),
      )
    )
      .filter(
        (result: PromiseSettledResult<RouterInfo>) =>
          result.status == "fulfilled",
      )
      .map((result: PromiseFulfilledResult<RouterInfo>) => result.value);

    // populate netdbs of all routers with the generated router infos
    console.log("populate network databases of routers with router infos");

    await Promise.allSettled(
      [emissary, i2pd].flat().map(async (router: Router) => {
        await router.populateNetDb(routerInfos);
      }),
    );

    // start network
    await Promise.allSettled(
      [emissary, i2pd].flat().map(async (router: Router) => {
        await router.start();
      }),
    );

    // fetch metrics info for emissaries
    let scrapeEndpoints = (
      await Promise.allSettled(
        emissary.map(
          async (router: Emissary) => await router.getScrapeEndpoint(),
        ),
      )
    )
      .filter(
        (result: PromiseSettledResult<any>) => result.status === "fulfilled",
      )
      .map((result: PromiseFulfilledResult<any>) => result.value);

    await fs.writeFile(
      "/tmp/i2p-simnet/scrape_configs.json",
      JSON.stringify(scrapeEndpoints),
      "utf8",
    );

    await waitForExit();

    // start network
    await Promise.allSettled(
      [emissary, i2pd].flat().map(async (router: Router) => {
        await router.stop();
      }),
    );

    if (!no_purge)
      await fs.rm("/tmp/i2p-simnet", {
        force: true,
        recursive: true,
      });

    if (remove_network) await network.destroy();

    process.exit(0);
  },
});

const app = subcommands({
  name: "eepnet",
  cmds: { spawn },
});

run(app, process.argv.slice(2));
