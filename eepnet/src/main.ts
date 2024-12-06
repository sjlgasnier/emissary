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

import { buildEmissary, Emissary } from "./router/emissary";
import { buildI2pd, I2pd } from "./router/i2pd";
import { buildI2p, I2p } from "./router/i2p";
import { Network } from "./docker";
import { parseConfig, Router, RouterInfo } from "./config";
import { waitForExit, rmdir, mkdir } from "./router/util";

async function setupNetwork(rebuild: boolean, log?: boolean): Promise<Network> {
  let network = new Network(log);

  await network.create();
  await mkdir("/tmp/eepnet");

  if (rebuild) {
    await buildI2pd();
    await buildI2p();
    await buildEmissary();
  }

  return network;
}

async function startNetwork(
  emissary: Emissary[],
  i2pd: I2pd[],
  i2p: I2p[],
  log?: boolean,
): Promise<void> {
  if (log)
    console.log(
      `generating router infos (emissary: ${emissary.length}, i2pd: ${i2pd.length}, i2p: ${i2p.length})`,
    );

  let routerInfos = (
    await Promise.allSettled(
      [emissary, i2pd, i2p].flat().map((router: Router) =>
        fs
          .mkdir(`/tmp/eepnet/${router.getName()}`, {
            recursive: true,
          })
          .then((_: any) =>
            router.generateRouterInfo(`/tmp/eepnet/${router.getName()}`),
          ),
      ),
    )
  )
    .filter(
      (result: PromiseSettledResult<RouterInfo>) =>
        result.status == "fulfilled",
    )
    .map((result: PromiseFulfilledResult<RouterInfo>) => result.value);

  if (log)
    console.log("populate network databases of routers with router infos");

  await Promise.allSettled(
    [emissary, i2pd, i2p].flat().map(async (router: Router) => {
      await router.populateNetDb(routerInfos);
    }),
  );

  await Promise.allSettled(
    [emissary, i2pd, i2p].flat().map(async (router: Router) => {
      if (log)
        console.log(`starting ${router.getName()} (${router.getRouterHash()})`);

      await router.start();
    }),
  );
}

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
    let network = await setupNetwork(!no_rebuild);

    let { emissary, i2pd, i2p } = await parseConfig(path);

    // assign ip address for each router
    [emissary, i2pd, i2p].flat().map((router: Router) => {
      let address = network.nextAddress();

      console.log(`assign ${address} for ${router.getName()}`);
      router.setHost(address);
    });

    await startNetwork(emissary, i2pd, i2p, true);

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
      "/tmp/eepnet/scrape_configs.json",
      JSON.stringify(scrapeEndpoints),
      "utf8",
    );

    // wait until user presses ctrl-c
    await waitForExit();

    await Promise.allSettled(
      [emissary, i2pd, i2p].flat().map(async (router: Router) => {
        await router.stop();
      }),
    );

    if (!no_purge)
      await fs.rm("/tmp/eepnet", {
        force: true,
        recursive: true,
      });

    if (remove_network) await network.destroy();

    process.exit(0);
  },
});

const test = command({
  name: "test",
  args: {
    test: option({
      type: string,
      long: "test",
    }),
  },
  handler: async ({ test }) => {
    let network = await setupNetwork(false);
    let module = require(
      require.resolve(`../${test.replace(/^\//, "")}/test.ts`),
    );

    // setup the test by building rust code
    try {
      await module.setup(test);
    } catch (error) {
      console.error("failed to build test runner", error);

      await network.destroy();
      await fs.rm("/tmp/eepnet", {
        force: true,
        recursive: true,
      });
      process.exit(1);
    }

    let networks = await fs.readdir(`${test}/networks`);
    let numFailed = 0;

    for (const i in networks) {
      const testName = `${test.split("/")[1]}-${networks[i].split(".")[0]}`;

      await mkdir(`/tmp/eepnet/${testName}`);

      process.stdout.write(`running ${testName}...`);

      let { emissary, i2pd, i2p } = await parseConfig(
        `${test}/networks/${networks[i]}`,
      );

      // assign ip address for each router
      [emissary, i2pd, i2p].flat().forEach((router: Router) => {
        router.setHost(network.nextAddress());
      });

      await startNetwork(emissary, i2pd, i2p);

      try {
        await module.run(test);
        await rmdir(`/tmp/eepnet/${testName}`);

        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write(`✅ ${testName}\n`);
      } catch (error: any) {
        numFailed++;

        await fs.writeFile(
          `/tmp/eepnet/${testName}/test-runner`,
          error.toString(),
        );

        [emissary, i2pd, i2p].flat().forEach(async (router: Router) => {
          try {
            let logs = await router.getLogs();
            await fs.writeFile(
              `/tmp/eepnet/${testName}/${router.getName()}`,
              logs.toString(),
            );
          } catch (error) {}
        });

        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write(`❌ ${testName}\n`);
        process.stdout.write(
          `\tartifacts stored into /tmp/eepnet/${testName}\n`,
        );
      }

      [emissary, i2pd, i2p].flat().forEach(async (router: Router) => {
        await router.stop();
        await rmdir(`/tmp/eepnet/${router.getName()}`);
      });

      // sleep a bit to give docker a chance to remove containers
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }

    if (numFailed == 0) await rmdir("/tmp/eepnet");

    await new Promise((resolve) => setTimeout(resolve, 2_000));
    await network.destroy();
    process.exit(numFailed);
  },
});

const app = subcommands({
  name: "eepnet",
  cmds: { spawn, test },
});

run(app, process.argv.slice(2));
