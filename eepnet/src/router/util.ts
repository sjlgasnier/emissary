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

import * as crypto from "crypto";
import { promises as fs } from "fs";

/// Calculate router hash from router identity.
export function getRouterHash(identity: Uint8Array): string {
  const hash = crypto.createHash("sha256");
  hash.update(identity);

  return hash
    .digest()
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "~");
}

export async function waitForExit(): Promise<void> {
  return new Promise<void>(async (resolve) => {
    const handleSignal = async () => {
      process.removeListener("SIGINT", handleSignal);
      resolve();
    };

    process.on("SIGINT", handleSignal);

    while (true) await new Promise((resolve) => setTimeout(resolve, 10_000));
  });
}

export async function mkdir(path: string) {
  await fs.mkdir(path, {
    recursive: true,
  });
}

export async function rmdir(path: string) {
  await fs.rm(path, {
    force: true,
    recursive: true,
  });
}
