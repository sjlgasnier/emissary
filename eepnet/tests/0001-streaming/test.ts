import { promises as fs } from "fs";
import { spawn } from "child_process";

export async function setup(path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const cargo = spawn("cargo", ["build"], { cwd: `${path}/test-runner` });

    let output = "";
    cargo.stdout.on("data", (data) => {
      output += data.toString();
    });

    cargo.stderr.on("data", (data) => {
      output += data.toString();
    });

    cargo.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(output));
    });

    cargo.on("error", (err) => {
      reject(new Error(err.message));
    });
  });
}

export async function run(path: string): Promise<void> {
  // give network some time to start
  await new Promise((resolve) => setTimeout(resolve, 30_000));

  return new Promise((resolve, reject) => {
    const cargo = spawn("cargo", ["run", "--", "sam-1", "sam-2"], {
      cwd: `${path}/test-runner`,
    });

    let output = "";
    cargo.stdout.on("data", (data) => {
      output += data.toString();
    });

    cargo.stderr.on("data", (data) => {
      output += data.toString();
    });

    cargo.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(output));
    });

    cargo.on("error", (err) => {
      reject(new Error(err.message));
    });
  });
}
