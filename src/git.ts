import { exec } from "@actions/exec";

async function runGit(...args: string[]) {
  let output = "";
  await exec("git", args, {
    listeners: {
      stdout: (data: Buffer) => {
        output += data.toString();
      },
    },
  });
  return output.trim();
}

export async function getCurrentBranch() {
  return runGit("rev-parse", "--abbrev-ref", "HEAD");
}

export async function getShortHash() {
  return runGit("rev-parse", "--short", "HEAD");
}

export async function getDiffFiles(): Promise<string[]> {
  const output = await runGit("diff", "--name-only", "HEAD~1");
  return output.split("\n").filter(Boolean);
}

export async function getFileDiff(file: string) {
  return runGit("show", file);
}

export async function addFile(file: string) {
  await runGit("add", file);
}

export async function commit(message: string) {
  await runGit("commit", "-m", message);
}

export async function push() {
  await runGit("push");
}
