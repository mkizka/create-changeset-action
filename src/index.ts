import fs from "node:fs/promises";

import { setFailed } from "@actions/core";

import * as git from "./git.js";
import { getInputs } from "./input.js";
import { logger } from "./logger.js";

async function getChangesetIgnoredPackages(): Promise<string[]> {
  const changesetConfig = JSON.parse(
    await fs.readFile(".changeset/config.json", "utf8"),
  ) as { ignore?: string[] };
  return changesetConfig.ignore ?? [];
}

function shouldIgnorePackage(
  packageName: string,
  ignoredPackages: string[],
): boolean {
  return ignoredPackages.some((ignored) =>
    ignored.endsWith("*")
      ? packageName.startsWith(ignored.slice(0, -1))
      : packageName === ignored,
  );
}

async function getPackagesNames(files: string[]): Promise<string[]> {
  const ignored = await getChangesetIgnoredPackages();
  const packages: string[] = [];

  await Promise.all(
    files.map(async (file) => {
      const data = JSON.parse(await fs.readFile(file, "utf8")) as {
        name: string;
        version?: string;
        workspaces?: string[];
      };
      if (
        !shouldIgnorePackage(data.name, ignored) &&
        !data.workspaces &&
        data.version
      ) {
        packages.push(data.name);
      }
    }),
  );

  return packages;
}

async function createChangeset(
  fileName: string,
  bumps: Map<string, string>,
  packages: string[],
  sort: boolean,
) {
  const lines = [...bumps.entries()].map(
    ([pkg, v]) => `Updated dependency \`${pkg}\` to \`${v}\`.`,
  );
  if (sort) {
    packages.sort();
    lines.sort();
  }

  const header = packages.map((pkg) => `'${pkg}': patch`).join("\n");
  const body = `---\n${header}\n---\n\n${lines.join("\n")}\n`;
  await fs.writeFile(fileName, body);
}

async function getBumps(files: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  await Promise.all(
    files.map(async (file) => {
      const diff = await git.getFileDiff(file);
      for (const line of diff.split("\n")) {
        if (line.startsWith("+ ")) {
          const match = line.match(/"(.*?)"/g);
          if (match?.[0] && match[1]) {
            map.set(match[0].replace(/"/g, ""), match[1].replace(/"/g, ""));
          }
        }
      }
    }),
  );
  return map;
}

export async function main() {
  const inputs = getInputs();
  const branch = await git.getCurrentBranch();
  logger.info(`Detected branch: ${branch}`);

  if (!branch.startsWith(inputs.branchPrefix) && !inputs.skipBranchCheck) {
    logger.info("Not a renovate branch, skipping");
    return;
  }

  const changed = await git.getDiffFiles();
  logger.info(`Found changed files: ${changed.join(", ")}`);

  if (changed.some((f) => f.startsWith(".changeset"))) {
    logger.info("Changeset already exists, skipping");
    return;
  }

  const pkgFiles = changed.filter((f) => f.includes("package.json"));
  if (!pkgFiles.length) {
    logger.info("No package.json changes, skipping");
    return;
  }

  const names = await getPackagesNames(pkgFiles);
  if (!names.length) {
    logger.info("No modified packages, skipping");
    return;
  }

  const hash = await git.getShortHash();
  const filename = `.changeset/renovate-${hash}.md`;
  const bumps = await getBumps(pkgFiles);

  await createChangeset(filename, bumps, names, inputs.sortChangesets);

  if (!inputs.skipCommit) {
    await git.addFile(filename);
    await git.commit(`chore: add changeset renovate-${hash}`);
    await git.push();
  }
}

try {
  await main();
} catch (err) {
  setFailed((err as Error).message);
}
