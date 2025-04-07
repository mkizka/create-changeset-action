import { getInput } from "@actions/core";

export function getInputs() {
  return {
    branchPrefix: getInput("BRANCH_PREFIX") || "renovate/",
    skipCommit: !!getInput("SKIP_COMMIT"),
    skipBranchCheck: !!getInput("SKIP_BRANCH_CHECK"),
    sortChangesets: !!getInput("SORT_CHANGESETS"),
  };
}
