import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

// Test-runner cleanup only. kill(0) also sees unreaped Linux zombies, which
// cannot execute or retain a native server. Every other state remains live.
export async function ownedProcessGroupAlive(group, {
  platform = process.platform, procRoot = "/proc", probe = process.kill,
  readStat = (path) => readFile(path, "utf8"),
} = {}) {
  if (!Number.isSafeInteger(group) || group < 1) throw new Error("invalid owned process group");
  try { probe(-group, 0); } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
  if (platform !== "linux") return true;
  const pids = async () => (await readdir(procRoot)).filter(pid => /^[1-9][0-9]*$/.test(pid)).sort();
  const inspect = async (pid) => {
    let stat;
    try { stat = await readStat(join(procRoot, pid, "stat")); } catch (error) {
      // The vanished process may have forked a child after enumeration. Its
      // absence is uncertainty, not evidence that the owned group is dead.
      if (error.code === "ENOENT" || error.code === "ESRCH") return null;
      throw error;
    }
    // comm may contain whitespace and parentheses. Fields after its final ')'
    // begin with state, parent pid, process group, and session id.
    const close = stat.lastIndexOf(")");
    const fields = stat.slice(close + 2).trim().split(/\s+/);
    if (!stat.startsWith(`${pid} (`) || close < 0 || !/^[A-Za-z]$/.test(fields[0]) || !/^\d+$/.test(fields[1]) || !/^\d+$/.test(fields[2])) {
      throw new Error(`cannot inspect process metadata for ${pid}`);
    }
    return { state: fields[0], group: fields[2] };
  };
  const before = await pids();
  const dead = [];
  for (const pid of before) {
    const member = await inspect(pid);
    if (!member) return true;
    if (member.group !== String(group)) continue;
    if (member.state !== "Z" && member.state !== "X") return true;
    dead.push(pid);
  }
  // /proc is not atomic. Accept only observed dead membership, with stable
  // enumeration and repeated member reads; any churn stays conservatively live.
  if (dead.length === 0 || JSON.stringify(before) !== JSON.stringify(await pids())) return true;
  for (const pid of dead) {
    const member = await inspect(pid);
    if (!member || member.group !== String(group) || (member.state !== "Z" && member.state !== "X")) return true;
  }
  return JSON.stringify(before) !== JSON.stringify(await pids());
}
