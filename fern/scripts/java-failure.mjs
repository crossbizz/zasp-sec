import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { stripVTControlCharacters } from "node:util";

// Only report a category or a Java source location in the public check name.
export function javaFailure(log) {
  const java = stripVTControlCharacters(log.split("== java: compile and test").at(-1));
  if (/No space left on device/i.test(java)) return "disk full";
  if (/OutOfMemoryError|Cannot allocate memory|insufficient memory/i.test(java)) return "memory exhausted";
  const compiler = java.match(/\/([A-Za-z_$][\w$]*\.java):\[(\d+),\d+\]/);
  if (compiler) return `compiler ${compiler[1]}:${compiler[2]}`;

  const junit = java.match(/\bat ai\.zasp\.api\.[\w.$]+\(([A-Za-z_$][\w$]*Test\.java):(\d+)\)/);
  if (junit) return `JUnit ${junit[1]}:${junit[2]}`;
  if (/There are test failures|<<< (?:ERROR|FAILURE)!/.test(java)) return "JUnit failure";
  if (/Could not transfer artifact|transfer failed for/i.test(java)) {
    const status = java.match(/status(?: code)?:\s*(\d{3})\b/i);
    return status ? `Maven artifact transfer HTTP ${status[1]}` : "Maven artifact transfer";
  }
  if (/Could not find artifact/i.test(java)) return "Maven artifact unavailable";
  if (/PluginResolutionException|DependencyResolutionException|UnresolvableModelException/.test(java)) {
    return "Maven dependency resolution";
  }
  if (/COMPILATION ERROR/i.test(java)) return "compiler failure";
  if (/Unable to start mvn: ENOENT/.test(java)) return "Maven executable missing";
  const plugin = java.match(/Failed to execute goal org\.apache\.maven\.plugins:maven-(compiler|surefire|resources)-plugin:[\w.-]+:([A-Za-z]+)/);
  if (plugin) return `Maven ${plugin[1]} ${plugin[2]}`;
  return "see Maven output";
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log(javaFailure(readFileSync(process.argv[2], "utf8")));
}
