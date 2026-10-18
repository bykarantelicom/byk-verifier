// One Markdown line per run for results/README.md: date, mode, verdict, sequences, head, Base scan, exit code.
import { readFileSync } from "node:fs";
const [file, rc, mode] = process.argv.slice(2);
let line;
try {
  const r = JSON.parse(readFileSync(file, "utf8"));
  const base = r.base_scan_error ? "not read" : r.base_scan_incomplete ? "incomplete" : "complete";
  const head = r.sequences.length ? r.sequences[r.sequences.length - 1].sequence : "none";
  line = `| ${r.as_of.slice(0, 16).replace("T", " ")} | ${mode} | ${r.passed ? "PASS" : "FAIL"} (${r.verdict}) | ${r.canonical} of ${r.checked} CANONICAL | head ${head} | Base ${base} | exit ${rc} |`;
} catch (err) {
  line = `| ${new Date().toISOString().slice(0, 16).replace("T", " ")} | ${mode} | NO RESULT (${err instanceof Error ? err.message.slice(0, 60) : String(err)}) | | | | exit ${rc} |`;
}
console.log(line);
