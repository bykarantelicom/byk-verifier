// One Markdown line per run for results/README.md: date, mode, verdict, sequences, head, Base witness, exit code.
import { readFileSync } from "node:fs";
const [file, rc, mode] = process.argv.slice(2);
let line;
try {
  const r = JSON.parse(readFileSync(file, "utf8"));
  const head = r.sequences.length ? r.sequences[r.sequences.length - 1].sequence : "none";
  const scan = r.base_scan ?? null;
  let base;
  if (r.base_scan_error) base = "not read";
  else if (scan && scan.mode === "windows") {
    // windows mode (2026-10-18): the expected copies found, the ones missing from their window, the windows still open
    base = `${r.base_scan_incomplete ? "incomplete" : "complete"}, copies ${scan.found} of ${scan.copies}${scan.missing ? ` (${scan.missing} missing)` : ""}${scan.open ? ` (${scan.open} open)` : ""}${scan.not_walked ? ` (${scan.not_walked} not walked)` : ""}`;
  } else base = r.base_scan_incomplete ? "incomplete" : "complete";
  line = `| ${r.as_of.slice(0, 16).replace("T", " ")} | ${mode} | ${r.passed ? "PASS" : "FAIL"} (${r.verdict}) | ${r.canonical} of ${r.checked} CANONICAL | head ${head} | Base ${base} | exit ${rc} |`;
} catch (err) {
  line = `| ${new Date().toISOString().slice(0, 16).replace("T", " ")} | ${mode} | NO RESULT (${err instanceof Error ? err.message.slice(0, 60) : String(err)}) | | | | exit ${rc} |`;
}
console.log(line);
