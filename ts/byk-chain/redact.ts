/* BYK Data Layer · keeps endpoint credentials out of everything the verifier prints or writes (2026-10-18).
 *
 * A keyed RPC endpoint carries its key in the URL (Alchemy and Infura in the path, Helius in the query string), and the
 * libraries quote the full URL in their error messages (viem: "URL: https://..."). The verifier's JSON and its stderr are
 * committed to a public repository by the daily GitHub Actions run, so every message that may contain a URL passes through
 * here first: scheme and host stay (a reader should know which endpoint was read), path and query go. */

const URL_IN_TEXT = /\b((?:https?|wss?):\/\/)([^\s"'<>`)[\]]+)/gi;
const MARKER = "[redacted]";

/** Every URL in `text` cut down to scheme and host, userinfo dropped as well; the marker is appended only when something
 *  was actually cut, so a bare public endpoint reads as it was. Text without a URL is returned unchanged, and so is a URL
 *  already cut (the function is idempotent: a message may be redacted when caught and again when printed). */
export function redactUrls(text: string): string {
  return text.replace(URL_IN_TEXT, (m: string, scheme: string, rest: string, offset: number, whole: string) => {
    if (whole.startsWith(MARKER, offset + m.length)) return m; // already cut
    const end = rest.search(/[/?#]/);
    const authority = end >= 0 ? rest.slice(0, end) : rest;
    const host = authority.includes("@") ? authority.slice(authority.lastIndexOf("@") + 1) : authority;
    const cut = authority !== host || (end >= 0 && rest.length > end + 1);
    return cut ? `${scheme}${host}/${MARKER}` : `${scheme}${host}`;
  });
}

/** The host of an endpoint for a "read from" line: never the path or the query, which is where keys live. */
export function endpointHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return redactUrls(url);
  }
}

/** One line of at most `max` characters for a log line or a JSON field: whitespace collapsed, URLs cut to their host. */
export function oneLine(text: string, max = 200): string {
  return redactUrls(text).replace(/\s+/g, " ").trim().slice(0, max);
}
