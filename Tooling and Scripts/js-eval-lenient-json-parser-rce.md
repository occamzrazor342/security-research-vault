# `Function('return ' + input)()` as a "Lenient JSON Parser" Is RCE by Construction

A recurring anti-pattern in Node.js apps that want to accept "relaxed
JSON" from users — unquoted object keys, trailing commas, single quotes,
comments, JS-object-literal syntax in general — is reaching for the
language's own parser instead of a real data-only one:

```js
function convertToValidJSONString(inputString) {
    const jsObject = Function('return ' + inputString)()   // executes, doesn't just parse
    return JSON.stringify(jsObject, null, 2)
}
```

`Function('return ' + inputString)()` compiles and **runs** arbitrary
JavaScript — it's `eval()` in a slightly different wrapper (a new function
scope instead of the caller's own), not a parser. Anything the input string
can express as an IIFE/expression executes with the same privileges as the
Node process, `this` and `arguments` chicanery aside. There is no length of
distance between "this looks like relaxed JSON" and "this is a full RCE
sink" — they're the same code path.

## What the correct fix looks like

Real permissive-JSON libraries (JSON5, Hjson, `relaxed-json`, etc.) still
parse — they build an AST/token stream and construct the resulting value
without ever handing the runtime a `Function`/`eval` call to execute. The
fix for this exact bug (Flowise, CVE-2025-59528) was a one-line swap:

```diff
 function convertToValidJSONString(inputString) {
-    const jsObject = Function('return ' + inputString)()
+    const jsObject = JSON5.parse(inputString)
     return JSON.stringify(jsObject, null, 2)
 }
```

Same convenience syntax accepted (JSON5 tolerates unquoted keys, trailing
commas, comments), same output shape — the only thing removed is the
ability to run code, because JSON5 has no mechanism to invoke anything.

## What to look for as an attacker

- Any config/DSL field described as accepting "JS object literal" or
  "relaxed/lenient JSON" syntax, especially in workflow/no-code/low-code
  platforms (visual pipeline builders, MCP/plugin config strings, template
  engines) — these are exactly the features that reach for `Function()`/
  `eval()` as a shortcut instead of a real parser.
- Grep accessible source (if available) for `Function(` / `new Function(`
  / `eval(` anywhere near a "parse config string" helper.
- If landing code execution this way, remember `Function(...)`'s lexical
  scope is the **global** scope only — it does not close over the
  surrounding CommonJS module's local `require`. Use
  `process.mainModule.require('child_process')` (or dynamic `import()`)
  instead of a bare `require(...)` call inside the injected payload.

## Seen on

- [[Silentium#Foothold|Silentium]] — Flowise 3.0.5's CustomMCP node
  (`packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts`,
  CVE-2025-59528) parsed the `mcpServerConfig` field this way; reachable
  post-authentication only (JWT session required for ≥3.0.1), which is why
  the [[password-reset-token-in-api-response|forgot-password token leak]]
  account-takeover bug was chained in front of it as a prerequisite on this
  box rather than using the older fully-unauthenticated bypass that only
  works against Flowise <3.0.1.
