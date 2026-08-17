# GraphQL API Attack Techniques

A single GraphQL endpoint (almost always `POST /graphql`, sometimes with a
`GET` fallback) replaces an entire REST API's worth of routes with one URL
and a query language — which means the usual "enumerate every endpoint"
recon instinct doesn't apply the same way; the attack surface is inside the
query/schema itself.

## Schema discovery when introspection is "disabled"

The standard `__schema` introspection query dumps the entire object/field
graph, so production apps often try to block it — usually with a naive
string/regex filter looking for the literal substring `__schema{}` or
similar. GraphQL itself ignores whitespace/commas between tokens, so
inserting characters the filter doesn't account for still parses correctly
server-side while evading the filter:

```
query{__schema
{queryType{name}}}
```

Also try submitting the query as a `GET` with URL-encoded whitespace if POST
is filtered but GET isn't:

```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

## Bypassing rate limits / brute-force protections via aliasing

A rate limiter that counts **HTTP requests**, not **operations inside a
request**, is fully bypassable using GraphQL's alias feature — one HTTP
request can carry the same query repeated arbitrarily many times, each
under a different alias, all evaluated server-side in one pass:

```graphql
query bruteForce($code: Int) {
  attempt1: isValidDiscount(code: $code) { valid }
  attempt2: isValidDiscount(code: $code) { valid }
  attempt3: isValidDiscount(code: $code) { valid }
}
```

This turns any per-request-limited guessing target (discount/coupon codes,
2FA codes, password-reset tokens) into an effectively per-request-unlimited
one — worth checking before assuming a rate limit rules out brute-forcing a
GraphQL-backed field.

## CSRF via non-JSON content types

A GraphQL endpoint that accepts a query via `GET` params or a
`application/x-www-form-urlencoded`/`multipart/form-data` POST body (not
just `application/json`) is CSRF-able with a plain HTML form or auto-
submitting link — the browser will happily send either of those content
types cross-origin without a preflight, unlike a JSON `Content-Type`, which
forces a CORS preflight that a same-origin-only server would reject:

```html
<form action="https://target/graphql" method="POST"
      enctype="text/plain">
  <input name='{"query":"mutation{transferFunds(amount:1000)}","x":"' value='"}'>
</form>
```

## IDOR through query arguments

The same authorization gaps as any REST API can hide in a resolver argument
— `query { product(id: 3) { name, internalCost } }` where the server checks
"does this product exist" but never "is the current user allowed to see
this specific product/field." Enumerate ID-shaped arguments the same way
you would path/query parameters in REST.

## Source

Web Security Academy, "GraphQL API vulnerabilities" —
https://portswigger.net/web-security/graphql

Not yet encountered on a vault box — added from PortSwigger research ahead
of hitting it live.
