# Security policy

## Supported versions

Security fixes go into the latest release on
[pub.dev](https://pub.dev/packages/tlsa_resolver). While the package is at
0.x, there are no separate maintenance branches: upgrade to the latest
version to get a fix.

## Reporting a vulnerability

Please report security problems privately through
[GitHub's security advisories](https://github.com/mebur/tlsa_resolver/security/advisories/new),
not in public issues.

Useful things to include:

* what an attacker can do, and from where (the network path, the resolver,
  a zone they control, a TLS server);
* the name, record type and transport involved, or the response bytes;
* the `SecurityStatus`, `ValidationError` and `reason` you got, and what
  you expected.

Reports are acknowledged in the advisory, worked on there, and published
with the fixed release and credit to the reporter unless they prefer
otherwise.

## Scope

In scope: anything that makes the validator report forged or altered data
as secure, a signed answer as insecure (a downgrade), a failure as
something other than bogus or indeterminate, or that lets a resolver,
zone or server crash a lookup or keep it busy far beyond its time budget;
and mistakes in DANE matching.

Out of scope: denial of service by a resolver that simply does not answer
(lookups then fail, as they must), and the known limits listed in the
README's Status section.
