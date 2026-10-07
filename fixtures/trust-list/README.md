`C2PA-TRUST-LIST.pem` is the official C2PA conformance trust list, downloaded 2026-10-07 from
https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem
(30 certificates). `scripts/deploy.ts` anchors every entry whose key the registry can verify:
29 of 30 (RSA-4096 and P-384). The one it skips is vivo's root, which uses P-521.
