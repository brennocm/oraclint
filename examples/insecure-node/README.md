# insecure-node

A deliberately misconfigured Chainlink node deployment. **Do not use it.**

It exists to show what oraclint reports and is scanned by the integration
tests on every CI run, so every rule keeps firing on a realistic deployment.
All credentials are fake placeholders.

```sh
oraclint scan --experimental examples/insecure-node
```
