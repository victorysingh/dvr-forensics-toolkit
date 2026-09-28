# Generated parsers - do not edit

`dahua_dhfs41.py` and `hikvision_ps.py` are generated from `../dahua_dhfs41.ksy`
and `../hikvision_ps.ksy` by the official **kaitai-struct-compiler 0.11.0**.
Edit the `.ksy`, then rebuild these.

They are **not** what the tool runs: the parsers in `parsers/` and `recover/`
are hand-written (`docs/TECH_STACK.md`). These exist so that
`python -m validate.ksy_check` can check the published format definitions
against the hand-written parsers, field by field (`VALIDATION_REPORT.md` §9a).
They need the Kaitai runtime: `pip install kaitaistruct` (0.11 or later).

## Rebuilding

With Java: `kaitai-struct-compiler -t python --outdir formats/generated formats/*.ksy`.

Without Java, as done on 28 Sep 2026: the compiler's JavaScript build from npm
(`npm install --ignore-scripts kaitai-struct-compiler`), run by Node.js, called
through its API - the `.ksy` is loaded as YAML, passed as JSON:

```js
const c = require("kaitai-struct-compiler");
const compiler = typeof c === "function" ? new c() : c;
compiler.compile("python", ksyAsJson, null, false)
        .then(files => { /* write each {name: source} to formats/generated/ */ });
```
