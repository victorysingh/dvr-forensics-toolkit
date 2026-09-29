# The case console (React + Vite + Tailwind)

The UI described in `docs/UI_PLAN.md`. Source lives here; the **build output
is committed to `viewer/static/`**, which is what `packaging/ps26150.spec`
bundles into `ps26150-dvr.exe`.

Node is a **build-time tool only**. An examiner running the .exe, or an
air-gapped workstation serving the console, never needs Node, npm or this
directory.

## Running it

The Python viewer serves the built console. Nothing here is needed:

```bash
python cli.py serve --out <folder of cases> --port 8150
```

## Changing it

```bash
cd ui
npm install          # once
npm run build        # writes ../viewer/static/ - commit the result
```

`npm run build` empties `viewer/static/` and rewrites it. **Commit the built
files with your source change**, or the served console and the source will
disagree.

For a fast edit loop, run the Python viewer on 8150 and Vite alongside it —
`/api`, `/report`, `/thumb` and `/file` are proxied through:

```bash
python cli.py serve --out out --port 8150   # one terminal
cd ui && npm run dev                        # another; open the URL it prints
```

## Rules this code has to keep

From `docs/UI_PLAN.md` §1. They are not style preferences:

- **Air-gapped.** No CDN, no font host, no external URL of any kind. Tailwind
  is compiled to a local stylesheet, never loaded from `cdn.tailwindcss.com`.
  Type is the system stack. After a build, this must print nothing:
  ```bash
  grep -rniE 'https?://(?!127\.0\.0\.1|localhost)' ../viewer/static/assets/*.css
  ```
  (the JS bundle legitimately contains W3C namespace URIs and React's
  `react.dev/errors/` message text — neither is ever fetched)
- **Read-only.** The console reads what the pipeline wrote. No route here
  opens a device or writes to a case.
- **Honest statuses.** Every parsed result shows its `validation_status`
  pill. Never hide one to make a screen look tidier.
- **AI is a lead, not evidence.** Any screen showing model output carries the
  violet banner and the models' hashes — including its empty state.
- **Time is the recorder's.** Never parse a recorder timestamp into a `Date`
  and re-render it: that silently moves it into the viewer's zone. Print the
  stored string. See `clockTime` and `claimLocal` in `src/lib/format.js`.
- **Traceable numbers.** A KPI names the file it came from.

## Layout

```
src/
  main.jsx          mount
  App.jsx           shell: top bar, sidebar, stepper, routing, cases home
  index.css         Tailwind theme - the status/lead/camera colour tokens
  lib/
    api.js          every fetch, all relative to the loopback server
    format.js       bytes, durations, and the two time helpers above
    useHashRoute.js #/<case>/<screen>
  components/
    index.jsx       Pill, Hash, Kpi, DataTable, Empty, banners, toasts
  screens/          one file per screen, a pure component of the case view
```

A screen fetches nothing itself: it takes the case view and renders it. To
add one, add a file under `screens/` and an entry to `SCREENS` in `App.jsx`.

`report/case.py::load_case` is the single source of data. Add to it rather
than reading case files from the front-end.

## Where this is in the plan

`docs/UI_PLAN.md` §10. P0 (shell) and P1 (core screens) are done. Still to
come: P2 server routes (`/file` with Range, `/blockmap`, `/stamp`, the
`load_case` additions), P3 disk map + zoomable timeline + video player,
P4 live scan polling and auto-refresh, P5 polish and the .exe rebuild.
