# likzik-ui: design system and rules

The dashboard (`likzik-ui`) follows the **Likzik config console** design.
The reference mockups are in `docs/design/console/` (routes, add-route,
review-publish, sources-status). They render with a design-tool runtime,
but their markup and inline styles are the source of truth for layout,
spacing and copy. Read the relevant one before changing a screen.

## Architecture (do not change without reason)

- React 19 + Vite + TypeScript in `src/ui/web`. `npm run build` type
  checks, builds `web/dist/` and regenerates `src/ui/assets.zig`
  (`scripts/embed.mjs`), which `main.zig` embeds with `@embedFile`.
  Commit `dist/` and `assets.zig` with every UI change so `zig build`
  needs no Node. Never edit `assets.zig` by hand.
- Layout of `src/`:
  - `types.ts`: the config file and admin API shapes.
  - `model.ts`: pure logic (route listing, diff, overlap, checks). Keep
    it free of React and test it in `model.test.ts`.
  - `api.ts`: the likzik-ui HTTP API.
  - `store.tsx`: live config, draft, status polling and the hash router.
  - `components/`: the design-system primitives (`ui.tsx`), the shell,
    schema forms for table + aside screens (`Form.tsx`), history.
  - `pages/`: one file per screen.
- No external assets. Fonts come from `@fontsource` (IBM Plex, SIL OFL)
  and are bundled. The CSP in `main.zig` allows only `'self'` for
  scripts, styles and fonts: no inline `<script>`, no CDN links. React
  `style` props are fine (they go through the CSSOM).
- Routing is by `#hash`; the server returns `index.html` for any
  non-API path, and caches `/assets/*` forever (file names are hashed).
- The server (`src/ui/main.zig`) only reads/writes the config file, keeps
  the change history, and proxies allow-listed GETs to the proxy's admin
  endpoint. It must not need changes to the proxy core.
- All edits go to a client-side **draft** (a copy of the config JSON).
  Nothing is written until "Publish": validate with the proxy's own
  `--check`, keep history, atomically replace the file, wait for the new
  generation.

## Honesty rule

The mockups show features likzik does not have yet (mTLS client identity,
a shared rate limit service, per-listener drain progress, delta xDS,
notifications, user accounts). Retry policies, request mirroring, active
health checks and xDS exist in the proxy now, but the console does not
edit them yet: show them only from the config file or `/stats`.
**Never render fake data or controls for
them.** Either omit the element, or show it as a dashed "not available
in this version" panel when the layout depends on it. Every number on
screen comes from the config, the admin endpoint, or the change history.

## Color tokens

| Token | Hex | Use |
| --- | --- | --- |
| `--ink` | `#151515` | Text, every border, primary button fill |
| `--paper` | `#F4F1EB` | Page background, inputs, secondary buttons |
| `--panel` | `#EAE6DD` | Panels (sections, tables, the detail aside) |
| `--lime` | `#D7F98A` | Header, sidebar, selected row, the "route" box, active choice |
| `--lime-ink` | `#3A4A1A` | Muted text on lime |
| `--muted` | `#45443F` | Secondary text |
| `--rule` | `#B9B4A8` | Row separators (1px), unselected choice borders |
| `--warn-bg` / `--warn-line` / `--warn-ink` | `#FCE7BF` / `#8A4A00` / `#6E3B00` | Draft banner, "Edited"/"New" badges, warnings |
| `--ok-bg` / `--ok-line` / `--ok-ink` | `#E2F0DE` / `#256B40` / `#1E5634` | "Passed", "Applied", healthy |
| `--err-bg` / `--err-line` / `--err-ink` | `#F8E1DE` / `#A3241B` / `#7E1A13` | Rejected, delete buttons, errors |
| white | `#FFFFFF` | Text on ink |

Light only: the design has no dark variant. Do not invent one.

## Type

- **IBM Plex Sans** for everything: 15px/1.5 body, 13px for help and
  table secondary text, 12px for badges. Weights 400/500/600/700.
- **IBM Plex Mono** for things a person could type into the config:
  paths, methods, addresses, cluster names, generations, header names,
  and for page titles (h1: 40px, 700, letter-spacing -0.02em, line-height
  1.1). Panel titles (h2) are Sans 16px 600.
- The small uppercase eyebrow ("Gateway console") appears only above the
  page h1, as in the mockups. Do not add more labels like it.

## Shape and layout

- Square corners everywhere. Borders are `2px solid var(--ink)` for
  containers and controls; `1px solid var(--rule)` for table row rules.
  No shadows, no gradients, no rounded anything.
- Header: lime, 56px, 2px bottom border: menu toggle, logo block (30px
  ink square with a lime "L" + "Likzik" in Mono 700 17px), search, then
  live status on the right.
- Sidebar: lime, ~240px, 2px right border. Top-level items 44px tall with
  an 18px stroke icon; "Routing" expands to Listeners / Routes / Clusters
  (indented 42px). The current page gets the paper background and 600
  weight. The draft-change count is an ink badge on "Routing".
- Main: paper background, 32px padding, 20px gaps. Page head: eyebrow +
  Mono h1 on the left, actions on the right (44px controls).
- Two-column screens use flex-wrap: content `flex: 999 1 560px`, aside
  `flex: 1 1 380px; max-width: 460px`. Everything wraps to one column on
  narrow screens.

## Components

- **Buttons** (min-height 44px; 40px inside panels): primary = ink fill,
  white 600 text; secondary = paper fill, ink border; danger = paper fill,
  `--err-line` border and text. Disabled primary uses `--rule` fill.
- **Inputs**: 42px min height, 2px ink border, paper fill, Mono for
  config values. Labels above, 13px 600. Help text below, 13px muted.
- **Segmented choice** (match kind, methods, auth): a 2px ink box of
  buttons; the active one is ink with white text.
- **Radio cards** (auth kind, destination): 10–12px padding; selected =
  2px ink border + lime fill, otherwise 1px rule border + paper.
- **Badges**: 12px, 1px border, 1px 7px padding. Neutral = ink border +
  paper. Edited/New = warn colors. Passed/Applied = ok colors.
  Rejected = err line + white fill.
- **Tables**: in a panel; header row 13px muted 500; rows separated by
  1px rule; the selected row is lime with an inset 4px ink bar on the
  left.
- **Tabs**: text buttons with a 3px ink bottom border when active.
- **Draft banner**: warn background, 2px ink border, bold count + one
  sentence about generations.
- **Pipeline** ("How a request travels"): boxes joined by 24px 2px ink
  connectors; the route box is lime and lists its steps numbered (it is
  a real sequence).

## Copy

- Sentence case, plain verbs, the user's words: "Add route", "Save to
  draft", "Discard draft", "Review and publish", "Publish generation N",
  "Roll back to generation N". An action keeps its name through the flow
  (publish → "Published generation N").
- Explain consequences in terms of generations and workers: "Workers keep
  serving generation 41 until you publish."
- Errors say what is wrong and how to fix it, using the validator's own
  message. Empty states invite the next action.

## Accessibility

Visible focus (`outline: 3px solid var(--ink); outline-offset: 2px`),
hit targets ≥ 40px, real `<label>`s, `aria-current` on the nav item,
`role=tablist`/`aria-selected` on tabs, `aria-pressed` on toggles,
`role=progressbar` with values. Respect `prefers-reduced-motion` (there is
almost no motion anyway).

## Verifying changes

Run `npm test` and `npm run build` in `src/ui/web`, then `zig build`; run `likzik-gw` with a demo config and `likzik-ui`
next to it, and take Playwright screenshots of every screen at 1440px
and 390px wide; check for console errors. Compare against the mockups in
`docs/design/console/`.
