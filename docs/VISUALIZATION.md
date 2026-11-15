# Data visualizations (phase 14)

Traffic AL's charts are built to be *read*, not admired. Each one encodes a real aggregate the
app already computes, states in one line what it shows and how to read it, and offers a longer
hint with the caveat a cybersecurity reader needs. The colours are not chosen by taste — the
series palette is run through a colour-blindness validator so the bars and lines stay
distinguishable in both light and dark mode.

## The palette: blue first, dark orange second

The series palette is the data-viz reference ramp, led by **blue** and **dark orange** — the
"blueish dark-orange" look, made rigorous. Blue is sent / readable; orange is received /
encrypted; the meaning is held constant across every chart. Each surface (light and dark) gets
its own steps — never an automatic flip — so the hues keep their lightness band on the surface
they actually render on.

| Slot | Hue | Light | Dark |
|------|-----|-------|------|
| 1 | blue | `#2a78d6` | `#3987e5` |
| 2 | orange (dark) | `#eb6834` | `#d95926` |
| 3 | aqua | `#1baf7a` | `#199e70` |
| 4 | yellow | `#eda100` | `#c98500` |
| 5 | magenta | `#e87ba4` | `#d55181` |
| 6 | green | `#008300` | `#0ca30c` |
| 7 | violet | `#6250d6` | `#9085e9` |
| 8 | red | `#e34948` | `#e66767` |

Only the leading few slots are ever on screen at once: every aggregate folds its tail into a
single muted **"Other"** slice (the grey `outline` role), so a chart never needs more colours
than the palette's safe leading slots. The slot **order** is the colour-blind-safety mechanism —
candidate orderings were enumerated and only those clearing every gate kept.

The palette lives in `VizPalette` (`app/.../ui/common/Charts.kt`) and the two directions are
exposed as `sentColor()` (slot 1) and `receivedColor()` (slot 2), so the throughput chart, the
per-app bars and the legends all speak the same colours. Light vs dark is chosen from the
surface luminance (`chartIsDark()`), which works identically in the app and in the Compose
Desktop preview.

## Validation (don't eyeball — run the validator)

The palette is checked with the data-viz skill's `scripts/validate_palette.js` against Traffic
AL's own surfaces. All hard gates pass in both modes:

- **Lightness band**, **chroma floor**, **CVD separation** (worst adjacent ΔE 9.1 light / 8.4
  dark, target ≥ 8) and the **normal-vision floor** (worst adjacent ΔE 19.6 light / 19.3 dark,
  floor 15): **PASS** in both modes.
- **Contrast vs surface**: a **WARN** on a few slots that sit below 3:1 on the lightest surfaces
  (this is inherent to mid-tone categorical hues). The data-viz **relief rule** is satisfied —
  every chart ships a **legend with visible value labels** and text stays in ink tokens, so a
  colour never carries meaning alone.

Re-run after any palette change:

```
node <dataviz-skill>/scripts/validate_palette.js \
  "#2a78d6,#eb6834,#1baf7a,#eda100,#e87ba4,#008300,#6250d6,#e34948" --mode light --surface "#F6FAFE"
node <dataviz-skill>/scripts/validate_palette.js \
  "#3987e5,#d95926,#199e70,#c98500,#d55181,#0ca30c,#9085e9,#e66767" --mode dark  --surface "#41484D"
```

## The components (`app/.../ui/common/Charts.kt`)

- **`ChartCard`** — the frame every chart sits in: a title, a tap-to-reveal **ⓘ** hint toggle,
  an always-visible one-line **caption** (what it shows / how to read it), the plot, and the
  longer **hint** underneath when revealed. Nothing ships a chart without its reading
  instructions.
- **`ThroughputChart`** (`Components.kt`) — the sent/received area chart. **One** y-axis (bytes
  per second): the baseline is zero and the top label marks the peak rate. The x-axis runs from
  the start of the selected window (left) to **now** (right). Two series on one shared scale, so
  their heights compare directly — deliberately never a second axis.
- **`DistributionChart`** — a 100%-stacked segmented bar (2px surface gaps, muted "Other") with a
  value legend that spells out each slice's **share %, bytes and connection count** — the direct
  labels that are the relief for the contrast WARN. Weights by bytes, or by connections where
  that matches the context.
- **`LegendRow`** — swatch + label in ink tokens; identity is never colour-alone.

## Where they appear

- **Dashboard** — the throughput chart (with its legend) and a **Protocol mix** distribution
  (TLS / QUIC / HTTP / DNS / … by volume), from the new `DashboardData.protocols`.
- **Connections** — a **Protocols in view** distribution over exactly the connections shown,
  weighted by connection count, so it follows the search and filters.
- **Audit → Decryptability** — the phase-13 readable-vs-encrypted breakdown as the same
  distribution bar (blue readable / orange encrypted), above the per-app list.

## The aggregate (`core/.../analysis/Distribution.kt`)

`protocolMix(flows, maxSlots = 5)` groups flows by `protocolLabel`, largest by bytes first, and
folds everything past the slot cap into one `"Other"` slice that always sorts last — so the chart
stays inside the validated leading slots. It is pure `core` and unit-tested
(`DistributionTest`: grouping, byte/connection totals preserved across the fold, the "Other"
slice, and the empty case). `DashboardData.protocols` is computed from this.

## How it is verified

- **Palette**: the validator run above (light and dark, against the app's surfaces).
- **Logic**: `DistributionTest` in `core` (runs in CI).
- **Pixels**: the Compose Desktop preview (`tools/ui-preview`) renders the Dashboard (light and
  dark) and Connections with the real components and sample data, so the charts are screenshotted
  in CI — the throughput axes, the protocol-mix bar, the legends and the blue/orange palette are
  all on screen. The Audit decryptability card reuses the same `ChartCard` + `DistributionChart`,
  so it inherits that visual check.
