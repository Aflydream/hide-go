# Design System Master File (Swiss Editorial Light & Anti-AI Precision)

> **LOGIC:** Global Source of Truth for Hide-Go Desktop UI.
> **Style:** `minimalism-and-swiss-style` (Swiss Grid / Technical Inspector)
> **Design Dials:** Variance `2/10` (Strict Grid) | Motion `2/10` (150ms Subtle) | Density `9/10` (High-Density Inspector)

---

## 1. Anti-AI Design Rules (Mandatory)

1. **Zero Floating Card Soup**: Do NOT wrap every section in `rounded-xl p-5 shadow-sm`. Use continuous 1px hairlines (`#E4E4E7`), flush split panes, and tabular rows.
2. **Zero Soft Pastel Pill Spam**: Do NOT scatter colorful rounded-full pills across every card. Status indicators must be sharp (`rounded-[3px]`), compact (`11px` uppercase monospace), and neutral by default, reserving color strictly for semantic signals.
3. **Zero Decorative Icon Boxes**: Do NOT put every heading icon inside a `p-2 rounded-lg bg-slate-50 border` container. Use typography, index numbers (`01`, `02`, `03`), or bare 14px SVG icons aligned to the baseline.
4. **Zero Emoji & Zero AI Copy**: No emojis anywhere. No bilingual filler titles or marketing slogans. Use concise, technical, desktop utility terminology.
5. **Strict Border Radius & Shadow**: Maximum radius is `4px` (`rounded`) or `0px` (flush grid). `box-shadow: none` across all static surfaces.

---

## 2. Three-Layer Token Architecture

### Layer 1: Primitive Tokens
- `--zinc-50`: `#FAFAFA`
- `--zinc-100`: `#F4F4F5`
- `--zinc-200`: `#E4E4E7`
- `--zinc-300`: `#D4D4D8`
- `--zinc-500`: `#71717A`
- `--zinc-600`: `#52525B`
- `--zinc-800`: `#27272A`
- `--zinc-950`: `#09090B`
- `--emerald-600`: `#059669`
- `--emerald-700`: `#047857`
- `--emerald-50`: `#ECFDF5`
- `--amber-700`: `#B45309`
- `--amber-50`: `#FFFBEB`
- `--red-600`: `#DC2626`
- `--red-50`: `#FEF2F2`

### Layer 2: Semantic Tokens (Light Mode)
| Token | Value | Role |
|---|---|---|
| `--bg-canvas` | `#F4F4F5` | App outer frame / recessed well |
| `--bg-surface` | `#FFFFFF` | Primary work surface / inspector pane |
| `--bg-subtle` | `#FAFAFA` | Table header / code gutter / inactive bar |
| `--text-primary` | `#09090B` | Primary headings, active labels, code |
| `--text-secondary` | `#52525B` | Body descriptions, secondary cells |
| `--text-muted` | `#71717A` | Timestamps, endpoints, metadata |
| `--border-hairline` | `#E4E4E7` | Primary 1px grid divider |
| `--border-strong` | `#09090B` | Active selection border / primary focus |
| `--accent-brand` | `#059669` | Hide-Go emerald status & active restoration |
| `--signal-danger` | `#DC2626` | Raw secret / unmasked leak indicator |
| `--signal-warn` | `#B45309` | Chaff / telemetry interception |

### Layer 3: Density 9/10 Spacing Scale
- `--space-xs`: `2px`
- `--space-sm`: `4px`
- `--space-md`: `8px`
- `--space-lg`: `12px`
- `--space-xl`: `16px`
- `--space-2xl`: `24px`

---

## 3. Typography & Scannability

- **UI Sans**: `'Inter'`, `-apple-system`, `BlinkMacSystemFont`, `'PingFang SC'`, `'Microsoft YaHei'`, `sans-serif`
- **Technical Mono**: `'JetBrains Mono'`, `'SFMono-Regular'`, `'Menlo'`, `'Consolas'`, `monospace`
- **Numeric Discipline**: `font-variant-numeric: tabular-nums` on all counters, latencies, timestamps, and ports.
- **Hierarchy**:
  - Section Index / Column Header: `11px` (`0.6875rem`), `font-mono`, `uppercase`, `tracking-wider`, `text-zinc-500`
  - Body / Table Cell: `12px` (`0.75rem`) – `13px` (`0.8125rem`), `text-zinc-900`
  - Pane Title: `13px` (`0.8125rem`), `font-semibold`, `tracking-tight`, `text-zinc-950`
