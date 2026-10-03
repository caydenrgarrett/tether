# Design direction

The reference is [spacefs.com](https://spacefs.com/): clean, smooth, quiet and expensive-looking. Match the feel, not the content. Don't reuse its logo, imagery, copy or branding. Values below were read off screenshots, so they're approximate. Tune them by eye.

## What makes it work

1. **Almost monochrome.** The UI is neutral gray, near-black and white. Color comes only from imagery and one soft decorative background. Status color (red, green, amber) should be the only saturated thing on a screen, so it pops.
2. **Big, tight type with a two-tone headline.** Line one is near-black and line two is slate gray: "Find anything. / *Ask anything.*"
3. **Everything floats.** Controls are pills and circles with soft, diffuse shadows over a light textured background. There are no hard borders and no boxed header bar.
4. **Lots of air.** Content is narrow and centered, with large vertical gaps between sections.
5. **Glass on top of things.** Overlays such as command bars and result lists are translucent and blurred, so they feel part of what's behind them.

## Tokens

```css
:root {
  /* surfaces */
  --bg:            #f1f2f4;   /* cool off-white page, with a faint grain/noise overlay */
  --surface:       #ffffff;   /* pills, cards */
  --surface-glass: rgba(255,255,255,.55);  /* + backdrop-filter: blur(24px) saturate(1.4) */
  --hairline:      rgba(17,18,20,.08);

  /* text */
  --ink:           #111214;   /* headlines, primary buttons */
  --ink-2:         #5f6571;   /* second headline line, slate */
  --muted:         #6e737c;   /* body copy */
  --faint:         #9aa0a9;   /* metadata, mono numerals */

  /* decorative only (background particle field) */
  --dust-blue:     #8fa3c8;
  --dust-clay:     #d99a7c;

  /* shape */
  --r-pill: 999px;
  --r-card: 24px;
  --r-row:  14px;
  --shadow-float: 0 1px 2px rgba(17,18,20,.04), 0 8px 24px rgba(17,18,20,.06);
  --shadow-window: 0 2px 6px rgba(17,18,20,.05), 0 30px 80px rgba(17,18,20,.12);

  /* motion */
  --ease: cubic-bezier(.22, 1, .36, 1);  /* fast out, long soft settle */
  --dur:  420ms;
}
```

Dark mode isn't shown on the reference. If we add it, keep the same restraint: a deep neutral background (`#0e0f11`), the same glass treatment, and the same two-tone headline.

## Typography

- **Family:** a modern geometric grotesk with tight default spacing, such as Geist, Inter Display or General Sans. Use a monospace (Geist Mono, JetBrains Mono) for numerals, hashes, paths and IDs.
- **Hero headline:** 80–96px desktop, weight 600, `letter-spacing: -0.035em`, `line-height: 1.02`. Two lines in `--ink` then `--ink-2`.
- **Section headline:** 56–64px, weight 600, left-aligned, same tight tracking.
- **Row title:** 40–48px, weight 500.
- **Body:** 18–20px, weight 400, `--muted`, `line-height: 1.6`, max width about 640px. Center it under a centered hero.
- **Small labels:** 13–14px. Numbered markers (`01`, `02`) in mono, `--faint`.

## Components

| Component | Spec |
|---|---|
| **Header** | No bar. Three floating pieces: a white circular logo button (56px, `--shadow-float`) on the left, a centered white "Menu" pill with a hamburger icon, and a black `--ink` "Download"-style primary pill on the right. |
| **Primary button** | `--ink` background, white text, fully rounded, 48–64px tall, medium weight. It lifts slightly on hover (1px up, deeper shadow). |
| **Secondary pill** | White, hairline border or float shadow, ink text. |
| **Badge** | Small white pill with a hairline border and muted text, e.g. "Backed by …". |
| **Segmented tabs** | A pill track holding icon+label tabs. The active tab is a white pill with a float shadow. Icons are 1.5px-stroke line icons. |
| **Window / card** | Radius 20–28px, `--shadow-window`. It shows the product itself, mocked like a real app window, with a sidebar, toolbar pills and a breadcrumb footer. |
| **Command bar** | A large glass pill (64–72px tall) with placeholder text and a hint on the right ("Show commands ↓"). Results sit in a glass panel underneath. Each row has an icon, a name, a mono path in `--faint`, and the type right-aligned. The selected row has a soft tinted fill, not an outline. Keyboard hints appear as tiny keycaps. |
| **Feature list** | Full-width rows separated by hairlines. Each row has a mono number, a big title, and a gray description in a right-hand column. |
| **Background** | A light grain plus a slow particle "wave" (stippled dots, blue on one side and clay on the other) behind the hero. Keep it subtle and decorative, and turn it off under `prefers-reduced-motion`. |

## Motion

- Content fades and rises (8–16px) on scroll into view, using `--ease` with short staggers.
- Demos animate themselves: text types into the command bar, results appear row by row, and selection glides between rows.
- Hover states are quick (150ms). Layout moves are slower (400ms+). Nothing bounces.
- Respect `prefers-reduced-motion`.

## Applying it to tether

- **Review app:** the floating header uses a logo circle on the left, a centered pill with Review, History and Activity tabs, and the reviewer plus audit badge as pills on the right. Use the light textured background. Workspaces become glass cards. Diffs sit in "window" cards. Approve is the black primary pill.
- **Command bar:** "Search or ask tether…" jumps to workspaces, files, agents and log entries. Results use the glass list described above.
- **Headlines:** two-tone, e.g. "Every agent action. / *Reviewed, versioned, reversible.*"
- **Status color is the exception to monochrome.** Muted red for denied and flagged, muted green for merged and verified, amber for modified. Use it sparingly, so a flag is the most visible thing on the screen.
- **Security rules still apply.** Agent-supplied content is always rendered as text. Keep the CSP, Host check and token check. No third-party scripts. Self-host fonts or fall back to the system stack.
