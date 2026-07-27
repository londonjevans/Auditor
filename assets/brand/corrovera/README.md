# Corrovera Security brand system

Corrovera Security is the public identity for evidence-led, multi-agent security assurance.
The visual system represents independent lines of analysis converging on a verified center.

**Tagline:** Independent minds. Corroborated truth.

## Domain architecture

| Domain | Role | Use |
| --- | --- | --- |
| `corrovera.com` | Primary identity | Company, services, trust center, reports, and contact |
| `corrovera.ai` | Audit engine | Product experience, engine documentation, and model-assisted workflows |
| `corrovera.io` | Developer platform | CLI, API, SDKs, integrations, and technical documentation |

Always use `corrovera.com` as the default public address. Use the other domains only when the
destination clearly belongs to the engine or developer platform.

## Core idea

The Corrovera mark is built from four independent evidence paths and a crystalline center. The
paths may differ in direction and color, but their conclusion is shared. This is the visual
shorthand for corroboration: multiple independent observations resolving into defensible evidence.

The mark is not a shield, lock, bug, robot, or hacker symbol. Do not enclose it in those shapes or
pair it with stock cybersecurity imagery.

## Logo files

Use SVG masters whenever possible. PNG exports are supplied for applications that cannot use SVG.

| Need | Preferred asset |
| --- | --- |
| Default horizontal logo | `logos/corrovera-lockup-horizontal.svg` |
| Horizontal logo on dark backgrounds | `logos/corrovera-lockup-horizontal-reversed.svg` |
| Compact or centered layout | `logos/corrovera-lockup-stacked.svg` |
| Symbol only | `logos/corrovera-mark-color.svg` |
| Single-color dark symbol | `logos/corrovera-mark-midnight.svg` |
| Single-color light symbol | `logos/corrovera-mark-reversed.svg` |
| Wordmark only | `logos/corrovera-wordmark-midnight.svg` |

Maintain clear space of at least one quarter of the mark width on every side. Do not render the
full lockup below 180 px wide or the standalone mark below 24 px. Do not rotate, stretch, outline,
recolor, add shadows, or rearrange the lockup.

## Color

| Token | Hex | Role |
| --- | --- | --- |
| Midnight | `#08131E` | Primary dark field |
| Ink | `#0D2030` | Primary text on light surfaces |
| Slate | `#365163` | Secondary text and rules |
| Mist | `#D9E4E8` | Secondary text on dark surfaces |
| Paper | `#F6F4EE` | Editorial light field |
| Verification teal | `#2CE0C2` | Verified evidence and active emphasis |
| Corroboration cobalt | `#5870FF` | Independent analytical path |
| Signal amber | `#E7B75F` | Sparse signals and cautions |

For normal body text, use Paper, Mist, or Teal on Midnight, and Ink or Slate on Paper. These pairs
meet WCAG AA contrast for normal text. Cobalt on Midnight is acceptable at `4.61:1`, but reserve it
for larger text, controls, diagrams, and accents when possible.

Finding severity colors are defined in `tokens/corrovera-brand-tokens.json`. Severity must always be
communicated with a text label or icon as well as color.

## Typography

- **Inter** is the preferred display and body family.
- **IBM Plex Mono** is the preferred family for hashes, identifiers, evidence references, and data.
- The supplied CSS and SVG templates include safe system fallbacks.
- Use sentence case for prose and titles. Use spaced uppercase only for short labels and eyebrows.
- Keep line lengths restrained and layouts editorial; dense evidence should feel ordered, not busy.

No font files are redistributed in this kit. Confirm the applicable font licenses and install or
self-host the selected families for production.

## Imagery

The generated master imagery is in `imagery/`:

- `corrovera-hero-master.png` — wide brand hero with left-side copy space.
- `corrovera-report-cover-art.png` — portrait report-cover composition.
- `corrovera-avatar-art.png` — detailed square convergence artwork.
- `corrovera-evidence-pattern.svg` — repeatable vector evidence-path pattern.
- `corrovera-watermark.svg` — low-contrast document watermark.

Use the crystalline center as the point of visual resolution. Evidence paths may extend beyond a
crop, but the center should remain calm and legible. Avoid cyberpunk glow, noisy particles,
futuristic dashboards, locks, shields, hooded figures, circuit brains, and generic code imagery.

The exact generation prompts and mode are preserved in `generation-prompts.md`.

## Templates and exports

| Asset | Intended use |
| --- | --- |
| `templates/report-cover-a4.svg` | Editable audit-report cover |
| `templates/report-page-header.svg` | Report running header |
| `templates/report-page-footer.svg` | Report running footer |
| `templates/report-print.css` | Branded HTML/PDF print stylesheet |
| `templates/severity-badges.svg` | Finding severity and resolved states |
| `templates/letterhead-a4.svg` | Formal correspondence |
| `templates/presentation-title-16x9.svg` | Presentation title master |
| `templates/business-card-front.svg` | Contact side |
| `templates/business-card-back.svg` | Brand side |
| `templates/email-signature.html` | Portable email-signature starter |
| `social/open-graph-1200x630.svg` | Website and link-preview card |
| `social/linkedin-banner-1584x396.svg` | Company-page banner |
| `icons/site.webmanifest` | Web-app identity manifest |

Each editable SVG template has a matching PNG preview/export. Replace brace-delimited placeholder
text before production use. Preserve report identifiers, dates, classification, scope, and evidence
hashes as selectable text in the final document.

`report-print.css` targets generic HTML produced from the generated Markdown report. Its paged-media
headers and footers require a renderer with CSS paged-media support; unsupported renderers still
receive the core typography, color, table, code, and cover styling.

## Digital implementation

Use `tokens/corrovera.css` for web prototypes and
`tokens/corrovera-brand-tokens.json` as the platform-neutral source of truth. Icon exports cover
browser favicons, Apple touch icons, Android/PWA icons, transparent marks, and detailed app icons.

The compact vector mark is preferred for favicons. The more detailed generated app icon is intended
for app stores, launchers, and large social avatars.

## Voice

Corrovera communicates with calm precision. Prefer:

- evidence, assurance, corroboration, scope, validation, and remediation;
- direct qualifications where evidence is incomplete;
- specific outcomes and reproducible references.

Avoid claims of perfect security, guaranteed detection, or unqualified comprehensiveness. The
identity should feel rigorous because the evidence is rigorous, not because the language is loud.
