# Loom public design system

## Visual thesis

Loom is a living map of work. A request enters as one route, branches through the current world,
domain knowledge, planning, verification, and learning, then reconverges as an execution-ready
plan. The public identity rejects the generic AI-dashboard hero and the decorative weaving
metaphor. Navigation, proof, controls, and motion all use the grammar of terrain, routes, survey
marks, field notes, and sealed map revisions.

## Color

- `--ink: #0a0b0a` is the primary text, route, and dark-field color.
- `--paper: #f5f5ed` is the reading surface.
- `--signal: #dafa3f` is the living terrain field and primary action color.
- `--cobalt: #1646d8` marks selected routes, links, and verified state.
- `--muted: #5f625a` supports secondary copy on paper.
- `--line: #b8baae` carries contours and non-authoritative boundaries.
- `--alert: #b72b24` is reserved for blocked or unsafe states.

Signal owns large page regions. Cobalt is functional, not decorative. There are no gradients.

## Typography

Use installed workhorse sans-serif faces only so the public site remains offline-capable:

- Display: `"Arial Black", "Helvetica Neue", "Segoe UI", sans-serif`
- Text and controls: `"Aptos", "Segoe UI", Arial, sans-serif`
- Code and exact measurements only: `"Cascadia Code", "SFMono-Regular", Consolas, monospace`

Headlines are blunt and compact with restrained negative tracking. Body copy stays between 65 and
72 characters per line. Uppercase is limited to route labels, evidence stamps, and map keys.

## Composition

- The first viewport is a map, not a header plus feature cards.
- A single input route enters from the left, branches through Loom's five governing systems, and
  terminates in a sealed plan at the lower edge.
- Major sections alternate between wide terrain fields, quiet paper reading passages, and dense
  evidence ledgers.
- Rules, coordinates, contour labels, and route arrows organize space. Same-size feature-card
  grids do not.
- Page actions sit at natural route junctions rather than floating as generic pills.

## Components

- **Route line:** 3px ink or cobalt SVG path with directional markers and visible junctions.
- **Terrain field:** flat signal or ink region with low-contrast SVG contour lines.
- **Survey label:** compact uppercase functional label tied to a real section or state.
- **Evidence stamp:** square or circular content-bound status mark, never a decorative badge.
- **Map key:** plain legend explaining line states and proof types.
- **Field note:** paper block attached to a path, used only for a concrete request or decision.
- **Sealed plan:** strong rectangular terminus with exact version, state, and verification label.

## Motion

One authored route event carries the experience. The input line draws into the map, branches
activate as the pointer or keyboard selects a request, and the plan seal lands after the final
verified branch. Contours drift subtly to suggest a changing world. Content is visible before
motion, and `prefers-reduced-motion` removes drawing, drift, and parallax without hiding meaning.

## Interaction and state

- Every interactive route is a native button, link, or tab with a visible focus ring.
- Hover and focus thicken the selected route and reveal its plain-language consequence.
- Loading shows a bounded route traversal; it never spins indefinitely.
- Blocked state stops before the seal, changes to alert red, and explains the one required action.
- Unknown-domain state keeps the route open but marks the terrain as unsurveyed.
- Copy controls state exactly what was copied and how to recover if clipboard access fails.

## Responsive behavior

Desktop shows the complete branching terrain. Mobile linearizes the selected branch and preserves
back-markers to every junction. The map never requires horizontal scrolling. Labels remain
readable at 200% zoom, the primary action stays visible in the first viewport, and touch targets
remain at least 44px.

## Accessibility

The document order carries the complete story without SVG or JavaScript. Decorative contours are
hidden from assistive technology. Every visualization has a textual equivalent. Signal yellow is
paired with ink, never white. Motion is optional, focus is never suppressed, and status changes
use polite live regions.
