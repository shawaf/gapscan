import type { JSX } from "preact";

// Decorative pictures for the domain cards, drawn inline (the Control Center stays fully offline). Colors come
// from the card's tone variables, so every picture follows the theme and the soft or classic look.
const ART: Record<string, JSX.Element> = {
  security: (
    <>
      <rect class="p s" x="56" y="16" width="170" height="88" rx="8" />
      <path class="s" d="M56 32h170" />
      <circle class="t" cx="68" cy="24" r="2.5" /><circle class="t" cx="78" cy="24" r="2.5" /><circle class="t" cx="88" cy="24" r="2.5" />
      <rect class="m" x="70" y="44" width="58" height="5" rx="2.5" />
      <rect class="m" x="70" y="56" width="96" height="5" rx="2.5" />
      <rect class="f" x="64" y="66" width="150" height="13" rx="3" />
      <rect class="t" x="78" y="70" width="78" height="5" rx="2.5" />
      <rect class="m" x="70" y="88" width="66" height="5" rx="2.5" />
      <path class="p s" d="M250 28l26 10v22c0 17-11 29-26 35-15-6-26-18-26-35V38z" />
      <path class="s w" d="M238 61l8 8 16-16" />
    </>
  ),
  standards: (
    <>
      <rect class="p s" x="132" y="10" width="92" height="96" rx="6" transform="rotate(6 178 58)" />
      <rect class="p s" x="104" y="16" width="92" height="96" rx="6" />
      {[34, 52, 70].map((y) => <g key={y}><rect class="s" x="116" y={y} width="11" height="11" rx="2" /><path class="s" d={`M118.5 ${y + 5.5}l2.5 2.5 4.5-5`} /><rect class="m" x="134" y={y + 3} width="48" height="5" rx="2.5" /></g>)}
      <rect class="s dash" x="116" y="88" width="11" height="11" rx="2" /><rect class="f" x="134" y="91" width="40" height="5" rx="2.5" />
      <circle class="f" cx="222" cy="86" r="19" /><circle class="p s" cx="222" cy="86" r="13" />
      <path class="s" d="M212 100l-5 14 9-4 4 8 3-11M232 100l5 14-9-4-4 8-3-11" />
      <path class="s w" d="M216 86l4 4 8-8" />
    </>
  ),
  industry: (
    <>
      <path class="s dash" d="M74 100h174" />
      {[52, 110, 168, 226].map((x) => <g key={x}><rect class="p s" x={x} y="30" width="44" height="44" rx="10" /><path class="s" d={`M${x + 22} 74v26`} /><circle class="t" cx={x + 22} cy="100" r="3.5" /></g>)}
      <rect class="s" x="60" y="42" width="28" height="20" rx="3" /><path class="s" d="M60 48h28" /><rect class="t" x="64" y="55" width="9" height="3" rx="1.5" />
      <path class="s w" d="M114 54h8l4-10 6 20 4-10h14" />
      <path class="s" d="M174 66V50l7 5v-5l7 5v-5l7 5V40h5v26z" />
      <path class="s" d="M232 60l4-9h16l4 9v7h-24z" /><circle class="t" cx="238" cy="67" r="3" /><circle class="t" cx="250" cy="67" r="3" />
    </>
  ),
  eu: (
    <>
      <path class="t" d="M202.0 55.8L203.1 58.5L206.0 58.7L203.7 60.6L204.5 63.4L202.0 61.8L199.5 63.4L200.3 60.6L198.0 58.7L200.9 58.5zM196.4 76.8L197.4 79.5L200.4 79.7L198.1 81.6L198.8 84.4L196.4 82.8L193.9 84.4L194.7 81.6L192.4 79.7L195.3 79.5zM181.0 92.2L182.1 94.9L185.0 95.1L182.7 96.9L183.5 99.8L181.0 98.2L178.5 99.8L179.3 96.9L177.0 95.1L179.9 94.9zM160.0 97.8L161.1 100.5L164.0 100.7L161.7 102.6L162.5 105.4L160.0 103.8L157.5 105.4L158.3 102.6L156.0 100.7L158.9 100.5zM139.0 92.2L140.1 94.9L143.0 95.1L140.7 96.9L141.5 99.8L139.0 98.2L136.5 99.8L137.3 96.9L135.0 95.1L137.9 94.9zM123.6 76.8L124.7 79.5L127.6 79.7L125.3 81.6L126.1 84.4L123.6 82.8L121.2 84.4L121.9 81.6L119.6 79.7L122.6 79.5zM118.0 55.8L119.1 58.5L122.0 58.7L119.7 60.6L120.5 63.4L118.0 61.8L115.5 63.4L116.3 60.6L114.0 58.7L116.9 58.5zM123.6 34.8L124.7 37.5L127.6 37.7L125.3 39.6L126.1 42.4L123.6 40.8L121.2 42.4L121.9 39.6L119.6 37.7L122.6 37.5zM139.0 19.4L140.1 22.2L143.0 22.3L140.7 24.2L141.5 27.0L139.0 25.4L136.5 27.0L137.3 24.2L135.0 22.3L137.9 22.2zM160.0 13.8L161.1 16.5L164.0 16.7L161.7 18.6L162.5 21.4L160.0 19.8L157.5 21.4L158.3 18.6L156.0 16.7L158.9 16.5zM181.0 19.4L182.1 22.2L185.0 22.3L182.7 24.2L183.5 27.0L181.0 25.4L178.5 27.0L179.3 24.2L177.0 22.3L179.9 22.2zM196.4 34.8L197.4 37.5L200.4 37.7L198.1 39.6L198.8 42.4L196.4 40.8L193.9 42.4L194.7 39.6L192.4 37.7L195.3 37.5z" />
      <rect class="p s" x="142" y="42" width="36" height="36" rx="6" />
      <path class="s" d="M136 50h6M136 60h6M136 70h6M178 50h6M178 60h6M178 70h6M150 36v6M160 36v6M170 36v6M150 78v6M160 78v6M170 78v6" />
      <path class="s w" d="M152 60l5 5 10-10" />
    </>
  ),
  privacy: (
    <>
      <circle class="p s" cx="70" cy="46" r="11" /><path class="p s" d="M50 84c2-14 10-22 20-22s18 8 20 22z" />
      <path class="s dash" d="M96 70h44M180 70h34" />
      <rect class="f" x="140" y="54" width="40" height="34" rx="6" /><rect class="p s" x="146" y="64" width="28" height="20" rx="4" /><path class="s" d="M152 64v-6a8 8 0 0 1 16 0v6" /><circle class="t" cx="160" cy="74" r="2.5" />
      <ellipse class="p s" cx="236" cy="56" rx="20" ry="6" /><path class="p s" d="M216 56v28c0 3.3 9 6 20 6s20-2.7 20-6V56" /><path class="s" d="M216 70c0 3.3 9 6 20 6s20-2.7 20-6" />
      <path class="s dash" d="M88 56l46-30" /><circle class="p s" cx="146" cy="20" r="10" /><path class="s w" d="M141 15l10 10M151 15l-10 10" />
    </>
  ),
  mena: (
    <>
      <circle class="p s" cx="132" cy="62" r="46" />
      <ellipse class="s" cx="132" cy="62" rx="18" ry="46" /><path class="s" d="M86 62h92M93 39h78M93 85h78" />
      <path class="f" d="M138 38c10-4 22 0 28 10-2 10-12 14-20 12-6-6-12-12-8-22z" />
      {[[142, 44], [158, 50], [148, 60]].map(([x, y]) => <path key={x} class="t" d={`M${x} ${y}c-5 0-8-3.5-8-7.5a8 8 0 0 1 16 0c0 4-3 7.5-8 7.5zm0-10a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z`} />)}
      <rect class="p s" x="200" y="26" width="70" height="72" rx="6" /><path class="s" d="M235 36v52" />
      <text class="t" x="217" y="60" text-anchor="middle" font-size="20" font-weight="700">A</text>
      <text class="t" x="253" y="60" text-anchor="middle" font-size="22" font-weight="700">ع</text>
      <rect class="m" x="208" y="70" width="18" height="4" rx="2" /><rect class="m" x="244" y="70" width="18" height="4" rx="2" /><rect class="m" x="208" y="80" width="14" height="4" rx="2" /><rect class="m" x="248" y="80" width="14" height="4" rx="2" />
    </>
  ),
};

/** The picture at the top of a domain card; nothing for an unknown domain. */
export function DomainArt({ id }: { id: string }) {
  const art = ART[id];
  if (!art) return null;
  return (
    <div class={`dom-art tone-${id}`} aria-hidden="true">
      <svg viewBox="0 0 320 120" preserveAspectRatio="xMidYMid meet">{art}</svg>
    </div>
  );
}
