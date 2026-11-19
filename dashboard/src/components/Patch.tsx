// @ts-nocheck -- a direct port of the design system generator; inputs are fixed enums and an escaped label.
/* Patch, the GapScan character: a shield with a visor and an orange mend where a gap was closed.
   Ported from the GapScan design system. Drawn as inline SVG (nothing is loaded from the network).
   Rules: at most one Patch per screen, on dark grounds he stands on the halo, no emoji. */
/* eslint-disable */
import type { JSX } from "preact";
import "./patch.css";

export type PatchMood = "neutral" | "happy" | "wink" | "scanning" | "thinking" | "talking" | "success" | "alert" | "sleepy";
export type PatchPose = "stand" | "wave" | "point" | "cheer" | "think" | "shrug";
export type PatchKit = "none" | "magnifier" | "wrench" | "bell" | "branch" | "clipboard" | "lock" | "headset";
export type PatchState = "idle" | "greet" | "scanning" | "thinking" | "talking" | "fixing" | "done" | "alert" | "error" | "offline";

  var C = {
    body: '#9DB0FF', shade: '#7489E0', visor: '#0E1626', eye: '#EAF0FF',
    ink: '#0E1626', hand: '#FFFFFF', patch: '#FF9F5A', stitch: '#0E1626',
    antennaIdle: '#9DB0FF', antennaScan: '#FFC266', antennaAlert: '#FF8A65', antennaDone: '#8FB3D9'
  };
  var MOODS = ['neutral', 'happy', 'wink', 'scanning', 'thinking', 'talking', 'success', 'alert', 'sleepy'];
  var POSES = ['stand', 'wave', 'point', 'cheer', 'think', 'shrug'];
  var KITS = ['none', 'magnifier', 'wrench', 'bell', 'branch', 'clipboard', 'lock', 'headset'];

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  var SHIELD = 'M80 14 L134 32 V84 C134 120 112 146 80 160 C48 146 26 120 26 84 V32 Z';
  var SHIELD_LEFT = 'M80 14 L26 32 V84 C26 120 48 146 80 160 Z';

  function eyes(mood, ink) {
    var w = C.eye;
    var open = '<ellipse cx="64" cy="72" rx="5.5" ry="7.5" fill="' + w + '"/><ellipse cx="96" cy="72" rx="5.5" ry="7.5" fill="' + w + '"/>';
    var arcL = '<path d="M57 75 Q64 65 71 75" fill="none" stroke="' + w + '" stroke-width="4" stroke-linecap="round"/>';
    var arcR = '<path d="M89 75 Q96 65 103 75" fill="none" stroke="' + w + '" stroke-width="4" stroke-linecap="round"/>';
    switch (mood) {
      case 'happy': case 'success': return arcL + arcR;
      case 'wink': return arcL + '<ellipse cx="96" cy="72" rx="5.5" ry="7.5" fill="' + w + '"/>';
      case 'scanning':
        return '<ellipse cx="64" cy="72" rx="6" ry="3.5" fill="' + w + '"/><ellipse cx="96" cy="72" rx="6" ry="3.5" fill="' + w + '"/>' +
          '<rect class="patch-scan" x="48" y="70" width="64" height="3" rx="1.5" fill="' + C.antennaScan + '" opacity="0.9"/>';
      case 'thinking': return '<ellipse cx="68" cy="68" rx="5" ry="7" fill="' + w + '"/><ellipse cx="100" cy="68" rx="5" ry="7" fill="' + w + '"/>';
      case 'alert': return '<circle cx="64" cy="72" r="8" fill="' + w + '"/><circle cx="96" cy="72" r="8" fill="' + w + '"/><circle cx="64" cy="72" r="3" fill="' + ink + '"/><circle cx="96" cy="72" r="3" fill="' + ink + '"/>';
      case 'sleepy': return '<path d="M57 73 H71 M89 73 H103" stroke="' + w + '" stroke-width="4" stroke-linecap="round"/>';
      default: return open;
    }
  }

  function mouth(mood, ink) {
    var s = ' fill="none" stroke="' + ink + '" stroke-width="3.5" stroke-linecap="round"';
    switch (mood) {
      case 'happy': case 'wink': return '<path d="M70 108 Q80 116 90 108"' + s + '/>';
      case 'success': return '<path d="M67 106 Q80 120 93 106 Z" fill="' + ink + '" stroke="' + ink + '" stroke-width="2" stroke-linejoin="round"/>';
      case 'talking': return '<ellipse class="patch-mouth" cx="80" cy="110" rx="7" ry="5" fill="' + ink + '"/>';
      case 'alert': return '<ellipse cx="80" cy="111" rx="4.5" ry="5.5" fill="' + ink + '"/>';
      case 'sleepy': return '<path d="M73 110 H87"' + s + '/>';
      case 'thinking': return '<path d="M72 110 Q78 107 88 111"' + s + '/>';
      case 'scanning': return '<path d="M73 109 H87"' + s + '/>';
      default: return '<path d="M72 108 Q80 113 88 108"' + s + '/>';
    }
  }

  function extras(mood, ink) {
    if (mood === 'thinking') {
      return '<g class="patch-dots"><circle cx="140" cy="22" r="3" fill="' + ink + '"/><circle cx="149" cy="12" r="4" fill="' + ink + '"/><circle cx="160" cy="0" r="5" fill="' + ink + '"/></g>';
    }
    if (mood === 'sleepy') {
      return '<path d="M140 10 h10 l-10 12 h10" fill="none" stroke="' + ink + '" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>';
    }
    if (mood === 'success') {
      return '<path d="M146 30 l3 7 l7 3 l-7 3 l-3 7 l-3 -7 l-7 -3 l7 -3 z" fill="' + C.patch + '" stroke="' + ink + '" stroke-width="1.5" stroke-linejoin="round"/>';
    }
    if (mood === 'alert') {
      return '<g><path d="M146 6 V24" stroke="' + C.antennaAlert + '" stroke-width="5" stroke-linecap="round"/><circle cx="146" cy="33" r="3" fill="' + C.antennaAlert + '"/></g>';
    }
    if (mood === 'talking') {
      return '<path d="M140 98 q6 8 0 16 M148 92 q10 14 0 28" fill="none" stroke="' + ink + '" stroke-width="2.5" stroke-linecap="round"/>';
    }
    return '';
  }

  var ARMS = {
    stand: { l: 'M28 92 L14 124', r: 'M132 92 L146 124', lh: [14, 124], rh: [146, 124] },
    wave: { l: 'M28 92 L14 124', r: 'M132 92 L152 56', lh: [14, 124], rh: [152, 56] },
    point: { l: 'M28 92 L14 124', r: 'M132 92 L160 92', lh: [14, 124], rh: [160, 92] },
    cheer: { l: 'M28 92 L8 58', r: 'M132 92 L152 58', lh: [8, 58], rh: [152, 58] },
    think: { l: 'M28 92 L14 124', r: 'M132 92 L144 116 L118 120', lh: [14, 124], rh: [118, 120] },
    shrug: { l: 'M28 92 L14 106 L6 86', r: 'M132 92 L146 106 L154 86', lh: [6, 86], rh: [154, 86] }
  };

  function handKit(kit, x, y, ink) {
    var st = ' stroke="' + ink + '" stroke-linecap="round" stroke-linejoin="round"';
    switch (kit) {
      case 'magnifier':
        return '<path d="M' + x + ' ' + y + ' L' + (x + 7) + ' ' + (y - 9) + '" stroke-width="5"' + st + '/>' +
          '<circle cx="' + (x + 13) + '" cy="' + (y - 17) + '" r="10" fill="#EAF0FF" fill-opacity="0.75" stroke-width="3.5"' + st + '/>';
      case 'wrench':
        return '<path d="M' + x + ' ' + y + ' L' + (x + 13) + ' ' + (y - 15) + '" stroke-width="5"' + st + '/>' +
          '<path d="M' + (x + 10) + ' ' + (y - 22) + ' a7 7 0 1 0 9 9 l-4 -1 l-1 -4 z" fill="#C9D2DD" stroke-width="3"' + st + '/>';
      case 'bell':
        return '<path d="M' + (x + 2) + ' ' + (y - 6) + ' c0 -14 4 -20 12 -20 c8 0 12 6 12 20 l3 4 h-30 z" fill="#FFC266" stroke-width="3"' + st + '/>' +
          '<circle cx="' + (x + 14) + '" cy="' + (y + 1) + '" r="3" fill="' + ink + '"/>';
      case 'branch':
        return '<g fill="#EAF0FF" stroke-width="3"' + st + '><path d="M' + (x + 8) + ' ' + (y - 4) + ' V' + (y - 28) + ' M' + (x + 8) + ' ' + (y - 12) + ' Q' + (x + 22) + ' ' + (y - 12) + ' ' + (x + 22) + ' ' + (y - 22) + '" fill="none"/>' +
          '<circle cx="' + (x + 8) + '" cy="' + (y - 30) + '" r="4"/><circle cx="' + (x + 22) + '" cy="' + (y - 25) + '" r="4"/><circle cx="' + (x + 8) + '" cy="' + (y - 2) + '" r="4"/></g>';
      case 'clipboard':
        return '<rect x="' + (x - 2) + '" y="' + (y - 30) + '" width="22" height="28" rx="3" fill="#EAF0FF" stroke-width="3"' + st + '/>' +
          '<path d="M' + (x + 3) + ' ' + (y - 20) + ' l3 3 l5 -6 M' + (x + 3) + ' ' + (y - 10) + ' h11" fill="none" stroke-width="2.5"' + st + '/>';
      case 'lock':
        return '<path d="M' + (x + 4) + ' ' + (y - 16) + ' v-6 a7 7 0 0 1 14 0 v6" fill="none" stroke-width="3.5"' + st + '/>' +
          '<rect x="' + x + '" y="' + (y - 17) + '" width="22" height="17" rx="3" fill="#FFC266" stroke-width="3"' + st + '/>';
      default: return '';
    }
  }

  function headKit(kit, ink) {
    if (kit !== 'headset') return '';
    return '<g stroke="' + ink + '" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M30 52 C30 10 130 10 130 52" fill="none" stroke-width="5"/>' +
      '<rect x="20" y="46" width="14" height="24" rx="6" fill="#FFC266" stroke-width="3"/>' +
      '<rect x="126" y="46" width="14" height="24" rx="6" fill="#FFC266" stroke-width="3"/>' +
      '<path d="M27 70 C27 96 46 108 64 110" fill="none" stroke-width="3"/><circle cx="66" cy="110" r="3.5" fill="' + ink + '"/></g>';
  }

  function antennaColor(mood) {
    if (mood === 'scanning' || mood === 'thinking') return C.antennaScan;
    if (mood === 'alert') return C.antennaAlert;
    if (mood === 'success') return C.antennaDone;
    return C.antennaIdle;
  }

  function svg(o) {
    o = o || {};
    var mood = MOODS.indexOf(o.mood) >= 0 ? o.mood : 'neutral';
    var pose = ARMS[o.pose] ? o.pose : 'stand';
    var kit = KITS.indexOf(o.kit) >= 0 ? o.kit : 'none';
    var size = Number(o.size) > 0 ? Number(o.size) : 120;
    var ink = o.outline || C.ink;
    var small = size < 40;
    if (small) { kit = 'none'; pose = 'stand'; if (['neutral', 'happy', 'scanning'].indexOf(mood) < 0) mood = 'neutral'; }
    var a = ARMS[pose];
    var h = Math.round(size * 198 / 204);
    var aria = o.label ? 'role="img" aria-label="' + esc(o.label) + '"' : 'aria-hidden="true"';
    var limb = ' fill="none" stroke="' + ink + '" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"';
    var out = '<svg class="patch" xmlns="http://www.w3.org/2000/svg" viewBox="-16 -14 204 198" width="' + size + '" height="' + h + '" ' + aria + '>';
    out += '<g class="patch-bob">';
    out += '<path d="M64 148 L62 166 M96 148 L98 166"' + limb + '/>';
    out += '<ellipse cx="57" cy="169" rx="10" ry="5.5" fill="' + ink + '"/><ellipse cx="103" cy="169" rx="10" ry="5.5" fill="' + ink + '"/>';
    out += '<path d="' + a.l + '"' + limb + '/>';
    if (!small) out += '<path d="M80 14 V2"' + ' stroke="' + ink + '" stroke-width="3.5" stroke-linecap="round"/><circle class="patch-antenna" cx="80" cy="0" r="5" fill="' + antennaColor(mood) + '" stroke="' + ink + '" stroke-width="2.5"/>';
    out += '<path d="' + SHIELD + '" fill="' + C.body + '"/>';
    out += '<path d="' + SHIELD_LEFT + '" fill="' + C.shade + '"/>';
    out += '<path d="' + SHIELD + '" fill="none" stroke="' + ink + '" stroke-width="3.5" stroke-linejoin="round"/>';
    out += '<rect x="42" y="52" width="76" height="40" rx="20" fill="' + C.visor + '"/>';
    out += eyes(mood, ink);
    out += mouth(mood, ink);
    if (!small) {
      out += '<g transform="rotate(-24 108 132)"><rect x="94" y="124" width="30" height="15" rx="5" fill="' + C.patch + '" stroke="' + ink + '" stroke-width="2.5"/>' +
        '<path d="M101 128 v7 M109 128 v7 M117 128 v7" stroke="' + C.stitch + '" stroke-width="1.8" stroke-linecap="round"/></g>';
    }
    out += headKit(kit, ink);
    out += '<path d="' + a.r + '"' + limb + '/>';
    out += '<circle cx="' + a.lh[0] + '" cy="' + a.lh[1] + '" r="6.5" fill="' + C.hand + '" stroke="' + ink + '" stroke-width="3"/>';
    out += handKit(kit, a.rh[0], a.rh[1], ink);
    out += '<circle cx="' + a.rh[0] + '" cy="' + a.rh[1] + '" r="6.5" fill="' + C.hand + '" stroke="' + ink + '" stroke-width="3"/>';
    if (!small) out += extras(mood, ink);
    out += '</g></svg>';
    return out;
  }

  var STATES = {
    idle: { mood: 'neutral', pose: 'stand', text: 'ready' },
    greet: { mood: 'happy', pose: 'wave', text: 'hello' },
    scanning: { mood: 'scanning', pose: 'stand', kit: 'magnifier', text: 'scanning' },
    thinking: { mood: 'thinking', pose: 'think', text: 'thinking' },
    talking: { mood: 'talking', pose: 'stand', text: 'answering' },
    fixing: { mood: 'scanning', pose: 'stand', kit: 'wrench', text: 'preparing a fix' },
    done: { mood: 'success', pose: 'cheer', text: 'done' },
    alert: { mood: 'alert', pose: 'point', kit: 'bell', text: 'alert' },
    error: { mood: 'neutral', pose: 'shrug', text: 'something failed' },
    offline: { mood: 'sleepy', pose: 'stand', text: 'offline' }
  };


export function patchSvg(o: { mood?: PatchMood; pose?: PatchPose; kit?: PatchKit; size?: number; label?: string; outline?: string }): string {
  return svg(o);
}

/** Patch in one of the assistant states (idle, scanning, fixing, done, alert, ...). `live` animates
 *  him; the animation stops under prefers-reduced-motion. `halo` puts him on the halo disc. */
export function Patch({ state = "idle", size = 96, live = false, halo = true, label }: { state?: PatchState; size?: number; live?: boolean; halo?: boolean; label?: string }): JSX.Element {
  const s = STATES[state] || STATES.idle;
  const html = svg({ mood: s.mood, pose: s.pose, kit: s.kit || "none", size, label: label ?? "Patch, GapScan assistant: " + s.text });
  return <span class={`${halo ? "patch-stage " : ""}${live ? "patch-live" : ""}`} dangerouslySetInnerHTML={{ __html: html }} />;
}
