/** The GapScan mark: a square with a gap in its right side. Drawn in currentColor, so it follows the theme. */
export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg class="logo" width={size} height={size} viewBox="0 0 100 100" aria-hidden="true" focusable="false" shape-rendering="crispEdges">
      <path fill="currentColor" d="M0 0H100V43H86V14H14V86H86V57H100V100H0Z" />
    </svg>
  );
}
