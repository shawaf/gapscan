import { useEffect, useRef, useState } from "preact/hooks";

/** Windowed list for 10,000+ rows: only the rows in view (plus overscan) exist in the DOM.
 *  Rows have a fixed height, so positions are computed, never measured. */
export function VirtualList<T>({
  items, rowHeight, render, height = 560, overscan = 8, selectedIndex, label,
}: {
  items: T[]; rowHeight: number; render: (item: T, index: number, top: number) => preact.ComponentChildren;
  height?: number; overscan?: number; selectedIndex?: number; label: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(height);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewport(el.clientHeight));
    ro.observe(el);
    setViewport(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // Keep the keyboard selection in view.
  useEffect(() => {
    const el = ref.current;
    if (el == null || selectedIndex == null || selectedIndex < 0) return;
    const top = selectedIndex * rowHeight;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = top + rowHeight - el.clientHeight;
  }, [selectedIndex, rowHeight]);

  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const last = Math.min(items.length, Math.ceil((scrollTop + viewport) / rowHeight) + overscan);
  const rows = [];
  for (let i = first; i < last; i++) rows.push(render(items[i] as T, i, i * rowHeight));

  return (
    <div ref={ref} class="vscroll" style={{ height: `${height}px` }} onScroll={(e) => setScrollTop((e.currentTarget as HTMLDivElement).scrollTop)}
      role="list" aria-label={label} aria-rowcount={items.length} data-rendered-rows={rows.length}>
      <div style={{ height: `${items.length * rowHeight}px`, position: "relative" }}>{rows}</div>
    </div>
  );
}
