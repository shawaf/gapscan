import { useEffect, useRef } from "preact/hooks";
import * as echarts from "echarts/core";
import { BarChart, PieChart, TreemapChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent, TitleComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";
import { uiStore, useStore, type Ui } from "../store";

echarts.use([BarChart, PieChart, TreemapChart, GridComponent, LegendComponent, TooltipComponent, TitleComponent, CanvasRenderer]);

const PALETTES = {
  // Okabe-Ito based, as in the original design.
  classic: {
    sev: { critical: "#d55e00", high: "#e69f00", medium: "#c8b900", low: "#56b4e9", info: "#8a94a6" },
    accent: "#4b7bd8", neutral: "#aab4c4", bad: "#d55e00", good: "#1b7a46", treemapBorder: "#fff",
  },
  // Soft pastel tones that read on both the light and the dark surface; every chart also labels its values.
  soft: {
    sev: { critical: "#d97aa5", high: "#f0a274", medium: "#e8c66e", low: "#86bce3", info: "#b3baca" },
    accent: "#8f93e6", neutral: "#b3baca", bad: "#f0a274", good: "#72c6a4", treemapBorder: "transparent",
  },
  // The glassy look shares the soft pastels so charts read on its translucent surfaces.
  glassy: {
    sev: { critical: "#d97aa5", high: "#f0a274", medium: "#e8c66e", low: "#86bce3", info: "#b3baca" },
    accent: "#8f93e6", neutral: "#b3baca", bad: "#f0a274", good: "#72c6a4", treemapBorder: "transparent",
  },
} as const;

/** Chart colors for the active UI edition; include the result in a chart option's memo deps. */
export function useChartPalette(): (typeof PALETTES)[Ui] {
  return PALETTES[useStore(uiStore)];
}

type Opt = Record<string, unknown>;
const asList = (v: unknown): Opt[] => (Array.isArray(v) ? v : v ? [v] : []) as Opt[];

/** Rounded bars, faint gridlines and no axis chrome: the soft look, applied to every chart. */
function soften(option: Opt, line: string, muted: string): Opt {
  const axis = (a: Opt): Opt => ({
    axisLine: { show: a.type === "category", lineStyle: { color: line } }, axisTick: { show: false },
    axisLabel: { color: muted }, splitLine: { lineStyle: { color: line, type: "dashed" } }, ...a,
  });
  const series = asList(option.series).map((s) => s.type === "bar"
    ? { barMaxWidth: 22, ...s, itemStyle: { borderRadius: s.stack ? 0 : 6, ...(s.itemStyle as Opt | undefined) } }
    : s.type === "treemap"
      ? { ...s, itemStyle: { borderRadius: 6, gapWidth: 2, ...(s.itemStyle as Opt | undefined) } }
      : s);
  return {
    ...option,
    ...(option.xAxis ? { xAxis: Array.isArray(option.xAxis) ? asList(option.xAxis).map(axis) : axis(option.xAxis as Opt) } : {}),
    ...(option.yAxis ? { yAxis: Array.isArray(option.yAxis) ? asList(option.yAxis).map(axis) : axis(option.yAxis as Opt) } : {}),
    ...(option.series ? { series } : {}),
    ...(option.tooltip ? { tooltip: { borderWidth: 0, padding: [8, 12], extraCssText: "border-radius:10px;box-shadow:0 6px 20px rgba(34,38,70,.12);", ...(option.tooltip as Opt) } } : {}),
  };
}

function cssVar(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/** An ECharts chart that follows the page theme and resizes with its container. */
export function EChart({ option, height, label, tall = false }: { option: EChartsCoreOption; height?: number; label: string; tall?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const c = echarts.init(ref.current, undefined, { renderer: "canvas" });
    chart.current = c;
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(ref.current);
    return () => { ro.disconnect(); c.dispose(); chart.current = null; };
  }, []);

  useEffect(() => {
    const c = chart.current;
    if (!c) return;
    const apply = () => c.setOption({
      backgroundColor: "transparent", textStyle: { color: cssVar("--text", "#22263a"), fontFamily: "inherit" },
      animation: false, ...(uiStore.get() === "soft" ? soften : (o: Opt) => o)(option as Opt, cssVar("--line", "#e4e7f0"), cssVar("--muted", "#5f6580")),
    } as EChartsCoreOption, true);
    apply();
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const obs = new MutationObserver(apply);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-ui"] });
    mq.addEventListener("change", apply);
    return () => { obs.disconnect(); mq.removeEventListener("change", apply); };
  }, [option]);

  return <div ref={ref} class={`chart${tall ? " tall" : ""}`} style={height ? { height: `${height}px` } : undefined} role="img" aria-label={label} />;
}
