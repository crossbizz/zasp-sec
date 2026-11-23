"use client";

import { useEffect, useRef } from "react";
import { init, use } from "echarts/core";
import { LineChart } from "echarts/charts";
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent, DataZoomComponent } from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import type { CalibrationMetrics } from "../../../apps/web/api/generated";

use([LineChart, GridComponent, LegendComponent, TooltipComponent, AriaComponent, DataZoomComponent, SVGRenderer]);

export default function CalibrationChart({ metrics }: { metrics: CalibrationMetrics }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || typeof ResizeObserver === "undefined") return;
    const host = target.current;
    const chart = init(host, undefined, { renderer: "svg" });
    const style = getComputedStyle(host);
    chart.setOption({
      aria: { enabled: true }, animation: false, textStyle: { color: style.color },
      color: [style.getPropertyValue("--blue").trim() || "#0064ed", style.getPropertyValue("--green").trim() || "#247454"],
      grid: { left: 54, right: 16, top: 40, bottom: 65 }, legend: { top: 0, textStyle: { color: style.color } },
      tooltip: { trigger: "axis", renderMode: "richText", confine: true },
      xAxis: { type: "value", name: "Predicted probability", nameLocation: "middle", nameGap: 32, min: 0, max: 1 },
      yAxis: { type: "value", min: 0, max: 1, axisLabel: { formatter: (x: number) => Math.round(x * 100) + "%" } },
      dataZoom: [{ type: "inside", zoomOnMouseWheel: false }],
      series: [
        { name: "Observed rate", type: "line", symbolSize: 8, data: metrics.bins.filter(b => b.count > 0).map(b => [b.mean_probability, b.observed_rate]) },
        { name: "Perfect calibration", type: "line", symbol: "none", lineStyle: { type: "dashed" }, data: [[0, 0], [1, 1]] },
      ],
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [metrics]);
  return <div style={{ height: 260 }} ref={target} aria-label="Observed detection rate by predicted probability" />;
}
