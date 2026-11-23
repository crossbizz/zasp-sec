"use client";

import { useEffect, useId, useRef, useState } from "react";
import { connect, disconnect, init, use as registerCharts, type EChartsCoreOption } from "echarts/core";
import { HeatmapChart, LineChart } from "echarts/charts";
import { AriaComponent, DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import type { CalibrationMetrics } from "../../../apps/web/api/generated";

registerCharts([LineChart, HeatmapChart, GridComponent, LegendComponent, TooltipComponent, VisualMapComponent, MarkLineComponent, AriaComponent, DataZoomComponent, SVGRenderer]);

function useEChart(ref: React.RefObject<HTMLDivElement | null>, options: EChartsCoreOption, group?: string) {
  useEffect(() => {
    const host = ref.current;
    if (!host || typeof ResizeObserver === "undefined") return;
    const chart = init(host, undefined, { renderer: "svg" });
    if (group) chart.group = group;
    chart.setOption({ animation: false, aria: { enabled: true }, textStyle: { color: getComputedStyle(host).color }, ...options });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [ref, options, group]);
}
const ratio = (a: number, b: number) => a + b ? a / (a + b) : null;
const base = {
  grid: { left: 58, right: 24, top: 45, bottom: 54 }, legend: { top: 0 },
  tooltip: { trigger: "axis", renderMode: "richText", confine: true, axisPointer: { type: "cross" } },
  xAxis: { type: "value", min: 0, max: 1, nameLocation: "middle", nameGap: 29 },
  yAxis: { type: "value", min: 0, max: 1 },
  dataZoom: [{ type: "inside", zoomOnMouseWheel: false }],
};
function Reliability({ data, group }: { data: CalibrationMetrics; group: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEChart(host, { ...base, xAxis: {...base.xAxis, name: "Predicted probability"}, series: [
    { name: "Observed rate", type: "line", symbolSize: 7, data: data.bins.filter(b => b.count > 0).map(b => [b.mean_probability,b.observed_rate]) },
    { name: "Perfect calibration", type: "line", symbol: "none", lineStyle: { type: "dashed" }, data: [[0,0],[1,1]] },
  ] }, group);
  return <div style={{ height: 230 }} ref={host} aria-label="Observed detection rate by predicted probability" />;
}
function ThresholdCurve({ data, group, cutoff }: { data: CalibrationMetrics; group: string; cutoff: number }) {
  const host = useRef<HTMLDivElement>(null);
  const seriousRecall = data.thresholds.map(row => [
    row.threshold,
    row.serious_tp === undefined || row.serious_fn === undefined ? null : ratio(row.serious_tp, row.serious_fn),
  ]);
  const hasSeriousLabels = seriousRecall.some(([, value]) => value !== null);
  useEChart(host, {
    ...base,
    grid: { ...base.grid, top: 65 },
    xAxis: { ...base.xAxis, name: "Confidence cutoff" },
    series: [
      { name: "Recall", type: "line", data: data.thresholds.map(row => [row.threshold, ratio(row.tp, row.fn)]),
        markLine: { symbol: "none", data: [{ xAxis: cutoff }], label: { show: false } } },
      { name: "False positive rate", type: "line", data: data.thresholds.map(row => [row.threshold, ratio(row.fp, row.tn)]) },
      ...(hasSeriousLabels ? [{
        name: "Serious detection recall", type: "line", data: seriousRecall,
        markLine: { symbol: "none", data: [{ yAxis: 1 }], lineStyle: { type: "dashed" }, label: { show: false } },
      }] : []),
    ],
  }, group);
  return <>
    <div style={{ height: 250 }} ref={host} aria-label="Recall and false positive rate by cutoff" />
    <p>{hasSeriousLabels
      ? "The dashed line marks the required 100% recall for labelled serious detections."
      : "Serious detection recall needs at least one labelled serious detection."}</p>
  </>;
}
function ConfusionMatrix({ row }: { row: CalibrationMetrics["thresholds"][number] }) {
  const host=useRef<HTMLDivElement>(null);
  useEChart(host,{ grid:{left:125,right:24,top:22,bottom:44}, tooltip:{renderMode:"richText"},
    xAxis:{type:"category",data:["Predicted negative","Predicted positive"]}, yAxis:{type:"category",data:["Actual negative","Actual positive"]},
    visualMap:{show:false,min:0,max:Math.max(row.tp,row.fp,row.tn,row.fn,1),inRange:{color:["#e2ebf5","#70aacd"]}},
    series:[{type:"heatmap",data:[[0,0,row.tn],[1,0,row.fp],[0,1,row.fn],[1,1,row.tp]],label:{show:true,color:"#172f44"}}] });
  return <div style={{height:168}} ref={host} aria-label={`Confusion matrix: ${row.tp} true positives, ${row.fp} false positives, ${row.tn} true negatives and ${row.fn} false negatives`} />;
}
export default function CalibrationChart({ metrics }: { metrics: CalibrationMetrics }) {
  const group=useId(), [index,setIndex]=useState(0);
  const row=metrics.thresholds[Math.min(index,metrics.thresholds.length-1)];
  useEffect(()=>{connect(group);return ()=>disconnect(group);},[group]);
  return <><Reliability data={metrics} group={group}/>
    {row && <><h3>Threshold trade-offs</h3>
      <label>Confidence cutoff {row.threshold.toFixed(2)} <input type="range" min={0} max={metrics.thresholds.length-1} step={1} value={index} onChange={e=>setIndex(e.target.valueAsNumber)} /></label>
      <ThresholdCurve data={metrics} cutoff={row.threshold} group={group}/><ConfusionMatrix row={row}/></>}
  </>;
}
