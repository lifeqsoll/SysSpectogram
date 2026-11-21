<script lang="ts">
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { onDestroy } from 'svelte';

  export interface ChartSeries {
    label: string;
    color: string;
    values: (number | null)[];
    dash?: number[];
  }

  let {
    xs,
    series,
    height = 220,
    yRange,
    legend = false,
    syncKey = null,
    markers = [],
  }: {
    xs: number[];
    series: ChartSeries[];
    height?: number;
    yRange?: [number, number];
    legend?: boolean;
    /** When set, uPlot cursors sync across charts with the same key. */
    syncKey?: string | null;
    /** Unix timestamps for vertical alert markers. */
    markers?: number[];
  } = $props();

  let container: HTMLDivElement | undefined = $state();
  let plot: uPlot | null = null;
  let resizeObserver: ResizeObserver | null = null;
  let lastSig = '';
  let resizeTimer: ReturnType<typeof setTimeout> | undefined;

  const AXIS = '#6b7c94';
  const GRID = 'rgba(148, 178, 230, 0.06)';

  function signature(): string {
    const n = xs.length;
    const head = n ? xs[0] : 0;
    const tail = n ? xs[n - 1] : 0;
    const tails = series
      .map((s) => {
        const v = s.values;
        const last = v.length ? v[v.length - 1] : null;
        return `${s.label}:${v.length}:${last}`;
      })
      .join('|');
    const mk = markers.length ? `${markers[0]}:${markers[markers.length - 1]}:${markers.length}` : '0';
    return `${n}:${head}:${tail}:${series.length}:${tails}:${height}:${legend}:${mk}`;
  }

  function options(width: number): uPlot.Options {
    return {
      width,
      height,
      legend: { show: legend },
      cursor: {
        show: Boolean(syncKey),
        drag: { x: false, y: false },
        sync: syncKey ? { key: syncKey, setSeries: false } : undefined,
      },
      scales: {
        x: { time: true },
        y: yRange ? { range: () => yRange } : { auto: true },
      },
      axes: [
        { stroke: AXIS, grid: { show: false }, ticks: { stroke: GRID } },
        { stroke: AXIS, grid: { stroke: GRID, width: 1 }, ticks: { show: false } },
      ],
      series: [
        {},
        ...series.map((s) => ({
          label: s.label,
          stroke: s.color,
          width: 1.5,
          dash: s.dash,
          points: { show: false },
        })),
      ],
      hooks: {
        draw: [
          (u) => {
            if (!markers.length) return;
            const ctx = u.ctx;
            ctx.save();
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.55)';
            ctx.lineWidth = 1;
            ctx.setLineDash([3, 3]);
            for (const ts of markers) {
              const x = u.valToPos(ts, 'x', true);
              if (x < u.bbox.left || x > u.bbox.left + u.bbox.width) continue;
              ctx.beginPath();
              ctx.moveTo(x, u.bbox.top);
              ctx.lineTo(x, u.bbox.top + u.bbox.height);
              ctx.stroke();
            }
            ctx.restore();
          },
        ],
      },
    };
  }

  function data(): uPlot.AlignedData {
    return [xs, ...series.map((s) => s.values)] as uPlot.AlignedData;
  }

  $effect(() => {
    if (!container) return;
    // Touch deps so effect re-runs when data changes.
    const sig = signature();
    void xs;
    void series;
    void height;
    void legend;
    void markers;
    if (sig === lastSig && plot) return;
    lastSig = sig;

    const width = Math.max(320, container.clientWidth || 320);
    if (!plot) {
      plot = new uPlot(options(width), data(), container);
      resizeObserver = new ResizeObserver(() => {
        if (resizeTimer) clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
          if (plot && container) {
            plot.setSize({ width: Math.max(320, container.clientWidth || 320), height });
          }
        }, 200);
      });
      resizeObserver.observe(container);
      return;
    }
    const current = plot.series.length - 1;
    if (current !== series.length) {
      plot.destroy();
      plot = new uPlot(options(width), data(), container);
    } else {
      plot.setData(data());
    }
  });

  onDestroy(() => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeObserver?.disconnect();
    plot?.destroy();
    plot = null;
  });
</script>

<div class="chart" bind:this={container} style="min-height: {height}px"></div>

<style>
  .chart {
    width: 100%;
  }
  .chart :global(.u-legend) {
    color: var(--muted);
    font-size: 12px;
  }
</style>
