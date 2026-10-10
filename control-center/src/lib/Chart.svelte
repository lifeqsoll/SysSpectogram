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
  }: {
    xs: number[];
    series: ChartSeries[];
    height?: number;
    yRange?: [number, number];
  } = $props();

  let container: HTMLDivElement | undefined = $state();
  let plot: uPlot | null = null;
  let resizeObserver: ResizeObserver | null = null;

  const AXIS = '#8a96a0';
  const GRID = '#242b31';

  function options(width: number): uPlot.Options {
    return {
      width,
      height,
      legend: { show: true },
      cursor: { drag: { x: false, y: false } },
      scales: {
        x: { time: true },
        y: yRange ? { range: () => yRange } : { auto: true },
      },
      axes: [
        { stroke: AXIS, grid: { stroke: GRID, width: 1 }, ticks: { stroke: GRID } },
        { stroke: AXIS, grid: { stroke: GRID, width: 1 }, ticks: { stroke: GRID } },
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
    };
  }

  function data(): uPlot.AlignedData {
    return [xs, ...series.map((s) => s.values)] as uPlot.AlignedData;
  }

  $effect(() => {
    if (!container) return;
    const width = Math.max(320, container.clientWidth);
    if (!plot) {
      plot = new uPlot(options(width), data(), container);
      resizeObserver = new ResizeObserver(() => {
        if (plot && container) plot.setSize({ width: Math.max(320, container.clientWidth), height });
      });
      resizeObserver.observe(container);
    } else {
      // Series count or labels changed: rebuild the plot. Otherwise just push data.
      const current = plot.series.length - 1;
      if (current !== series.length) {
        plot.destroy();
        plot = new uPlot(options(width), data(), container);
      } else {
        plot.setData(data());
      }
    }
  });

  onDestroy(() => {
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
