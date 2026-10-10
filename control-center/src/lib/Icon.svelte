<script lang="ts">
  import overview from '../assets/icons/overview.svg?raw';
  import live from '../assets/icons/live.svg?raw';
  import dashboards from '../assets/icons/dashboards.svg?raw';
  import incidents from '../assets/icons/incidents.svg?raw';
  import agent from '../assets/icons/agent.svg?raw';
  import perimeter from '../assets/icons/perimeter.svg?raw';
  import settings from '../assets/icons/settings.svg?raw';
  import scenarios from '../assets/icons/scenarios.svg?raw';
  import lab from '../assets/icons/lab.svg?raw';
  import install from '../assets/icons/install.svg?raw';
  import logs from '../assets/icons/logs.svg?raw';
  import about from '../assets/icons/about.svg?raw';
  import refresh from '../assets/icons/refresh.svg?raw';

  // Handwritten 24px icon set: stroke 1.5, currentColor, no fills.
  const ICONS: Record<string, string> = {
    overview,
    live,
    dashboards,
    incidents,
    agent,
    perimeter,
    settings,
    scenarios,
    lab,
    install,
    logs,
    about,
    refresh,
  };

  let { name, size = 18 }: { name: string; size?: number } = $props();
</script>

<span class="icon" style="width: {size}px; height: {size}px" aria-hidden="true">{@html ICONS[name] ?? ''}</span>

<style>
  .icon {
    display: inline-flex;
    flex: none;
    color: currentColor;
  }
  .icon :global(svg) {
    width: 100%;
    height: 100%;
  }
</style>
