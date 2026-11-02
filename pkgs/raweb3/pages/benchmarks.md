---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Benchmarks"
description: "How ranet3 compares with wireguard-go, Tailscale, NetBird userspace, NetBird kernel, kernel WireGuard and kernel IPsec on 2 hosts connected with 10 GbE."
created: 2026-10-21
updated: 2026-11-02
vetted: 2026-11-02
layout: bare
---

<section class="section">
<h1 class="text-[2em] font-bold text-fg">Benchmarks</h1>
<p class="note">Measured on November 1, 2026</p>
<p class="mt-[.6em] text-fg2">How ranet3 compares with wireguard-go, Tailscale, NetBird userspace, NetBird kernel, kernel WireGuard and kernel IPsec on 2 hosts connected with 10 GbE. The result of each test is the median of its 10 runs. Latency is the RTT p99 of the pings pooled over the 10 runs, and ping loss is the share of those pings lost.</p>
<p class="note mt-[1.5em] flex flex-wrap gap-x-[2ch]"><a href="#head-to-head" class="link">Head to head</a> <a href="#throughput" class="link">Throughput</a> <a href="#packet-rate" class="link">Packet rate</a> <a href="#latency" class="link">Latency</a> <a href="#cpu-cost" class="link">CPU cost</a> <a href="#memory" class="link">Memory</a> <a href="#all-figures" class="link">All figures</a> <a href="#setup" class="link">Setup</a></p>
<h2 id="head-to-head" class="mt-[3em] text-[1.5em] font-bold text-fg">Head to head</h2>
<p class="mt-[.6em] text-fg2">In every saturated TCP test ranet3 carries the most. Its CPU cost is lower than that of each WireGuard dataplane, apart from 1 of 6 tests against Tailscale. It trails NetBird kernel and kernel WireGuard on packet rate one way, kernel IPsec on CPU cost, and the kernel dataplanes on latency under saturation.</p>
<div class="overflow-x-auto mt-[1em]" tabindex="0">
<table class="data-table data-table-left data-table-ruled max-sm:whitespace-normal">
<thead>
<tr>
<th scope="col">Dataplane</th>
<th scope="col">Throughput<small>higher is better</small></th>
<th scope="col">Packet rate<small>higher is better</small></th>
<th scope="col">CPU per Gbit/s<small>lower is better</small></th>
<th scope="col">Latency p99<small>lower is better</small></th>
</tr>
</thead>
<tbody>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></th><td><span class="font-bold whitespace-nowrap text-good">1.2-1.6x</span> <small>better</small><span class="ratio text-good" style="--a:54.8%;--b:61.2%;--s:50%;--e:54.8%"></span></td><td><span class="font-bold whitespace-nowrap text-good">1.6-1.8x</span> <small>better</small><span class="ratio text-good" style="--a:61.8%;--b:64.6%;--s:50%;--e:61.8%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.9x</span> <small>better</small><span class="ratio text-good" style="--a:51.6%;--b:53.6%;--s:50%;--e:51.6%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.4-0.9x</span> <small>better</small><span class="ratio text-good" style="--a:53.4%;--b:71.2%;--s:50%;--e:53.4%"></span></td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></th><td><span class="font-bold whitespace-nowrap text-good">1.3-1.6x</span> <small>better</small><span class="ratio text-good" style="--a:56.2%;--b:61.6%;--s:50%;--e:56.2%"></span></td><td><span class="font-bold whitespace-nowrap text-good">2.3-2.5x</span> <small>better</small><span class="ratio text-good" style="--a:69.5%;--b:71.8%;--s:50%;--e:69.5%"></span></td><td><span class="font-bold whitespace-nowrap text-mute">0.9-1.0x</span> <small>mixed</small><span class="ratio text-mute" style="--a:49.5%;--b:52.9%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.3-0.7x</span> <small>better</small><span class="ratio text-good" style="--a:59.4%;--b:83.0%;--s:50%;--e:59.4%"></span></td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></th><td><span class="font-bold whitespace-nowrap text-good">1.3-1.6x</span> <small>better</small><span class="ratio text-good" style="--a:55.9%;--b:61.9%;--s:50%;--e:55.9%"></span></td><td><span class="font-bold whitespace-nowrap text-good">1.7-1.9x</span> <small>better</small><span class="ratio text-good" style="--a:62.6%;--b:65.5%;--s:50%;--e:62.6%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.9x</span> <small>better</small><span class="ratio text-good" style="--a:52.0%;--b:54.0%;--s:50%;--e:52.0%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.5-0.9x</span> <small>better</small><span class="ratio text-good" style="--a:53.7%;--b:64.8%;--s:50%;--e:53.7%"></span></td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></th><td><span class="font-bold whitespace-nowrap text-good">2.2-2.7x</span> <small>better</small><span class="ratio text-good" style="--a:68.7%;--b:73.4%;--s:50%;--e:68.7%"></span></td><td><span class="font-bold whitespace-nowrap text-mute">0.8-2.1x</span> <small>mixed</small><span class="ratio text-mute" style="--a:44.0%;--b:68.1%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.6-0.7x</span> <small>better</small><span class="ratio text-good" style="--a:59.5%;--b:61.8%;--s:50%;--e:59.5%"></span></td><td><span class="font-bold whitespace-nowrap text-bad">1.5-7.6x</span> <small>worse</small><span class="ratio text-bad" style="--a:1.2%;--b:40.0%;--s:40.0%;--e:50%"></span></td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></th><td><span class="font-bold whitespace-nowrap text-good">1.6-1.9x</span> <small>better</small><span class="ratio text-good" style="--a:62.0%;--b:65.9%;--s:50%;--e:62.0%"></span></td><td><span class="font-bold whitespace-nowrap text-mute">0.6-1.4x</span> <small>mixed</small><span class="ratio text-mute" style="--a:36.2%;--b:57.8%"></span></td><td><span class="font-bold whitespace-nowrap text-good">0.7x</span> <small>better</small><span class="ratio text-good" style="--a:57.9%;--b:60.2%;--s:50%;--e:57.9%"></span></td><td><span class="font-bold whitespace-nowrap text-bad">1.7-7.8x</span> <small>worse</small><span class="ratio text-bad" style="--a:0.7%;--b:37.9%;--s:37.9%;--e:50%"></span></td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></th><td><span class="font-bold whitespace-nowrap text-good">1.9-4.0x</span> <small>better</small><span class="ratio text-good" style="--a:65.3%;--b:83.6%;--s:50%;--e:65.3%"></span></td><td><span class="font-bold whitespace-nowrap text-mute">1.0-1.2x</span> <small>mixed</small><span class="ratio text-mute" style="--a:49.7%;--b:53.5%"></span></td><td><span class="font-bold whitespace-nowrap text-bad">1.5-1.8x</span> <small>worse</small><span class="ratio text-bad" style="--a:35.4%;--b:40.9%;--s:40.9%;--e:50%"></span></td><td><span class="font-bold whitespace-nowrap text-bad">1.6-7.0x</span> <small>worse</small><span class="ratio text-bad" style="--a:3.0%;--b:38.7%;--s:38.7%;--e:50%"></span></td></tr>
</tbody>
</table>
</div>
<p class="note">Each range is ranet3's result divided by the other dataplane's across 6 tests. A bar right of the center tick is where ranet3 is ahead, on a log scale from 8x behind to 8x ahead, with the range solid and the stretch from the tick to the range pale.</p>
<h2 id="throughput" class="mt-[3em] text-[1.5em] font-bold text-fg">Throughput</h2>
<p class="mt-[.6em] text-fg2">A userspace dataplane copies each packet into its own process, a cost the kernel dataplanes avoid. One way ranet3 stays at the 10 GbE limit from 1 to 16 streams, and both ways it reaches 16.09 to 16.65 Gbit/s of the 18.77 that plain TCP carries without a tunnel. The userspace WireGuard dataplanes and kernel IPsec lose throughput as streams rise. Kernel WireGuard holds 5.2 to 5.3 Gbit/s one way.</p>
<div class="mt-[2em] grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-10 lg:grid-cols-2">
<figure>
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>One way</b><span class="text-mute">Gbit/s received, out</span><span class="text-hint">Higher is better</span></figcaption>
<div class="lines" role="img" aria-label="Gbit/s received one way by stream count. At the limit ranet3 holds 8.77 to 8.80, and the others stay at 7.08 or below.">
<div class="lines-plot"><svg viewBox="0 0 100 240" preserveAspectRatio="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line class="line line-rule" x1="0" x2="100" y1="240.0" y2="240.0"/><line class="line line-rule" x1="0" x2="100" y1="195.6" y2="195.6"/><line class="line line-rule" x1="0" x2="100" y1="151.2" y2="151.2"/><line class="line line-rule" x1="0" x2="100" y1="106.8" y2="106.8"/><line class="line line-rule" x1="0" x2="100" y1="62.4" y2="62.4"/><line class="line line-rule" x1="0" x2="100" y1="18.0" y2="18.0"/><line class="line line-limit" x1="0" x2="100" y1="43.8" y2="43.8"/><polyline class="line" style="--c:var(--mark-1)" points="8.00,82.9 31.00,86.0 54.00,87.4 77.00,91.7 100.00,96.1"/><polyline class="line" style="--c:var(--mark-2)" points="8.00,90.8 31.00,92.1 54.00,95.2 77.00,96.8 100.00,97.8"/><polyline class="line" style="--c:var(--mark-3)" points="8.00,88.3 31.00,90.8 54.00,93.7 77.00,96.3 100.00,101.0"/><polyline class="line" style="--c:var(--mark-4)" points="8.00,150.2 31.00,151.2 54.00,150.3 77.00,151.2 100.00,151.2"/><polyline class="line" style="--c:var(--mark-5)" points="8.00,121.7 31.00,122.8 54.00,123.1 77.00,123.2 100.00,124.8"/><polyline class="line" style="--c:var(--mark-6)" points="8.00,136.8 31.00,138.6 54.00,144.2 77.00,150.5 100.00,156.2"/><polyline class="line line-halo" points="8.00,45.0 31.00,44.6 54.00,44.7 77.00,45.0 100.00,45.3"/><polyline class="line line-accent" points="8.00,45.0 31.00,44.6 54.00,44.7 77.00,45.0 100.00,45.3"/><polyline class="line line-hit" points="8.00,82.9 31.00,86.0 54.00,87.4 77.00,91.7 100.00,96.1"><title>wireguard-go: 1 stream 7.08, 2 streams 6.94, 4 streams 6.87, 8 streams 6.68, 16 streams 6.48</title></polyline><polyline class="line line-hit" points="8.00,90.8 31.00,92.1 54.00,95.2 77.00,96.8 100.00,97.8"><title>Tailscale: 1 stream 6.72, 2 streams 6.66, 4 streams 6.52, 8 streams 6.45, 16 streams 6.41</title></polyline><polyline class="line line-hit" points="8.00,88.3 31.00,90.8 54.00,93.7 77.00,96.3 100.00,101.0"><title>NetBird userspace: 1 stream 6.83, 2 streams 6.72, 4 streams 6.59, 8 streams 6.47, 16 streams 6.26</title></polyline><polyline class="line line-hit" points="8.00,150.2 31.00,151.2 54.00,150.3 77.00,151.2 100.00,151.2"><title>NetBird kernel: 1 stream 4.04, 2 streams 4.00, 4 streams 4.04, 8 streams 4.00, 16 streams 4.00</title></polyline><polyline class="line line-hit" points="8.00,121.7 31.00,122.8 54.00,123.1 77.00,123.2 100.00,124.8"><title>kernel WireGuard: 1 stream 5.33, 2 streams 5.28, 4 streams 5.27, 8 streams 5.26, 16 streams 5.19</title></polyline><polyline class="line line-hit" points="8.00,136.8 31.00,138.6 54.00,144.2 77.00,150.5 100.00,156.2"><title>kernel IPsec: 1 stream 4.65, 2 streams 4.57, 4 streams 4.31, 8 streams 4.03, 16 streams 3.77</title></polyline><polyline class="line line-hit" points="8.00,45.0 31.00,44.6 54.00,44.7 77.00,45.0 100.00,45.3"><title>ranet3: 1 stream 8.78, 2 streams 8.80, 4 streams 8.80, 8 streams 8.78, 16 streams 8.77</title></polyline></svg><span class="lines-tick" style="--y:240.0px">0</span><span class="lines-tick" style="--y:195.6px">2</span><span class="lines-tick" style="--y:151.2px">4</span><span class="lines-tick" style="--y:106.8px">6</span><span class="lines-tick" style="--y:62.4px">8</span><span class="lines-tick" style="--y:18.0px">10</span><span class="lines-tick" style="--y:43.8px;left:8%;margin-top:-4px">10 GbE limit 8.84</span><i class="plot-mark" style="--x:100%;--y:96.1px;--c:var(--mark-1)"></i><i class="plot-mark" style="--x:100%;--y:97.8px;--c:var(--mark-2)"></i><i class="plot-mark" style="--x:100%;--y:101.0px;--c:var(--mark-3)"></i><i class="plot-mark" style="--x:100%;--y:151.2px;--c:var(--mark-4)"></i><i class="plot-mark" style="--x:100%;--y:124.8px;--c:var(--mark-5)"></i><i class="plot-mark" style="--x:100%;--y:156.2px;--c:var(--mark-6)"></i><i class="plot-mark plot-mark-lead" style="--x:100%;--y:45.3px;--c:var(--mark)"></i><span class="lines-lead" style="--y:45.3px">ranet3 8.77</span></div>
<div class="lines-names"><svg viewBox="0 0 14 240" preserveAspectRatio="none" aria-hidden="true"><line class="line line-leader" style="--c:var(--mark)" x1="0" x2="14" y1="45.3" y2="45.3"/><line class="line line-leader" style="--c:var(--mark-1)" x1="0" x2="14" y1="96.1" y2="78.7"/><line class="line line-leader" style="--c:var(--mark-2)" x1="0" x2="14" y1="97.8" y2="95.7"/><line class="line line-leader" style="--c:var(--mark-3)" x1="0" x2="14" y1="101.0" y2="112.7"/><line class="line line-leader" style="--c:var(--mark-5)" x1="0" x2="14" y1="124.8" y2="129.7"/><line class="line line-leader" style="--c:var(--mark-4)" x1="0" x2="14" y1="151.2" y2="146.7"/><line class="line line-leader" style="--c:var(--mark-6)" x1="0" x2="14" y1="156.2" y2="163.7"/></svg><span class="lines-accent" style="--y:45.3px;--c:var(--mark)">ranet3 8.77</span><span style="--y:78.7px;--c:var(--mark-1)">wireguard-go</span><span style="--y:95.7px;--c:var(--mark-2)">Tailscale</span><span style="--y:112.7px;--c:var(--mark-3)">NetBird <small>user</small></span><span style="--y:146.7px;--c:var(--mark-4)">NetBird <small>kernel</small></span><span style="--y:129.7px;--c:var(--mark-5)">WireGuard <small>kernel</small></span><span style="--y:163.7px;--c:var(--mark-6)">IPsec <small>kernel</small></span></div>
<div class="lines-axis"><span style="--x:8.00%">1</span><span style="--x:31.00%">2</span><span style="--x:54.00%">4</span><span style="--x:77.00%">8</span><span style="--x:100.00%">16</span></div>
<div class="lines-unit">streams</div>
</div>
</figure>
<figure>
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Both ways</b><span class="text-mute">Gbit/s received</span><span class="text-hint">Higher is better</span></figcaption>
<div class="lines" role="img" aria-label="Gbit/s received both ways by stream count. Across them ranet3 holds 16.09 to 16.65, and the others stay at 11.20 or below.">
<div class="lines-plot"><svg viewBox="0 0 100 240" preserveAspectRatio="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line class="line line-rule" x1="0" x2="100" y1="240.0" y2="240.0"/><line class="line line-rule" x1="0" x2="100" y1="184.5" y2="184.5"/><line class="line line-rule" x1="0" x2="100" y1="129.0" y2="129.0"/><line class="line line-rule" x1="0" x2="100" y1="73.5" y2="73.5"/><line class="line line-rule" x1="0" x2="100" y1="18.0" y2="18.0"/><line class="line line-limit" x1="0" x2="100" y1="31.7" y2="31.7"/><polyline class="line" style="--c:var(--mark-1)" points="8.00,115.7 31.00,118.5 54.00,120.4 77.00,124.0 100.00,128.0"/><polyline class="line" style="--c:var(--mark-2)" points="8.00,118.9 31.00,118.5 54.00,123.0 77.00,125.8 100.00,127.3"/><polyline class="line" style="--c:var(--mark-3)" points="8.00,119.7 31.00,122.8 54.00,124.5 77.00,127.3 100.00,130.1"/><polyline class="line" style="--c:var(--mark-4)" points="8.00,169.2 31.00,170.0 54.00,168.4 77.00,170.3 100.00,171.3"/><polyline class="line" style="--c:var(--mark-5)" points="8.00,146.3 31.00,145.7 54.00,145.2 77.00,144.8 100.00,147.6"/><polyline class="line" style="--c:var(--mark-6)" points="8.00,187.3 31.00,188.7 54.00,191.5 77.00,194.3 100.00,197.1"/><polyline class="line line-halo" points="8.00,61.4 31.00,60.0 54.00,58.0 77.00,55.2 100.00,55.3"/><polyline class="line line-accent" points="8.00,61.4 31.00,60.0 54.00,58.0 77.00,55.2 100.00,55.3"/><polyline class="line line-hit" points="8.00,115.7 31.00,118.5 54.00,120.4 77.00,124.0 100.00,128.0"><title>wireguard-go: 1 stream 11.20, 2 streams 10.95, 4 streams 10.78, 8 streams 10.45, 16 streams 10.09</title></polyline><polyline class="line line-hit" points="8.00,118.9 31.00,118.5 54.00,123.0 77.00,125.8 100.00,127.3"><title>Tailscale: 1 stream 10.91, 2 streams 10.95, 4 streams 10.55, 8 streams 10.29, 16 streams 10.15</title></polyline><polyline class="line line-hit" points="8.00,119.7 31.00,122.8 54.00,124.5 77.00,127.3 100.00,130.1"><title>NetBird userspace: 1 stream 10.84, 2 streams 10.56, 4 streams 10.40, 8 streams 10.16, 16 streams 9.90</title></polyline><polyline class="line line-hit" points="8.00,169.2 31.00,170.0 54.00,168.4 77.00,170.3 100.00,171.3"><title>NetBird kernel: 1 stream 6.38, 2 streams 6.31, 4 streams 6.45, 8 streams 6.28, 16 streams 6.19</title></polyline><polyline class="line line-hit" points="8.00,146.3 31.00,145.7 54.00,145.2 77.00,144.8 100.00,147.6"><title>kernel WireGuard: 1 stream 8.44, 2 streams 8.49, 4 streams 8.54, 8 streams 8.58, 16 streams 8.32</title></polyline><polyline class="line line-hit" points="8.00,187.3 31.00,188.7 54.00,191.5 77.00,194.3 100.00,197.1"><title>kernel IPsec: 1 stream 4.75, 2 streams 4.62, 4 streams 4.37, 8 streams 4.12, 16 streams 3.87</title></polyline><polyline class="line line-hit" points="8.00,61.4 31.00,60.0 54.00,58.0 77.00,55.2 100.00,55.3"><title>ranet3: 1 stream 16.09, 2 streams 16.22, 4 streams 16.40, 8 streams 16.65, 16 streams 16.64</title></polyline></svg><span class="lines-tick" style="--y:240.0px">0</span><span class="lines-tick" style="--y:184.5px">5</span><span class="lines-tick" style="--y:129.0px">10</span><span class="lines-tick" style="--y:73.5px">15</span><span class="lines-tick" style="--y:18.0px">20</span><span class="lines-tick" style="--y:31.7px;left:8%;margin-top:-4px">Plain TCP 18.77</span><i class="plot-mark" style="--x:100%;--y:128.0px;--c:var(--mark-1)"></i><i class="plot-mark" style="--x:100%;--y:127.3px;--c:var(--mark-2)"></i><i class="plot-mark" style="--x:100%;--y:130.1px;--c:var(--mark-3)"></i><i class="plot-mark" style="--x:100%;--y:171.3px;--c:var(--mark-4)"></i><i class="plot-mark" style="--x:100%;--y:147.6px;--c:var(--mark-5)"></i><i class="plot-mark" style="--x:100%;--y:197.1px;--c:var(--mark-6)"></i><i class="plot-mark plot-mark-lead" style="--x:100%;--y:55.3px;--c:var(--mark)"></i><span class="lines-lead" style="--y:55.3px">ranet3 16.64</span></div>
<div class="lines-names"><svg viewBox="0 0 14 240" preserveAspectRatio="none" aria-hidden="true"><line class="line line-leader" style="--c:var(--mark)" x1="0" x2="14" y1="55.3" y2="55.3"/><line class="line line-leader" style="--c:var(--mark-2)" x1="0" x2="14" y1="127.3" y2="106.9"/><line class="line line-leader" style="--c:var(--mark-1)" x1="0" x2="14" y1="128.0" y2="123.9"/><line class="line line-leader" style="--c:var(--mark-3)" x1="0" x2="14" y1="130.1" y2="140.9"/><line class="line line-leader" style="--c:var(--mark-5)" x1="0" x2="14" y1="147.6" y2="157.9"/><line class="line line-leader" style="--c:var(--mark-4)" x1="0" x2="14" y1="171.3" y2="174.9"/><line class="line line-leader" style="--c:var(--mark-6)" x1="0" x2="14" y1="197.1" y2="197.1"/></svg><span class="lines-accent" style="--y:55.3px;--c:var(--mark)">ranet3 16.64</span><span style="--y:123.9px;--c:var(--mark-1)">wireguard-go</span><span style="--y:106.9px;--c:var(--mark-2)">Tailscale</span><span style="--y:140.9px;--c:var(--mark-3)">NetBird <small>user</small></span><span style="--y:174.9px;--c:var(--mark-4)">NetBird <small>kernel</small></span><span style="--y:157.9px;--c:var(--mark-5)">WireGuard <small>kernel</small></span><span style="--y:197.1px;--c:var(--mark-6)">IPsec <small>kernel</small></span></div>
<div class="lines-axis"><span style="--x:8.00%">1</span><span style="--x:31.00%">2</span><span style="--x:54.00%">4</span><span style="--x:77.00%">8</span><span style="--x:100.00%">16</span></div>
<div class="lines-unit">streams</div>
</div>
</figure>
</div>
<p class="note">Every dataplane's flow arrives on 1 NIC receive queue. At 1 stream one way, kernel IPsec's receiving host stays at 1.2 busy cores with that queue's softirq at 1.0, where the others spread the work over 3.6 to 4.6.</p>
<h2 id="packet-rate" class="mt-[3em] text-[1.5em] font-bold text-fg">Packet rate</h2>
<p class="mt-[.6em] text-fg2">These tests send UDP with GSO off, at a rate above what any dataplane carries. At 64 bytes one way ranet3 receives 0.32 Mpps, behind NetBird kernel at 0.39 and kernel WireGuard at 0.53, and level with kernel IPsec at 0.31. With traffic both ways it carries the most at both sizes, 0.62 and 0.52 Mpps, against 0.45 and 0.40 for kernel WireGuard, which leads one way.</p>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>64 byte packets</b><span class="text-mute">Mpps received, one way / both ways</span><span class="text-hint">Higher is better</span></figcaption>
<div class="plot-keys"><span><i class="plot-mark plot-mark-open"></i>One way, out</span><span><i class="plot-mark "></i>Both ways</span></div>
<div class="plot" role="img" aria-label="Million packets a second received at 64 bytes, one way out and both ways, for each dataplane." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 0.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 28.57% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 57.14% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 85.71% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: one way out 0.320, in 0.322, both ways 0.621 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:45.68%;--b:88.71%"></i><i class="plot-mark plot-mark-open" style="--x:45.68%"></i><i class="plot-mark" style="--x:88.71%"></i></span><span class="plot-figure">0.32 / 0.62</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: one way out 0.177, in 0.181, both ways 0.338 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:25.34%;--b:48.35%"></i><i class="plot-mark plot-mark-open" style="--x:25.34%"></i><i class="plot-mark" style="--x:48.35%"></i></span><span class="plot-figure">0.18 / 0.34</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: one way out 0.140, in 0.143, both ways 0.274 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:20.05%;--b:39.12%"></i><i class="plot-mark plot-mark-open" style="--x:20.05%"></i><i class="plot-mark" style="--x:39.12%"></i></span><span class="plot-figure">0.14 / 0.27</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: one way out 0.174, in 0.175, both ways 0.326 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:24.86%;--b:46.63%"></i><i class="plot-mark plot-mark-open" style="--x:24.86%"></i><i class="plot-mark" style="--x:46.63%"></i></span><span class="plot-figure">0.17 / 0.33</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: one way out 0.390, in 0.413, both ways 0.339 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:48.42%;--b:55.65%"></i><i class="plot-mark plot-mark-open" style="--x:55.65%"></i><i class="plot-mark" style="--x:48.42%"></i></span><span class="plot-figure">0.39 / 0.34</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard: one way out 0.526, in 0.570, both ways 0.449 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:64.18%;--b:75.1%"></i><i class="plot-mark plot-mark-open" style="--x:75.1%"></i><i class="plot-mark" style="--x:64.18%"></i></span><span class="plot-figure">0.53 / 0.45</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec: one way out 0.308, in 0.325, both ways 0.537 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:43.93%;--b:76.65%"></i><i class="plot-mark plot-mark-open" style="--x:43.93%"></i><i class="plot-mark" style="--x:76.65%"></i></span><span class="plot-figure">0.31 / 0.54</span></div>
<div class="plot-axis"><div><span style="--x:0.0%">0</span><span style="--x:28.57%">0.2</span><span style="--x:57.14%">0.4</span><span style="--x:85.71%">0.6</span></div></div>
</div>
</figure>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>1400 byte packets</b><span class="text-mute">Mpps received, one way / both ways</span><span class="text-hint">Higher is better</span></figcaption>
<div class="plot" role="img" aria-label="Million packets a second received at 1400 bytes, one way out and both ways, for each dataplane." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 0.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 28.57% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 57.14% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 85.71% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: one way out 0.287, in 0.287, both ways 0.523 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:40.93%;--b:74.7%"></i><i class="plot-mark plot-mark-open" style="--x:40.93%"></i><i class="plot-mark" style="--x:74.7%"></i></span><span class="plot-figure">0.29 / 0.52</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: one way out 0.169, in 0.173, both ways 0.320 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:24.2%;--b:45.65%"></i><i class="plot-mark plot-mark-open" style="--x:24.2%"></i><i class="plot-mark" style="--x:45.65%"></i></span><span class="plot-figure">0.17 / 0.32</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: one way out 0.118, in 0.116, both ways 0.225 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:16.8%;--b:32.21%"></i><i class="plot-mark plot-mark-open" style="--x:16.8%"></i><i class="plot-mark" style="--x:32.21%"></i></span><span class="plot-figure">0.12 / 0.23</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: one way out 0.167, in 0.168, both ways 0.310 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:23.79%;--b:44.29%"></i><i class="plot-mark plot-mark-open" style="--x:23.79%"></i><i class="plot-mark" style="--x:44.29%"></i></span><span class="plot-figure">0.17 / 0.31</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: one way out 0.328, in 0.308, both ways 0.246 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:35.19%;--b:46.8%"></i><i class="plot-mark plot-mark-open" style="--x:46.8%"></i><i class="plot-mark" style="--x:35.19%"></i></span><span class="plot-figure">0.33 / 0.25</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard: one way out 0.399, in 0.424, both ways 0.401 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:56.99%;--b:57.28%"></i><i class="plot-mark plot-mark-open" style="--x:56.99%"></i><i class="plot-mark" style="--x:57.28%"></i></span><span class="plot-figure">0.40 / 0.40</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec: one way out 0.275, in 0.288, both ways 0.473 Mpps"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:39.22%;--b:67.55%"></i><i class="plot-mark plot-mark-open" style="--x:39.22%"></i><i class="plot-mark" style="--x:67.55%"></i></span><span class="plot-figure">0.27 / 0.47</span></div>
<div class="plot-axis"><div><span style="--x:0.0%">0</span><span style="--x:28.57%">0.2</span><span style="--x:57.14%">0.4</span><span style="--x:85.71%">0.6</span></div></div>
</div>
</figure>
<p class="note">Sizes are of the inner packet, IPv6 and UDP headers included. Busy cores under this load do not measure the cost of a packet, because iperf3 asks for 10 Gbit/s each way and manages a different rate through each dataplane.</p>
<h2 id="latency" class="mt-[3em] text-[1.5em] font-bold text-fg">Latency</h2>
<p class="mt-[.6em] text-fg2">Under saturation ranet3's RTT p99 is <span class="whitespace-nowrap">0.3-0.9x</span> the userspace WireGuard dataplanes' and <span class="whitespace-nowrap">1.5-7.8x</span> the kernel dataplanes'. At 3 Gbit/s offered it falls to <span class="whitespace-nowrap">0.81-1.58</span> ms, <span class="whitespace-nowrap">0.5-1.9x</span> the kernel dataplanes'. With 100 kbit/s of UDP ranet3 is the highest of the 7 at 1.04 ms, against <span class="whitespace-nowrap">0.92-0.99</span> for the WireGuard dataplanes and 0.38 for kernel IPsec.</p>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>1 stream</b><span class="text-mute">RTT p99, ms, one way out</span><span class="text-hint">Lower is better</span></figcaption>
<div class="plot-keys"><span><i class="plot-mark plot-mark-open"></i>100 kbit/s</span><span><i class="plot-mark plot-mark-half"></i>3 Gbit/s</span><span><i class="plot-mark "></i>Saturated, the figure at the end of the row</span></div>
<div class="plot" role="img" aria-label="RTT p99 in milliseconds at 1 stream one way, by load, for each dataplane, on a log scale." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 3.51% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 26.7% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 47.85% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 71.04% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 92.19% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: 100 kbit/s 1.04, 3 Gbit/s 0.82, saturated 3.58 ms, 0.05% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:22.9%;--b:51.26%"></i><i class="plot-mark plot-mark-open" style="--x:27.45%"></i><i class="plot-mark plot-mark-half" style="--x:22.9%"></i><i class="plot-mark" style="--x:51.26%"></i></span><span class="plot-figure">3.58</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: 100 kbit/s 0.92, 3 Gbit/s 0.77, saturated 5.45 ms, 0.03% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:21.56%;--b:59.35%"></i><i class="plot-mark plot-mark-open" style="--x:25.05%"></i><i class="plot-mark plot-mark-half" style="--x:21.56%"></i><i class="plot-mark" style="--x:59.35%"></i></span><span class="plot-figure">5.45</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: 100 kbit/s 0.99, 3 Gbit/s 0.86, saturated 5.29 ms, 0.03% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:23.86%;--b:58.77%"></i><i class="plot-mark plot-mark-open" style="--x:26.44%"></i><i class="plot-mark plot-mark-half" style="--x:23.86%"></i><i class="plot-mark" style="--x:58.77%"></i></span><span class="plot-figure">5.29</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: 100 kbit/s 0.93, 3 Gbit/s 0.79, saturated 5.26 ms, 0.05% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:22.18%;--b:58.66%"></i><i class="plot-mark plot-mark-open" style="--x:25.36%"></i><i class="plot-mark plot-mark-half" style="--x:22.18%"></i><i class="plot-mark" style="--x:58.66%"></i></span><span class="plot-figure">5.26</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: 100 kbit/s 0.92, 3 Gbit/s 0.55, saturated 1.26 ms, 0.03% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:15.15%;--b:31.15%"></i><i class="plot-mark plot-mark-open" style="--x:25.13%"></i><i class="plot-mark plot-mark-half" style="--x:15.15%"></i><i class="plot-mark" style="--x:31.15%"></i></span><span class="plot-figure">1.26</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard: 100 kbit/s 0.93, 3 Gbit/s 0.44, saturated 1.15 ms, 0.11% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:10.8%;--b:29.39%"></i><i class="plot-mark plot-mark-open" style="--x:25.19%"></i><i class="plot-mark plot-mark-half" style="--x:10.8%"></i><i class="plot-mark" style="--x:29.39%"></i></span><span class="plot-figure">1.15</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec: 100 kbit/s 0.38, 3 Gbit/s 0.96, saturated 0.77 ms, 0.00% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:8.06%;--b:25.99%"></i><i class="plot-mark plot-mark-open" style="--x:8.06%"></i><i class="plot-mark plot-mark-half" style="--x:25.99%"></i><i class="plot-mark" style="--x:21.69%"></i></span><span class="plot-figure">0.77</span></div>
<div class="plot-axis"><div><span style="--x:3.51%">0.3</span><span style="--x:26.7%">1</span><span style="--x:47.85%">3</span><span style="--x:71.04%">10</span><span style="--x:92.19%">30</span></div></div>
</div>
</figure>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>8 streams</b><span class="text-mute">RTT p99, ms, one way out</span><span class="text-hint">Lower is better</span></figcaption>
<div class="plot" role="img" aria-label="RTT p99 in milliseconds at 8 streams one way, by load, for each dataplane, on a log scale." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 3.51% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 26.7% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 47.85% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 71.04% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 92.19% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: 3 Gbit/s 1.24, saturated 8.60 ms, 0.15% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:30.84%;--b:68.13%"></i><i class="plot-mark plot-mark-half" style="--x:30.84%"></i><i class="plot-mark" style="--x:68.13%"></i></span><span class="plot-figure">8.60</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: 3 Gbit/s 1.95, saturated 20.80 ms, 0.18% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:39.56%;--b:85.14%"></i><i class="plot-mark plot-mark-half" style="--x:39.56%"></i><i class="plot-mark" style="--x:85.14%"></i></span><span class="plot-figure">20.80</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: 3 Gbit/s 1.84, saturated 33.00 ms, 0.34% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:38.44%;--b:94.03%"></i><i class="plot-mark plot-mark-half" style="--x:38.44%"></i><i class="plot-mark" style="--x:94.03%"></i></span><span class="plot-figure">33.00</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: 3 Gbit/s 2.07, saturated 13.10 ms, 0.10% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span" style="--a:40.71%;--b:76.24%"></i><i class="plot-mark plot-mark-half" style="--x:40.71%"></i><i class="plot-mark" style="--x:76.24%"></i></span><span class="plot-figure">13.10</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: 3 Gbit/s 1.34, saturated 1.61 ms, 1.29% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:32.33%;--b:35.87%"></i><i class="plot-mark plot-mark-half" style="--x:32.33%"></i><i class="plot-mark" style="--x:35.87%"></i></span><span class="plot-figure">1.61</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard: 3 Gbit/s 1.32, saturated 1.62 ms, 0.84% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:32.04%;--b:35.99%"></i><i class="plot-mark plot-mark-half" style="--x:32.04%"></i><i class="plot-mark" style="--x:35.99%"></i></span><span class="plot-figure">1.62</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec: 3 Gbit/s 1.58, saturated 1.22 ms, 0.66% of pings lost when saturated"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span" style="--a:30.52%;--b:35.5%"></i><i class="plot-mark plot-mark-half" style="--x:35.5%"></i><i class="plot-mark" style="--x:30.52%"></i></span><span class="plot-figure">1.22</span></div>
<div class="plot-axis"><div><span style="--x:3.51%">0.3</span><span style="--x:26.7%">1</span><span style="--x:47.85%">3</span><span style="--x:71.04%">10</span><span style="--x:92.19%">30</span></div></div>
</div>
</figure>
<p class="note">At 1 stream every dataplane except kernel IPsec has a lower p99 at 3 Gbit/s than at 100 kbit/s.</p>
<p class="callout text-[.9em]">These figures count the replies that came back. At 8 streams the kernel dataplanes lost <span class="whitespace-nowrap">0.66-1.90%</span> of their pings under saturation and <span class="whitespace-nowrap">0.87-1.76%</span> at 3 Gbit/s, against at most 0.21% and 0.00% for ranet3. Where the loss passes 1%, a p99 over every ping sent would be a lost ping, which makes the kernel figures here a lower bound.</p>
<h2 id="cpu-cost" class="mt-[3em] text-[1.5em] font-bold text-fg">CPU cost</h2>
<p class="mt-[.6em] text-fg2">CPU cost is measured at 3 Gbit/s offered, where ranet3 uses <span class="whitespace-nowrap">0.96-1.23</span> busy cores per Gbit/s over both hosts. That is <span class="whitespace-nowrap">0.86-1.02x</span> the userspace WireGuard dataplanes and <span class="whitespace-nowrap">0.61-0.72x</span> NetBird kernel and kernel WireGuard. Kernel IPsec costs the least, at <span class="whitespace-nowrap">0.52-0.82.</span></p>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>CPU cost at 3 Gbit/s offered</b><span class="text-mute">Busy cores per Gbit/s, both hosts</span><span class="text-hint">Lower is better</span></figcaption>
<div class="plot-keys"><span><i class="plot-mark "></i>Median of 6 tests, the bar spanning their lowest and highest</span></div>
<div class="plot" role="img" aria-label="Busy cores per Gbit/s at 3 Gbit/s offered, the range over 6 tests for each dataplane." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 0.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 25.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 50.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 75.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 100.0% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: 1 out 1.051, 1 in 1.048, 1 both 0.960, 8 out 1.194, 8 in 1.229, 8 both 1.096"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:48.01%;--b:61.44%"></i><i class="plot-mark" style="--x:53.7%"></i></span><span class="plot-figure">0.96-1.23</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: 1 out 1.180, 1 in 1.172, 1 both 1.083, 8 out 1.361, 8 in 1.371, 8 both 1.199"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:54.13%;--b:68.55%"></i><i class="plot-mark" style="--x:59.47%"></i></span><span class="plot-figure">1.08-1.37</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: 1 out 1.175, 1 in 1.183, 1 both 1.025, 8 out 1.239, 8 in 1.238, 8 both 1.074"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:51.26%;--b:61.95%"></i><i class="plot-mark" style="--x:58.94%"></i></span><span class="plot-figure">1.03-1.24</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: 1 out 1.202, 1 in 1.201, 1 both 1.104, 8 out 1.383, 8 in 1.384, 8 both 1.210"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:55.19%;--b:69.21%"></i><i class="plot-mark" style="--x:60.29%"></i></span><span class="plot-figure">1.10-1.38</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: 1 out 1.590, 1 in 1.609, 1 both 1.571, 8 out 1.856, 8 in 1.848, 8 both 1.629"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:78.57%;--b:92.79%"></i><i class="plot-mark" style="--x:80.93%"></i></span><span class="plot-figure">1.57-1.86</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard: 1 out 1.478, 1 in 1.488, 1 both 1.468, 8 out 1.726, 8 in 1.744, 8 both 1.520"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:73.4%;--b:87.18%"></i><i class="plot-mark" style="--x:75.2%"></i></span><span class="plot-figure">1.47-1.74</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec: 1 out 0.639, 1 in 0.642, 1 both 0.523, 8 out 0.817, 8 in 0.813, 8 both 0.633"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:26.14%;--b:40.86%"></i><i class="plot-mark" style="--x:32.02%"></i></span><span class="plot-figure">0.52-0.82</span></div>
<div class="plot-axis"><div><span style="--x:0.0%">0</span><span style="--x:25.0%">0.5</span><span style="--x:50.0%">1</span><span style="--x:75.0%">1.5</span><span style="--x:100.0%">2</span></div></div>
</div>
</figure>
<p class="note">In the both ways tests kernel IPsec carried 4.72 and 4.14 of the 6 Gbit/s offered, and NetBird kernel 5.96 at 8 streams.</p>
<h2 id="memory" class="mt-[3em] text-[1.5em] font-bold text-fg">Memory</h2>
<p class="mt-[.6em] text-fg2">The ranet3 process peaks at <span class="whitespace-nowrap">155-180</span> MiB at 8 streams saturated. Under the same load wireguard-go peaks at <span class="whitespace-nowrap">94-959</span> MiB, Tailscale at <span class="whitespace-nowrap">57-91</span> and NetBird userspace at <span class="whitespace-nowrap">166-825</span>, depending on the direction and the host.</p>
<figure class="mt-[2em]">
<figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Peak memory at 8 streams saturated</b><span class="text-mute">RSS of each process, MiB</span><span class="text-hint">Lower is better</span></figcaption>
<div class="plot" role="img" aria-label="Peak resident memory of each dataplane&#x27;s process in MiB at 8 streams saturated." style="--grid:linear-gradient(var(--bg2),var(--bg2)) 0.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 25.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 50.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 75.0% 0/1px 100% no-repeat,linear-gradient(var(--bg2),var(--bg2)) 100.0% 0/1px 100% no-repeat">
<div class="plot-row plot-accent" title="ranet3: peak RSS 155-180 MiB"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:15.55%;--b:17.96%"></i></span><span class="plot-figure">155-180</span></div>
<div class="plot-row" style="--c:var(--mark-1)" title="wireguard-go: peak RSS 94-959 MiB"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-1)"></i>wireguard-go</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:9.45%;--b:95.87%"></i></span><span class="plot-figure">94-959</span></div>
<div class="plot-row" style="--c:var(--mark-2)" title="Tailscale: peak RSS 57-91 MiB"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:5.69%;--b:9.06%"></i></span><span class="plot-figure">57-91</span></div>
<div class="plot-row" style="--c:var(--mark-3)" title="NetBird userspace: peak RSS 166-825 MiB"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</span> <small>user</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:16.6%;--b:82.47%"></i></span><span class="plot-figure">166-825</span></div>
<div class="plot-row" style="--c:var(--mark-4)" title="NetBird kernel: peak RSS 60 MiB"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</span> <small>kernel</small></span><span class="plot-track"><i class="plot-span plot-bar" style="--a:5.97%;--b:6.77%"></i></span><span class="plot-figure">60</span></div>
<div class="plot-row" style="--c:var(--mark-5)" title="kernel WireGuard has no process to measure"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</span> <small>kernel</small></span><span class="plot-track"></span><span class="plot-figure">no process</span></div>
<div class="plot-row" style="--c:var(--mark-6)" title="kernel IPsec has no process to measure"><span class="plot-label"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span> <small>kernel</small></span><span class="plot-track"></span><span class="plot-figure">no process</span></div>
<div class="plot-axis"><div><span style="--x:0.0%">0</span><span style="--x:25.0%">250</span><span style="--x:50.0%">500</span><span style="--x:75.0%">750</span><span style="--x:100.0%">1000</span></div></div>
</div>
</figure>
<p class="note">The figure for NetBird kernel is its control process alone. RSS leaves out the kernel's own buffers, and kernel WireGuard and kernel IPsec have no process to measure.</p>
<h2 id="all-figures" class="mt-[3em] text-[1.5em] font-bold text-fg">All figures</h2>
<p class="note">The range under a figure spans its lowest and highest run. Each bar is the value over its row's largest.</p>
<div class="mt-[1em] border-t border-line">
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Throughput, saturated<small>Gbit/s received at 1 and 8 streams</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint td-best">8.78<small class="block font-normal whitespace-nowrap">8.76-8.80</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.08<small class="block font-normal whitespace-nowrap">6.86-7.41</small><span class="meter" style="--w:80.5%;--fill:var(--mark-1)"></span></td><td>6.72<small class="block font-normal whitespace-nowrap">6.51-6.86</small><span class="meter" style="--w:76.5%;--fill:var(--mark-2)"></span></td><td>6.83<small class="block font-normal whitespace-nowrap">6.67-6.98</small><span class="meter" style="--w:77.8%;--fill:var(--mark-3)"></span></td><td>4.04<small class="block font-normal whitespace-nowrap">3.98-4.20</small><span class="meter" style="--w:46%;--fill:var(--mark-4)"></span></td><td>5.33<small class="block font-normal whitespace-nowrap">5.25-5.53</small><span class="meter" style="--w:60.7%;--fill:var(--mark-5)"></span></td><td>4.65<small class="block font-normal whitespace-nowrap">4.63-4.69</small><span class="meter" style="--w:52.9%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint td-best">8.80<small class="block font-normal whitespace-nowrap">8.62-8.82</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.20<small class="block font-normal whitespace-nowrap">6.98-7.35</small><span class="meter" style="--w:81.8%;--fill:var(--mark-1)"></span></td><td>6.80<small class="block font-normal whitespace-nowrap">6.68-6.84</small><span class="meter" style="--w:77.2%;--fill:var(--mark-2)"></span></td><td>6.89<small class="block font-normal whitespace-nowrap">6.76-7.12</small><span class="meter" style="--w:78.2%;--fill:var(--mark-3)"></span></td><td>4.01<small class="block font-normal whitespace-nowrap">3.96-4.04</small><span class="meter" style="--w:45.5%;--fill:var(--mark-4)"></span></td><td>5.27<small class="block font-normal whitespace-nowrap">5.15-5.40</small><span class="meter" style="--w:59.8%;--fill:var(--mark-5)"></span></td><td>4.62<small class="block font-normal whitespace-nowrap">4.60-4.66</small><span class="meter" style="--w:52.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint td-best">16.09<small class="block font-normal whitespace-nowrap">15.77-16.26</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>11.20<small class="block font-normal whitespace-nowrap">11.02-11.37</small><span class="meter" style="--w:69.6%;--fill:var(--mark-1)"></span></td><td>10.91<small class="block font-normal whitespace-nowrap">10.18-11.08</small><span class="meter" style="--w:67.8%;--fill:var(--mark-2)"></span></td><td>10.84<small class="block font-normal whitespace-nowrap">10.57-11.13</small><span class="meter" style="--w:67.4%;--fill:var(--mark-3)"></span></td><td>6.38<small class="block font-normal whitespace-nowrap">6.23-6.45</small><span class="meter" style="--w:39.7%;--fill:var(--mark-4)"></span></td><td>8.44<small class="block font-normal whitespace-nowrap">8.28-8.56</small><span class="meter" style="--w:52.5%;--fill:var(--mark-5)"></span></td><td>4.75<small class="block font-normal whitespace-nowrap">4.66-4.78</small><span class="meter" style="--w:29.5%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint td-best">8.78<small class="block font-normal whitespace-nowrap">8.78-8.80</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.68<small class="block font-normal whitespace-nowrap">6.39-6.93</small><span class="meter" style="--w:76%;--fill:var(--mark-1)"></span></td><td>6.45<small class="block font-normal whitespace-nowrap">6.39-6.47</small><span class="meter" style="--w:73.4%;--fill:var(--mark-2)"></span></td><td>6.47<small class="block font-normal whitespace-nowrap">6.32-6.73</small><span class="meter" style="--w:73.7%;--fill:var(--mark-3)"></span></td><td>4.00<small class="block font-normal whitespace-nowrap">3.44-4.08</small><span class="meter" style="--w:45.5%;--fill:var(--mark-4)"></span></td><td>5.26<small class="block font-normal whitespace-nowrap">4.38-5.38</small><span class="meter" style="--w:59.9%;--fill:var(--mark-5)"></span></td><td>4.03<small class="block font-normal whitespace-nowrap">4.02-4.04</small><span class="meter" style="--w:45.9%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint td-best">8.80<small class="block font-normal whitespace-nowrap">8.79-8.82</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.75<small class="block font-normal whitespace-nowrap">6.50-6.91</small><span class="meter" style="--w:76.6%;--fill:var(--mark-1)"></span></td><td>6.46<small class="block font-normal whitespace-nowrap">6.39-6.57</small><span class="meter" style="--w:73.3%;--fill:var(--mark-2)"></span></td><td>6.56<small class="block font-normal whitespace-nowrap">6.32-6.67</small><span class="meter" style="--w:74.5%;--fill:var(--mark-3)"></span></td><td>3.98<small class="block font-normal whitespace-nowrap">3.93-4.08</small><span class="meter" style="--w:45.1%;--fill:var(--mark-4)"></span></td><td>5.23<small class="block font-normal whitespace-nowrap">5.15-5.38</small><span class="meter" style="--w:59.4%;--fill:var(--mark-5)"></span></td><td>4.02<small class="block font-normal whitespace-nowrap">3.97-4.04</small><span class="meter" style="--w:45.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint td-best">16.65<small class="block font-normal whitespace-nowrap">16.47-16.73</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>10.45<small class="block font-normal whitespace-nowrap">10.27-10.72</small><span class="meter" style="--w:62.8%;--fill:var(--mark-1)"></span></td><td>10.29<small class="block font-normal whitespace-nowrap">9.92-10.41</small><span class="meter" style="--w:61.8%;--fill:var(--mark-2)"></span></td><td>10.16<small class="block font-normal whitespace-nowrap">9.87-10.35</small><span class="meter" style="--w:61%;--fill:var(--mark-3)"></span></td><td>6.28<small class="block font-normal whitespace-nowrap">4.68-6.46</small><span class="meter" style="--w:37.7%;--fill:var(--mark-4)"></span></td><td>8.58<small class="block font-normal whitespace-nowrap">5.85-8.71</small><span class="meter" style="--w:51.5%;--fill:var(--mark-5)"></span></td><td>4.12<small class="block font-normal whitespace-nowrap">4.03-4.15</small><span class="meter" style="--w:24.7%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Throughput at 2, 4 and 16 streams<small>Gbit/s received</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">2 streams<small class="block">out</small></th>
<td class="bg-tint td-best">8.80<small class="block font-normal whitespace-nowrap">8.79-8.81</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.94<small class="block font-normal whitespace-nowrap">6.81-7.25</small><span class="meter" style="--w:78.8%;--fill:var(--mark-1)"></span></td><td>6.66<small class="block font-normal whitespace-nowrap">6.57-6.75</small><span class="meter" style="--w:75.7%;--fill:var(--mark-2)"></span></td><td>6.72<small class="block font-normal whitespace-nowrap">6.54-6.96</small><span class="meter" style="--w:76.4%;--fill:var(--mark-3)"></span></td><td>4.00<small class="block font-normal whitespace-nowrap">3.55-4.07</small><span class="meter" style="--w:45.4%;--fill:var(--mark-4)"></span></td><td>5.28<small class="block font-normal whitespace-nowrap">5.18-5.43</small><span class="meter" style="--w:60%;--fill:var(--mark-5)"></span></td><td>4.57<small class="block font-normal whitespace-nowrap">4.51-4.61</small><span class="meter" style="--w:51.9%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">4 streams<small class="block">out</small></th>
<td class="bg-tint td-best">8.80<small class="block font-normal whitespace-nowrap">8.78-8.80</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.87<small class="block font-normal whitespace-nowrap">6.76-7.00</small><span class="meter" style="--w:78.2%;--fill:var(--mark-1)"></span></td><td>6.52<small class="block font-normal whitespace-nowrap">6.43-6.62</small><span class="meter" style="--w:74.2%;--fill:var(--mark-2)"></span></td><td>6.59<small class="block font-normal whitespace-nowrap">6.45-6.81</small><span class="meter" style="--w:74.9%;--fill:var(--mark-3)"></span></td><td>4.04<small class="block font-normal whitespace-nowrap">3.06-4.11</small><span class="meter" style="--w:46%;--fill:var(--mark-4)"></span></td><td>5.27<small class="block font-normal whitespace-nowrap">5.19-5.44</small><span class="meter" style="--w:59.9%;--fill:var(--mark-5)"></span></td><td>4.31<small class="block font-normal whitespace-nowrap">4.23-4.33</small><span class="meter" style="--w:49.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">16 streams<small class="block">out</small></th>
<td class="bg-tint td-best">8.77<small class="block font-normal whitespace-nowrap">8.75-8.78</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.48<small class="block font-normal whitespace-nowrap">6.08-6.72</small><span class="meter" style="--w:73.9%;--fill:var(--mark-1)"></span></td><td>6.41<small class="block font-normal whitespace-nowrap">6.34-6.44</small><span class="meter" style="--w:73%;--fill:var(--mark-2)"></span></td><td>6.26<small class="block font-normal whitespace-nowrap">6.07-6.55</small><span class="meter" style="--w:71.4%;--fill:var(--mark-3)"></span></td><td>4.00<small class="block font-normal whitespace-nowrap">3.94-4.09</small><span class="meter" style="--w:45.6%;--fill:var(--mark-4)"></span></td><td>5.19<small class="block font-normal whitespace-nowrap">4.58-5.30</small><span class="meter" style="--w:59.2%;--fill:var(--mark-5)"></span></td><td>3.77<small class="block font-normal whitespace-nowrap">3.74-3.79</small><span class="meter" style="--w:43%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">2 streams<small class="block">in</small></th>
<td class="bg-tint td-best">8.81<small class="block font-normal whitespace-nowrap">8.63-8.82</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.07<small class="block font-normal whitespace-nowrap">6.78-7.26</small><span class="meter" style="--w:80.2%;--fill:var(--mark-1)"></span></td><td>6.67<small class="block font-normal whitespace-nowrap">6.60-6.75</small><span class="meter" style="--w:75.7%;--fill:var(--mark-2)"></span></td><td>6.74<small class="block font-normal whitespace-nowrap">6.54-6.93</small><span class="meter" style="--w:76.5%;--fill:var(--mark-3)"></span></td><td>3.94<small class="block font-normal whitespace-nowrap">3.87-4.05</small><span class="meter" style="--w:44.7%;--fill:var(--mark-4)"></span></td><td>5.26<small class="block font-normal whitespace-nowrap">4.58-5.37</small><span class="meter" style="--w:59.7%;--fill:var(--mark-5)"></span></td><td>4.54<small class="block font-normal whitespace-nowrap">4.48-4.58</small><span class="meter" style="--w:51.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">4 streams<small class="block">in</small></th>
<td class="bg-tint td-best">8.81<small class="block font-normal whitespace-nowrap">8.80-8.83</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.99<small class="block font-normal whitespace-nowrap">6.84-7.16</small><span class="meter" style="--w:79.3%;--fill:var(--mark-1)"></span></td><td>6.52<small class="block font-normal whitespace-nowrap">6.50-6.59</small><span class="meter" style="--w:74.1%;--fill:var(--mark-2)"></span></td><td>6.71<small class="block font-normal whitespace-nowrap">6.49-6.88</small><span class="meter" style="--w:76.2%;--fill:var(--mark-3)"></span></td><td>3.96<small class="block font-normal whitespace-nowrap">3.87-4.11</small><span class="meter" style="--w:45%;--fill:var(--mark-4)"></span></td><td>5.19<small class="block font-normal whitespace-nowrap">3.92-5.25</small><span class="meter" style="--w:58.9%;--fill:var(--mark-5)"></span></td><td>4.28<small class="block font-normal whitespace-nowrap">4.19-4.32</small><span class="meter" style="--w:48.6%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">16 streams<small class="block">in</small></th>
<td class="bg-tint td-best">8.79<small class="block font-normal whitespace-nowrap">8.76-8.81</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>6.67<small class="block font-normal whitespace-nowrap">6.22-6.88</small><span class="meter" style="--w:75.9%;--fill:var(--mark-1)"></span></td><td>6.35<small class="block font-normal whitespace-nowrap">6.30-6.47</small><span class="meter" style="--w:72.2%;--fill:var(--mark-2)"></span></td><td>6.30<small class="block font-normal whitespace-nowrap">5.93-6.61</small><span class="meter" style="--w:71.6%;--fill:var(--mark-3)"></span></td><td>3.90<small class="block font-normal whitespace-nowrap">3.49-4.06</small><span class="meter" style="--w:44.4%;--fill:var(--mark-4)"></span></td><td>5.15<small class="block font-normal whitespace-nowrap">4.99-5.28</small><span class="meter" style="--w:58.6%;--fill:var(--mark-5)"></span></td><td>3.77<small class="block font-normal whitespace-nowrap">3.70-3.79</small><span class="meter" style="--w:42.9%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">2 streams<small class="block">both</small></th>
<td class="bg-tint td-best">16.22<small class="block font-normal whitespace-nowrap">16.04-16.46</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>10.95<small class="block font-normal whitespace-nowrap">10.70-11.27</small><span class="meter" style="--w:67.5%;--fill:var(--mark-1)"></span></td><td>10.95<small class="block font-normal whitespace-nowrap">10.18-11.12</small><span class="meter" style="--w:67.5%;--fill:var(--mark-2)"></span></td><td>10.56<small class="block font-normal whitespace-nowrap">10.30-10.83</small><span class="meter" style="--w:65.1%;--fill:var(--mark-3)"></span></td><td>6.31<small class="block font-normal whitespace-nowrap">5.68-6.46</small><span class="meter" style="--w:38.9%;--fill:var(--mark-4)"></span></td><td>8.49<small class="block font-normal whitespace-nowrap">7.78-8.63</small><span class="meter" style="--w:52.4%;--fill:var(--mark-5)"></span></td><td>4.62<small class="block font-normal whitespace-nowrap">4.53-4.73</small><span class="meter" style="--w:28.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">4 streams<small class="block">both</small></th>
<td class="bg-tint td-best">16.40<small class="block font-normal whitespace-nowrap">16.01-16.58</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>10.78<small class="block font-normal whitespace-nowrap">10.62-10.91</small><span class="meter" style="--w:65.7%;--fill:var(--mark-1)"></span></td><td>10.55<small class="block font-normal whitespace-nowrap">10.36-10.80</small><span class="meter" style="--w:64.3%;--fill:var(--mark-2)"></span></td><td>10.40<small class="block font-normal whitespace-nowrap">10.20-10.57</small><span class="meter" style="--w:63.5%;--fill:var(--mark-3)"></span></td><td>6.45<small class="block font-normal whitespace-nowrap">4.58-6.50</small><span class="meter" style="--w:39.3%;--fill:var(--mark-4)"></span></td><td>8.54<small class="block font-normal whitespace-nowrap">5.77-8.73</small><span class="meter" style="--w:52.1%;--fill:var(--mark-5)"></span></td><td>4.37<small class="block font-normal whitespace-nowrap">4.29-4.42</small><span class="meter" style="--w:26.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">16 streams<small class="block">both</small></th>
<td class="bg-tint td-best">16.64<small class="block font-normal whitespace-nowrap">16.39-16.78</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>10.09<small class="block font-normal whitespace-nowrap">9.97-10.39</small><span class="meter" style="--w:60.6%;--fill:var(--mark-1)"></span></td><td>10.15<small class="block font-normal whitespace-nowrap">9.89-10.26</small><span class="meter" style="--w:61%;--fill:var(--mark-2)"></span></td><td>9.90<small class="block font-normal whitespace-nowrap">9.74-10.14</small><span class="meter" style="--w:59.5%;--fill:var(--mark-3)"></span></td><td>6.19<small class="block font-normal whitespace-nowrap">4.47-6.39</small><span class="meter" style="--w:37.2%;--fill:var(--mark-4)"></span></td><td>8.32<small class="block font-normal whitespace-nowrap">5.76-8.40</small><span class="meter" style="--w:50%;--fill:var(--mark-5)"></span></td><td>3.87<small class="block font-normal whitespace-nowrap">3.82-3.89</small><span class="meter" style="--w:23.2%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Packet rate<small>Mpps received, 8 streams, GSO off</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">64<small class="block">bytes, out</small></th>
<td class="bg-tint">0.320<small class="block font-normal whitespace-nowrap">0.307-0.327</small><span class="meter" style="--w:60.8%;--fill:var(--mark)"></span></td><td>0.177<small class="block font-normal whitespace-nowrap">0.176-0.178</small><span class="meter" style="--w:33.7%;--fill:var(--mark-1)"></span></td><td>0.140<small class="block font-normal whitespace-nowrap">0.137-0.150</small><span class="meter" style="--w:26.7%;--fill:var(--mark-2)"></span></td><td>0.174<small class="block font-normal whitespace-nowrap">0.171-0.177</small><span class="meter" style="--w:33.1%;--fill:var(--mark-3)"></span></td><td>0.390<small class="block font-normal whitespace-nowrap">0.269-0.395</small><span class="meter" style="--w:74.1%;--fill:var(--mark-4)"></span></td><td class="td-best">0.526<small class="block font-normal whitespace-nowrap">0.375-0.540</small><span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>0.308<small class="block font-normal whitespace-nowrap">0.299-0.312</small><span class="meter" style="--w:58.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, in</small></th>
<td class="bg-tint">0.322<small class="block font-normal whitespace-nowrap">0.314-0.326</small><span class="meter" style="--w:56.4%;--fill:var(--mark)"></span></td><td>0.181<small class="block font-normal whitespace-nowrap">0.178-0.183</small><span class="meter" style="--w:31.7%;--fill:var(--mark-1)"></span></td><td>0.143<small class="block font-normal whitespace-nowrap">0.136-0.154</small><span class="meter" style="--w:25%;--fill:var(--mark-2)"></span></td><td>0.175<small class="block font-normal whitespace-nowrap">0.173-0.177</small><span class="meter" style="--w:30.7%;--fill:var(--mark-3)"></span></td><td>0.413<small class="block font-normal whitespace-nowrap">0.277-0.425</small><span class="meter" style="--w:72.3%;--fill:var(--mark-4)"></span></td><td class="td-best">0.570<small class="block font-normal whitespace-nowrap">0.386-0.586</small><span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>0.325<small class="block font-normal whitespace-nowrap">0.320-0.327</small><span class="meter" style="--w:57.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, both</small></th>
<td class="bg-tint td-best">0.621<small class="block font-normal whitespace-nowrap">0.605-0.633</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.338<small class="block font-normal whitespace-nowrap">0.336-0.342</small><span class="meter" style="--w:54.5%;--fill:var(--mark-1)"></span></td><td>0.274<small class="block font-normal whitespace-nowrap">0.270-0.281</small><span class="meter" style="--w:44.1%;--fill:var(--mark-2)"></span></td><td>0.326<small class="block font-normal whitespace-nowrap">0.323-0.336</small><span class="meter" style="--w:52.6%;--fill:var(--mark-3)"></span></td><td>0.339<small class="block font-normal whitespace-nowrap">0.294-0.555</small><span class="meter" style="--w:54.6%;--fill:var(--mark-4)"></span></td><td>0.449<small class="block font-normal whitespace-nowrap">0.363-0.533</small><span class="meter" style="--w:72.3%;--fill:var(--mark-5)"></span></td><td>0.537<small class="block font-normal whitespace-nowrap">0.519-0.547</small><span class="meter" style="--w:86.4%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">1400<small class="block">bytes, out</small></th>
<td class="bg-tint">0.287<small class="block font-normal whitespace-nowrap">0.284-0.292</small><span class="meter" style="--w:71.8%;--fill:var(--mark)"></span></td><td>0.169<small class="block font-normal whitespace-nowrap">0.166-0.172</small><span class="meter" style="--w:42.5%;--fill:var(--mark-1)"></span></td><td>0.118<small class="block font-normal whitespace-nowrap">0.116-0.119</small><span class="meter" style="--w:29.5%;--fill:var(--mark-2)"></span></td><td>0.167<small class="block font-normal whitespace-nowrap">0.164-0.168</small><span class="meter" style="--w:41.7%;--fill:var(--mark-3)"></span></td><td>0.328<small class="block font-normal whitespace-nowrap">0.271-0.346</small><span class="meter" style="--w:82.1%;--fill:var(--mark-4)"></span></td><td class="td-best">0.399<small class="block font-normal whitespace-nowrap">0.330-0.451</small><span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>0.275<small class="block font-normal whitespace-nowrap">0.270-0.276</small><span class="meter" style="--w:68.8%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, in</small></th>
<td class="bg-tint">0.287<small class="block font-normal whitespace-nowrap">0.284-0.294</small><span class="meter" style="--w:67.8%;--fill:var(--mark)"></span></td><td>0.173<small class="block font-normal whitespace-nowrap">0.170-0.174</small><span class="meter" style="--w:40.8%;--fill:var(--mark-1)"></span></td><td>0.116<small class="block font-normal whitespace-nowrap">0.114-0.117</small><span class="meter" style="--w:27.3%;--fill:var(--mark-2)"></span></td><td>0.168<small class="block font-normal whitespace-nowrap">0.167-0.169</small><span class="meter" style="--w:39.6%;--fill:var(--mark-3)"></span></td><td>0.308<small class="block font-normal whitespace-nowrap">0.263-0.349</small><span class="meter" style="--w:72.6%;--fill:var(--mark-4)"></span></td><td class="td-best">0.424<small class="block font-normal whitespace-nowrap">0.316-0.492</small><span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>0.288<small class="block font-normal whitespace-nowrap">0.285-0.290</small><span class="meter" style="--w:67.9%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, both</small></th>
<td class="bg-tint td-best">0.523<small class="block font-normal whitespace-nowrap">0.512-0.537</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.320<small class="block font-normal whitespace-nowrap">0.317-0.321</small><span class="meter" style="--w:61.1%;--fill:var(--mark-1)"></span></td><td>0.225<small class="block font-normal whitespace-nowrap">0.224-0.226</small><span class="meter" style="--w:43.1%;--fill:var(--mark-2)"></span></td><td>0.310<small class="block font-normal whitespace-nowrap">0.307-0.312</small><span class="meter" style="--w:59.3%;--fill:var(--mark-3)"></span></td><td>0.246<small class="block font-normal whitespace-nowrap">0.205-0.417</small><span class="meter" style="--w:47.1%;--fill:var(--mark-4)"></span></td><td>0.401<small class="block font-normal whitespace-nowrap">0.387-0.494</small><span class="meter" style="--w:76.7%;--fill:var(--mark-5)"></span></td><td>0.473<small class="block font-normal whitespace-nowrap">0.463-0.480</small><span class="meter" style="--w:90.4%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
<p class="note">Busy cores over both hosts in these tests, under overload</p>
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">64<small class="block">bytes, out</small></th>
<td class="bg-tint">15.8<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.6<span class="meter" style="--w:47.8%;--fill:var(--mark-1)"></span></td><td>7.6<span class="meter" style="--w:48.1%;--fill:var(--mark-2)"></span></td><td>7.6<span class="meter" style="--w:47.9%;--fill:var(--mark-3)"></span></td><td>10.8<span class="meter" style="--w:68%;--fill:var(--mark-4)"></span></td><td>12.0<span class="meter" style="--w:76%;--fill:var(--mark-5)"></span></td><td>5.8<span class="meter" style="--w:36.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, in</small></th>
<td class="bg-tint">16.0<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.6<span class="meter" style="--w:47.5%;--fill:var(--mark-1)"></span></td><td>7.6<span class="meter" style="--w:47.1%;--fill:var(--mark-2)"></span></td><td>7.6<span class="meter" style="--w:47.6%;--fill:var(--mark-3)"></span></td><td>11.2<span class="meter" style="--w:69.7%;--fill:var(--mark-4)"></span></td><td>12.3<span class="meter" style="--w:76.4%;--fill:var(--mark-5)"></span></td><td>5.9<span class="meter" style="--w:36.8%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, both</small></th>
<td class="bg-tint">28.6<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>14.4<span class="meter" style="--w:50.5%;--fill:var(--mark-1)"></span></td><td>14.7<span class="meter" style="--w:51.4%;--fill:var(--mark-2)"></span></td><td>14.4<span class="meter" style="--w:50.6%;--fill:var(--mark-3)"></span></td><td>13.7<span class="meter" style="--w:47.8%;--fill:var(--mark-4)"></span></td><td>13.7<span class="meter" style="--w:48%;--fill:var(--mark-5)"></span></td><td>10.2<span class="meter" style="--w:35.6%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">1400<small class="block">bytes, out</small></th>
<td class="bg-tint">16.0<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.0<span class="meter" style="--w:43.8%;--fill:var(--mark-1)"></span></td><td>6.2<span class="meter" style="--w:38.6%;--fill:var(--mark-2)"></span></td><td>7.0<span class="meter" style="--w:43.8%;--fill:var(--mark-3)"></span></td><td>11.9<span class="meter" style="--w:74.7%;--fill:var(--mark-4)"></span></td><td>12.6<span class="meter" style="--w:79%;--fill:var(--mark-5)"></span></td><td>5.8<span class="meter" style="--w:36.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, in</small></th>
<td class="bg-tint">16.5<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>7.0<span class="meter" style="--w:42.5%;--fill:var(--mark-1)"></span></td><td>6.2<span class="meter" style="--w:37.7%;--fill:var(--mark-2)"></span></td><td>7.0<span class="meter" style="--w:42.2%;--fill:var(--mark-3)"></span></td><td>12.0<span class="meter" style="--w:72.7%;--fill:var(--mark-4)"></span></td><td>12.7<span class="meter" style="--w:77%;--fill:var(--mark-5)"></span></td><td>5.8<span class="meter" style="--w:35.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, both</small></th>
<td class="bg-tint">29.8<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>13.9<span class="meter" style="--w:46.8%;--fill:var(--mark-1)"></span></td><td>12.4<span class="meter" style="--w:41.6%;--fill:var(--mark-2)"></span></td><td>14.0<span class="meter" style="--w:46.8%;--fill:var(--mark-3)"></span></td><td>14.1<span class="meter" style="--w:47.4%;--fill:var(--mark-4)"></span></td><td>15.4<span class="meter" style="--w:51.7%;--fill:var(--mark-5)"></span></td><td>10.1<span class="meter" style="--w:34%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Latency under saturation<small>RTT p99 in ms, with the lowest and highest run's own p99 under it</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint">3.58<small class="block font-normal whitespace-nowrap">2.74-4.12</small><span class="meter" style="--w:65.7%;--fill:var(--mark)"></span></td><td>5.45<small class="block font-normal whitespace-nowrap">3.61-6.13</small><span class="meter" style="--w:100%;--fill:var(--mark-1)"></span></td><td>5.29<small class="block font-normal whitespace-nowrap">4.52-5.72</small><span class="meter" style="--w:97.1%;--fill:var(--mark-2)"></span></td><td>5.26<small class="block font-normal whitespace-nowrap">3.12-6.38</small><span class="meter" style="--w:96.5%;--fill:var(--mark-3)"></span></td><td>1.26<small class="block font-normal whitespace-nowrap">1.07-1.34</small><span class="meter" style="--w:23.1%;--fill:var(--mark-4)"></span></td><td>1.15<small class="block font-normal whitespace-nowrap">1.07-1.40</small><span class="meter" style="--w:21.1%;--fill:var(--mark-5)"></span></td><td class="td-best">0.77<small class="block font-normal whitespace-nowrap">0.71-0.95</small><span class="meter" style="--w:14.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint">3.47<small class="block font-normal whitespace-nowrap">2.37-3.99</small><span class="meter" style="--w:66.3%;--fill:var(--mark)"></span></td><td>4.00<small class="block font-normal whitespace-nowrap">2.43-4.81</small><span class="meter" style="--w:76.5%;--fill:var(--mark-1)"></span></td><td>5.23<small class="block font-normal whitespace-nowrap">4.39-5.44</small><span class="meter" style="--w:100%;--fill:var(--mark-2)"></span></td><td>4.04<small class="block font-normal whitespace-nowrap">2.87-4.94</small><span class="meter" style="--w:77.2%;--fill:var(--mark-3)"></span></td><td>0.99<small class="block font-normal whitespace-nowrap">0.95-1.09</small><span class="meter" style="--w:18.9%;--fill:var(--mark-4)"></span></td><td>1.00<small class="block font-normal whitespace-nowrap">0.92-1.17</small><span class="meter" style="--w:19.1%;--fill:var(--mark-5)"></span></td><td class="td-best">0.81<small class="block font-normal whitespace-nowrap">0.76-0.96</small><span class="meter" style="--w:15.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint">2.70<small class="block font-normal whitespace-nowrap">2.55-2.84</small><span class="meter" style="--w:42.8%;--fill:var(--mark)"></span></td><td>3.72<small class="block font-normal whitespace-nowrap">3.01-4.16</small><span class="meter" style="--w:59%;--fill:var(--mark-1)"></span></td><td>6.31<small class="block font-normal whitespace-nowrap">6.10-6.59</small><span class="meter" style="--w:100%;--fill:var(--mark-2)"></span></td><td>3.93<small class="block font-normal whitespace-nowrap">3.23-4.41</small><span class="meter" style="--w:62.3%;--fill:var(--mark-3)"></span></td><td>1.78<small class="block font-normal whitespace-nowrap">1.62-1.94</small><span class="meter" style="--w:28.2%;--fill:var(--mark-4)"></span></td><td class="td-best">1.63<small class="block font-normal whitespace-nowrap">1.46-1.79</small><span class="meter" style="--w:25.8%;--fill:var(--mark-5)"></span></td><td>1.69<small class="block font-normal whitespace-nowrap">1.36-2.25</small><span class="meter" style="--w:26.8%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint">8.60<small class="block font-normal whitespace-nowrap">6.52-9.58</small><span class="meter" style="--w:26.1%;--fill:var(--mark)"></span></td><td>20.80<small class="block font-normal whitespace-nowrap">10.80-26.80</small><span class="meter" style="--w:63%;--fill:var(--mark-1)"></span></td><td>33.00<small class="block font-normal whitespace-nowrap">30.70-33.90</small><span class="meter" style="--w:100%;--fill:var(--mark-2)"></span></td><td>13.10<small class="block font-normal whitespace-nowrap">12.40-15.40</small><span class="meter" style="--w:39.7%;--fill:var(--mark-3)"></span></td><td>1.61<small class="block font-normal whitespace-nowrap">1.20-2.03</small><span class="meter" style="--w:4.9%;--fill:var(--mark-4)"></span></td><td>1.62<small class="block font-normal whitespace-nowrap">1.13-2.01</small><span class="meter" style="--w:4.9%;--fill:var(--mark-5)"></span></td><td class="td-best">1.22<small class="block font-normal whitespace-nowrap">1.17-1.41</small><span class="meter" style="--w:3.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint">8.30<small class="block font-normal whitespace-nowrap">6.03-8.53</small><span class="meter" style="--w:25.4%;--fill:var(--mark)"></span></td><td>12.40<small class="block font-normal whitespace-nowrap">9.43-20.30</small><span class="meter" style="--w:37.9%;--fill:var(--mark-1)"></span></td><td>32.70<small class="block font-normal whitespace-nowrap">30.20-34.20</small><span class="meter" style="--w:100%;--fill:var(--mark-2)"></span></td><td>11.80<small class="block font-normal whitespace-nowrap">10.10-12.90</small><span class="meter" style="--w:36.1%;--fill:var(--mark-3)"></span></td><td>1.09<small class="block font-normal whitespace-nowrap">0.93-1.19</small><span class="meter" style="--w:3.3%;--fill:var(--mark-4)"></span></td><td class="td-best">1.07<small class="block font-normal whitespace-nowrap">0.92-1.19</small><span class="meter" style="--w:3.3%;--fill:var(--mark-5)"></span></td><td>1.24<small class="block font-normal whitespace-nowrap">1.07-1.82</small><span class="meter" style="--w:3.8%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint">6.54<small class="block font-normal whitespace-nowrap">4.79-7.29</small><span class="meter" style="--w:39.6%;--fill:var(--mark)"></span></td><td>11.80<small class="block font-normal whitespace-nowrap">9.54-12.80</small><span class="meter" style="--w:71.5%;--fill:var(--mark-1)"></span></td><td>16.50<small class="block font-normal whitespace-nowrap">15.50-17.00</small><span class="meter" style="--w:100%;--fill:var(--mark-2)"></span></td><td>12.10<small class="block font-normal whitespace-nowrap">8.80-14.00</small><span class="meter" style="--w:73.3%;--fill:var(--mark-3)"></span></td><td>2.48<small class="block font-normal whitespace-nowrap">1.92-2.93</small><span class="meter" style="--w:15%;--fill:var(--mark-4)"></span></td><td class="td-best">2.27<small class="block font-normal whitespace-nowrap">1.85-2.78</small><span class="meter" style="--w:13.8%;--fill:var(--mark-5)"></span></td><td>2.95<small class="block font-normal whitespace-nowrap">2.37-3.82</small><span class="meter" style="--w:17.9%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Latency at 3 Gbit/s offered<small>RTT p99 in ms, with the lowest and highest run's own p99 under it</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint">0.82<small class="block font-normal whitespace-nowrap">0.66-1.13</small><span class="meter" style="--w:85.2%;--fill:var(--mark)"></span></td><td>0.77<small class="block font-normal whitespace-nowrap">0.64-1.04</small><span class="meter" style="--w:79.5%;--fill:var(--mark-1)"></span></td><td>0.86<small class="block font-normal whitespace-nowrap">0.84-1.05</small><span class="meter" style="--w:89.5%;--fill:var(--mark-2)"></span></td><td>0.79<small class="block font-normal whitespace-nowrap">0.69-0.92</small><span class="meter" style="--w:82.1%;--fill:var(--mark-3)"></span></td><td>0.55<small class="block font-normal whitespace-nowrap">0.49-0.72</small><span class="meter" style="--w:57%;--fill:var(--mark-4)"></span></td><td class="td-best">0.44<small class="block font-normal whitespace-nowrap">0.42-0.49</small><span class="meter" style="--w:45.4%;--fill:var(--mark-5)"></span></td><td>0.96<small class="block font-normal whitespace-nowrap">0.88-1.08</small><span class="meter" style="--w:100%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint">0.81<small class="block font-normal whitespace-nowrap">0.65-0.94</small><span class="meter" style="--w:81.5%;--fill:var(--mark)"></span></td><td>0.82<small class="block font-normal whitespace-nowrap">0.60-1.03</small><span class="meter" style="--w:82.8%;--fill:var(--mark-1)"></span></td><td>0.84<small class="block font-normal whitespace-nowrap">0.73-0.98</small><span class="meter" style="--w:84.3%;--fill:var(--mark-2)"></span></td><td>0.84<small class="block font-normal whitespace-nowrap">0.72-1.09</small><span class="meter" style="--w:84%;--fill:var(--mark-3)"></span></td><td>0.66<small class="block font-normal whitespace-nowrap">0.50-1.10</small><span class="meter" style="--w:66.3%;--fill:var(--mark-4)"></span></td><td class="td-best">0.44<small class="block font-normal whitespace-nowrap">0.42-0.45</small><span class="meter" style="--w:44%;--fill:var(--mark-5)"></span></td><td>1.00<small class="block font-normal whitespace-nowrap">0.89-1.06</small><span class="meter" style="--w:100%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint td-best">0.86<small class="block font-normal whitespace-nowrap">0.78-1.09</small><span class="meter" style="--w:50.6%;--fill:var(--mark)"></span></td><td>1.11<small class="block font-normal whitespace-nowrap">1.04-1.19</small><span class="meter" style="--w:65.3%;--fill:var(--mark-1)"></span></td><td>1.15<small class="block font-normal whitespace-nowrap">1.02-1.46</small><span class="meter" style="--w:67.6%;--fill:var(--mark-2)"></span></td><td>1.14<small class="block font-normal whitespace-nowrap">1.08-1.24</small><span class="meter" style="--w:67.1%;--fill:var(--mark-3)"></span></td><td>1.60<small class="block font-normal whitespace-nowrap">1.42-1.83</small><span class="meter" style="--w:94.1%;--fill:var(--mark-4)"></span></td><td>0.91<small class="block font-normal whitespace-nowrap">0.69-1.24</small><span class="meter" style="--w:53.5%;--fill:var(--mark-5)"></span></td><td>1.70<small class="block font-normal whitespace-nowrap">1.36-2.10</small><span class="meter" style="--w:100%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint td-best">1.24<small class="block font-normal whitespace-nowrap">1.14-1.39</small><span class="meter" style="--w:59.9%;--fill:var(--mark)"></span></td><td>1.95<small class="block font-normal whitespace-nowrap">1.82-2.13</small><span class="meter" style="--w:94.2%;--fill:var(--mark-1)"></span></td><td>1.84<small class="block font-normal whitespace-nowrap">1.65-2.00</small><span class="meter" style="--w:88.9%;--fill:var(--mark-2)"></span></td><td>2.07<small class="block font-normal whitespace-nowrap">1.95-2.28</small><span class="meter" style="--w:100%;--fill:var(--mark-3)"></span></td><td>1.34<small class="block font-normal whitespace-nowrap">1.17-1.42</small><span class="meter" style="--w:64.7%;--fill:var(--mark-4)"></span></td><td>1.32<small class="block font-normal whitespace-nowrap">1.21-1.43</small><span class="meter" style="--w:63.8%;--fill:var(--mark-5)"></span></td><td>1.58<small class="block font-normal whitespace-nowrap">1.39-1.75</small><span class="meter" style="--w:76.3%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint">1.44<small class="block font-normal whitespace-nowrap">1.28-1.71</small><span class="meter" style="--w:71.6%;--fill:var(--mark)"></span></td><td>1.91<small class="block font-normal whitespace-nowrap">1.73-2.07</small><span class="meter" style="--w:95%;--fill:var(--mark-1)"></span></td><td>1.80<small class="block font-normal whitespace-nowrap">1.72-2.00</small><span class="meter" style="--w:89.6%;--fill:var(--mark-2)"></span></td><td>2.01<small class="block font-normal whitespace-nowrap">1.84-2.27</small><span class="meter" style="--w:100%;--fill:var(--mark-3)"></span></td><td>1.47<small class="block font-normal whitespace-nowrap">1.08-1.90</small><span class="meter" style="--w:73.1%;--fill:var(--mark-4)"></span></td><td class="td-best">1.32<small class="block font-normal whitespace-nowrap">1.04-1.47</small><span class="meter" style="--w:65.7%;--fill:var(--mark-5)"></span></td><td>1.35<small class="block font-normal whitespace-nowrap">1.15-1.51</small><span class="meter" style="--w:67.2%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint td-best">1.58<small class="block font-normal whitespace-nowrap">1.44-1.84</small><span class="meter" style="--w:64.5%;--fill:var(--mark)"></span></td><td>2.11<small class="block font-normal whitespace-nowrap">2.06-2.46</small><span class="meter" style="--w:86.1%;--fill:var(--mark-1)"></span></td><td>2.38<small class="block font-normal whitespace-nowrap">2.06-3.05</small><span class="meter" style="--w:97.1%;--fill:var(--mark-2)"></span></td><td>2.22<small class="block font-normal whitespace-nowrap">2.15-2.41</small><span class="meter" style="--w:90.6%;--fill:var(--mark-3)"></span></td><td>2.33<small class="block font-normal whitespace-nowrap">1.81-2.92</small><span class="meter" style="--w:95.1%;--fill:var(--mark-4)"></span></td><td>2.05<small class="block font-normal whitespace-nowrap">1.36-2.52</small><span class="meter" style="--w:83.7%;--fill:var(--mark-5)"></span></td><td>2.45<small class="block font-normal whitespace-nowrap">2.35-2.57</small><span class="meter" style="--w:100%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Latency at 100 kbit/s<small>RTT in ms, 1 stream</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">RTT p99</th>
<td class="bg-tint">1.04<small class="block font-normal whitespace-nowrap">1.02-1.06</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.92<small class="block font-normal whitespace-nowrap">0.88-0.94</small><span class="meter" style="--w:88.3%;--fill:var(--mark-1)"></span></td><td>0.99<small class="block font-normal whitespace-nowrap">0.96-1.00</small><span class="meter" style="--w:94.9%;--fill:var(--mark-2)"></span></td><td>0.93<small class="block font-normal whitespace-nowrap">0.92-0.94</small><span class="meter" style="--w:89.7%;--fill:var(--mark-3)"></span></td><td>0.92<small class="block font-normal whitespace-nowrap">0.85-1.42</small><span class="meter" style="--w:88.7%;--fill:var(--mark-4)"></span></td><td>0.93<small class="block font-normal whitespace-nowrap">0.86-1.33</small><span class="meter" style="--w:88.9%;--fill:var(--mark-5)"></span></td><td class="td-best">0.38<small class="block font-normal whitespace-nowrap">0.36-0.39</small><span class="meter" style="--w:36.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">RTT median</th>
<td class="bg-tint">0.83<span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.75<span class="meter" style="--w:89.6%;--fill:var(--mark-1)"></span></td><td>0.82<span class="meter" style="--w:98.3%;--fill:var(--mark-2)"></span></td><td>0.76<span class="meter" style="--w:91.1%;--fill:var(--mark-3)"></span></td><td>0.76<span class="meter" style="--w:91.5%;--fill:var(--mark-4)"></span></td><td>0.75<span class="meter" style="--w:89.9%;--fill:var(--mark-5)"></span></td><td class="td-best">0.33<span class="meter" style="--w:39.6%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Pings lost at 8 streams<small>Percent of the pings sent. At most 0.16% at 1 stream</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">Saturated<small class="block">out</small></th>
<td class="bg-tint">0.15<span class="meter" style="--w:11.9%;--fill:var(--mark)"></span></td><td>0.18<span class="meter" style="--w:13.9%;--fill:var(--mark-1)"></span></td><td>0.34<span class="meter" style="--w:25.9%;--fill:var(--mark-2)"></span></td><td class="td-best">0.10<span class="meter" style="--w:7.9%;--fill:var(--mark-3)"></span></td><td>1.29<span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>0.84<span class="meter" style="--w:65.1%;--fill:var(--mark-5)"></span></td><td>0.66<span class="meter" style="--w:51.2%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">Saturated<small class="block">in</small></th>
<td class="bg-tint">0.21<span class="meter" style="--w:17.9%;--fill:var(--mark)"></span></td><td class="td-best">0.08<span class="meter" style="--w:6.7%;--fill:var(--mark-1)"></span></td><td>0.36<span class="meter" style="--w:31.4%;--fill:var(--mark-2)"></span></td><td>0.13<span class="meter" style="--w:11.2%;--fill:var(--mark-3)"></span></td><td>1.06<span class="meter" style="--w:92.5%;--fill:var(--mark-4)"></span></td><td>1.15<span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>0.66<span class="meter" style="--w:57.2%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">Saturated<small class="block">both</small></th>
<td class="bg-tint">0.10<span class="meter" style="--w:5.4%;--fill:var(--mark)"></span></td><td class="td-best">0.10<span class="meter" style="--w:5.4%;--fill:var(--mark-1)"></span></td><td>0.32<span class="meter" style="--w:17.1%;--fill:var(--mark-2)"></span></td><td>0.18<span class="meter" style="--w:9.4%;--fill:var(--mark-3)"></span></td><td>1.90<span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.43<span class="meter" style="--w:75.4%;--fill:var(--mark-5)"></span></td><td>1.75<span class="meter" style="--w:91.8%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">3 Gbit/s<small class="block">out</small></th>
<td class="bg-tint td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark)"></span></td><td>0.03<span class="meter" style="--w:1.8%;--fill:var(--mark-1)"></span></td><td>0.03<span class="meter" style="--w:1.8%;--fill:var(--mark-2)"></span></td><td class="td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark-3)"></span></td><td>1.46<span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>0.87<span class="meter" style="--w:59.9%;--fill:var(--mark-5)"></span></td><td>1.29<span class="meter" style="--w:88.4%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">3 Gbit/s<small class="block">in</small></th>
<td class="bg-tint td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark)"></span></td><td class="td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark-1)"></span></td><td class="td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark-2)"></span></td><td class="td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark-3)"></span></td><td>1.67<span class="meter" style="--w:94.9%;--fill:var(--mark-4)"></span></td><td>1.06<span class="meter" style="--w:60.4%;--fill:var(--mark-5)"></span></td><td>1.76<span class="meter" style="--w:100%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">3 Gbit/s<small class="block">both</small></th>
<td class="bg-tint td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark)"></span></td><td>0.03<span class="meter" style="--w:1.5%;--fill:var(--mark-1)"></span></td><td class="td-best">0.00<span class="meter" style="--w:0%;--fill:var(--mark-2)"></span></td><td>0.03<span class="meter" style="--w:1.5%;--fill:var(--mark-3)"></span></td><td>1.64<span class="meter" style="--w:94.5%;--fill:var(--mark-4)"></span></td><td>1.73<span class="meter" style="--w:100%;--fill:var(--mark-5)"></span></td><td>1.46<span class="meter" style="--w:84.6%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>CPU cost<small>Busy cores per Gbit/s at 3 Gbit/s offered, both hosts</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">WireGuard</span><small><i class="swatch" style="--c:var(--mark-5)"></i>kernel</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint">1.051<small class="block font-normal whitespace-nowrap">1.029-1.064</small><span class="meter" style="--w:66.1%;--fill:var(--mark)"></span></td><td>1.180<small class="block font-normal whitespace-nowrap">1.155-1.207</small><span class="meter" style="--w:74.2%;--fill:var(--mark-1)"></span></td><td>1.175<small class="block font-normal whitespace-nowrap">1.152-1.217</small><span class="meter" style="--w:73.9%;--fill:var(--mark-2)"></span></td><td>1.202<small class="block font-normal whitespace-nowrap">1.183-1.214</small><span class="meter" style="--w:75.6%;--fill:var(--mark-3)"></span></td><td>1.590<small class="block font-normal whitespace-nowrap">1.557-1.615</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.478<small class="block font-normal whitespace-nowrap">1.463-1.553</small><span class="meter" style="--w:93%;--fill:var(--mark-5)"></span></td><td class="td-best">0.639<small class="block font-normal whitespace-nowrap">0.635-0.645</small><span class="meter" style="--w:40.2%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint">1.048<small class="block font-normal whitespace-nowrap">1.040-1.056</small><span class="meter" style="--w:65.1%;--fill:var(--mark)"></span></td><td>1.172<small class="block font-normal whitespace-nowrap">1.163-1.192</small><span class="meter" style="--w:72.9%;--fill:var(--mark-1)"></span></td><td>1.183<small class="block font-normal whitespace-nowrap">1.176-1.202</small><span class="meter" style="--w:73.6%;--fill:var(--mark-2)"></span></td><td>1.201<small class="block font-normal whitespace-nowrap">1.190-1.211</small><span class="meter" style="--w:74.6%;--fill:var(--mark-3)"></span></td><td>1.609<small class="block font-normal whitespace-nowrap">1.577-1.628</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.488<small class="block font-normal whitespace-nowrap">1.472-1.507</small><span class="meter" style="--w:92.5%;--fill:var(--mark-5)"></span></td><td class="td-best">0.642<small class="block font-normal whitespace-nowrap">0.637-0.643</small><span class="meter" style="--w:39.9%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint">0.960<small class="block font-normal whitespace-nowrap">0.947-0.980</small><span class="meter" style="--w:61.1%;--fill:var(--mark)"></span></td><td>1.083<small class="block font-normal whitespace-nowrap">1.054-1.103</small><span class="meter" style="--w:68.9%;--fill:var(--mark-1)"></span></td><td>1.025<small class="block font-normal whitespace-nowrap">1.004-1.042</small><span class="meter" style="--w:65.2%;--fill:var(--mark-2)"></span></td><td>1.104<small class="block font-normal whitespace-nowrap">1.070-1.143</small><span class="meter" style="--w:70.2%;--fill:var(--mark-3)"></span></td><td>1.571<small class="block font-normal whitespace-nowrap">1.557-1.587</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.468<small class="block font-normal whitespace-nowrap">1.461-1.489</small><span class="meter" style="--w:93.4%;--fill:var(--mark-5)"></span></td><td class="td-best">0.523<small class="block font-normal whitespace-nowrap">0.519-0.526</small><span class="meter" style="--w:33.3%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint">1.194<small class="block font-normal whitespace-nowrap">1.164-1.212</small><span class="meter" style="--w:64.3%;--fill:var(--mark)"></span></td><td>1.361<small class="block font-normal whitespace-nowrap">1.348-1.378</small><span class="meter" style="--w:73.3%;--fill:var(--mark-1)"></span></td><td>1.239<small class="block font-normal whitespace-nowrap">1.220-1.250</small><span class="meter" style="--w:66.8%;--fill:var(--mark-2)"></span></td><td>1.383<small class="block font-normal whitespace-nowrap">1.359-1.406</small><span class="meter" style="--w:74.5%;--fill:var(--mark-3)"></span></td><td>1.856<small class="block font-normal whitespace-nowrap">1.824-1.915</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.726<small class="block font-normal whitespace-nowrap">1.696-1.846</small><span class="meter" style="--w:93%;--fill:var(--mark-5)"></span></td><td class="td-best">0.817<small class="block font-normal whitespace-nowrap">0.809-0.825</small><span class="meter" style="--w:44%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint">1.229<small class="block font-normal whitespace-nowrap">1.214-1.243</small><span class="meter" style="--w:66.5%;--fill:var(--mark)"></span></td><td>1.371<small class="block font-normal whitespace-nowrap">1.361-1.381</small><span class="meter" style="--w:74.2%;--fill:var(--mark-1)"></span></td><td>1.238<small class="block font-normal whitespace-nowrap">1.224-1.256</small><span class="meter" style="--w:67%;--fill:var(--mark-2)"></span></td><td>1.384<small class="block font-normal whitespace-nowrap">1.375-1.407</small><span class="meter" style="--w:74.9%;--fill:var(--mark-3)"></span></td><td>1.848<small class="block font-normal whitespace-nowrap">1.831-1.895</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.744<small class="block font-normal whitespace-nowrap">1.733-1.777</small><span class="meter" style="--w:94.3%;--fill:var(--mark-5)"></span></td><td class="td-best">0.813<small class="block font-normal whitespace-nowrap">0.806-0.821</small><span class="meter" style="--w:44%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint">1.096<small class="block font-normal whitespace-nowrap">1.093-1.106</small><span class="meter" style="--w:67.3%;--fill:var(--mark)"></span></td><td>1.199<small class="block font-normal whitespace-nowrap">1.185-1.204</small><span class="meter" style="--w:73.6%;--fill:var(--mark-1)"></span></td><td>1.074<small class="block font-normal whitespace-nowrap">1.069-1.091</small><span class="meter" style="--w:65.9%;--fill:var(--mark-2)"></span></td><td>1.210<small class="block font-normal whitespace-nowrap">1.201-1.222</small><span class="meter" style="--w:74.3%;--fill:var(--mark-3)"></span></td><td>1.629<small class="block font-normal whitespace-nowrap">1.607-1.672</small><span class="meter" style="--w:100%;--fill:var(--mark-4)"></span></td><td>1.520<small class="block font-normal whitespace-nowrap">1.473-1.539</small><span class="meter" style="--w:93.3%;--fill:var(--mark-5)"></span></td><td class="td-best">0.633<small class="block font-normal whitespace-nowrap">0.627-0.635</small><span class="meter" style="--w:38.8%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Memory<small>Peak RSS of each process in MiB, at 8 streams saturated</small></span></summary>
<div class="sm:pl-1">
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">wireguard-go</span><small><i class="swatch" style="--c:var(--mark-1)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">Tailscale</span><small><i class="swatch" style="--c:var(--mark-2)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-3)"></i>user</small></th>
<th scope="col"><span class="whitespace-nowrap">NetBird</span><small><i class="swatch" style="--c:var(--mark-4)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr><th scope="row">Sender, out</th><td>168<small class="block">162-172</small></td><td>94<small class="block">68-162</small></td><td>57<small class="block">55-59</small></td><td>166<small class="block">112-237</small></td><td>60<small class="block">59-61</small></td></tr>
<tr><th scope="row">Receiver, out</th><td>155<small class="block">154-156</small></td><td>777<small class="block">607-1350</small></td><td>77<small class="block">71-84</small></td><td>673<small class="block">602-772</small></td><td>60<small class="block">59-60</small></td></tr>
</tbody>
<tbody>
<tr><th scope="row">Sender, in</th><td>176<small class="block">170-181</small></td><td>788<small class="block">612-1410</small></td><td>78<small class="block">68-84</small></td><td>680<small class="block">634-809</small></td><td>60<small class="block">59-61</small></td></tr>
<tr><th scope="row">Receiver, in</th><td>172<small class="block">170-176</small></td><td>617<small class="block">445-956</small></td><td>78<small class="block">64-86</small></td><td>690<small class="block">561-1038</small></td><td>60<small class="block">60-61</small></td></tr>
</tbody>
<tbody>
<tr><th scope="row">Host A, both</th><td>177<small class="block">174-179</small></td><td>749<small class="block">696-1310</small></td><td>91<small class="block">85-97</small></td><td>767<small class="block">645-1061</small></td><td>60<small class="block">60-61</small></td></tr>
<tr><th scope="row">Host B, both</th><td>180<small class="block">177-184</small></td><td>959<small class="block">739-1602</small></td><td>89<small class="block">82-96</small></td><td>825<small class="block">767-1038</small></td><td>60<small class="block">60-61</small></td></tr>
</tbody>
</table>
</div>
</div>
</details>
<details class="fold">
<summary class="row grid-cols-[minmax(0,1fr)_auto]"><span>Ciphers<small>AES-256-GCM and ChaCha20-Poly1305, on ranet3 and kernel IPsec</small></span></summary>
<div class="sm:pl-1">
<p class="mt-[.6em] text-fg2">The throughput of ranet3 on ChaCha20-Poly1305 stays within 1.3% of its throughput on AES-256-GCM, and its CPU cost rises <span class="whitespace-nowrap">6-11%</span>. Kernel IPsec loses <span class="whitespace-nowrap">32-37%</span> of its throughput to the same change. ChaCha20-Poly1305 is the cipher WireGuard uses, and on it ranet3 costs <span class="whitespace-nowrap">0.95-1.01x</span> the CPU of wireguard-go and <span class="whitespace-nowrap">0.94-1.13x</span> that of Tailscale.</p>
<div class="overflow-x-auto mt-[1em]" tabindex="0">
<table class="data-table max-sm:whitespace-normal">
<thead>
<tr>
<td></td>
<th scope="col">1 stream<small>out, Gbit/s</small></th>
<th scope="col">1 stream<small>both, Gbit/s</small></th>
<th scope="col">8 streams<small>both, Gbit/s</small></th>
<th scope="col">CPU per Gbit/s<small>across 6 tests</small></th>
<th scope="col">RTT p99<small>ms, 1 stream out</small></th>
</tr>
</thead>
<tbody>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span><small class="block whitespace-nowrap">AES-256-GCM</small></th><td>8.78</td><td>16.09</td><td>16.65</td><td class="whitespace-nowrap">0.96-1.23</td><td>3.58</td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark)"></i>ranet3</span><small class="block whitespace-nowrap">ChaCha20-Poly1305</small></th><td>8.77</td><td>16.11</td><td>16.43</td><td class="whitespace-nowrap">1.03-1.37</td><td>3.40</td></tr>
</tbody>
<tbody>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span><small class="block whitespace-nowrap">AES-256-GCM</small></th><td>4.65</td><td>4.75</td><td>4.12</td><td class="whitespace-nowrap">0.52-0.82</td><td>0.77</td></tr>
<tr><th scope="row"><span class="whitespace-nowrap"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</span><small class="block whitespace-nowrap">ChaCha20-Poly1305</small></th><td>3.17</td><td>3.17</td><td>2.65</td><td class="whitespace-nowrap">0.72-0.94</td><td>1.19</td></tr>
</tbody>
</table>
</div>
<p class="note mt-[1.5em] mb-[1em]">The tables below give every test on ChaCha20-Poly1305.</p>
<div class="grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-8 lg:grid-cols-2">
<div><p class="subhead mb-[.5em]">Throughput, Gbit/s</p>
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3 ChaCha20<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec ChaCha20</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint td-best">8.77<small class="block font-normal whitespace-nowrap">8.60-8.80</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>3.17<small class="block font-normal whitespace-nowrap">3.13-3.24</small><span class="meter" style="--w:36.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint td-best">8.80<small class="block font-normal whitespace-nowrap">8.61-8.81</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>3.11<small class="block font-normal whitespace-nowrap">3.08-3.12</small><span class="meter" style="--w:35.3%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint td-best">16.11<small class="block font-normal whitespace-nowrap">15.75-16.54</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>3.17<small class="block font-normal whitespace-nowrap">3.11-3.21</small><span class="meter" style="--w:19.7%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint td-best">8.77<small class="block font-normal whitespace-nowrap">8.76-8.79</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>2.57<small class="block font-normal whitespace-nowrap">2.54-2.58</small><span class="meter" style="--w:29.3%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint td-best">8.81<small class="block font-normal whitespace-nowrap">8.79-8.83</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>2.54<small class="block font-normal whitespace-nowrap">2.51-2.57</small><span class="meter" style="--w:28.8%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint td-best">16.43<small class="block font-normal whitespace-nowrap">16.28-16.59</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>2.65<small class="block font-normal whitespace-nowrap">2.61-2.66</small><span class="meter" style="--w:16.1%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
<div><p class="subhead mb-[.5em]">CPU per Gbit/s at 3 Gbit/s</p>
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3 ChaCha20<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec ChaCha20</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint">1.116<small class="block font-normal whitespace-nowrap">1.109-1.126</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.717<small class="block font-normal whitespace-nowrap">0.711-0.724</small><span class="meter" style="--w:64.3%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint">1.112<small class="block font-normal whitespace-nowrap">1.102-1.122</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.729<small class="block font-normal whitespace-nowrap">0.727-0.734</small><span class="meter" style="--w:65.6%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint">1.026<small class="block font-normal whitespace-nowrap">1.016-1.042</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.746<small class="block font-normal whitespace-nowrap">0.741-0.751</small><span class="meter" style="--w:72.7%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint">1.311<small class="block font-normal whitespace-nowrap">1.301-1.331</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.911<small class="block font-normal whitespace-nowrap">0.898-0.921</small><span class="meter" style="--w:69.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint">1.365<small class="block font-normal whitespace-nowrap">1.355-1.372</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.912<small class="block font-normal whitespace-nowrap">0.899-0.927</small><span class="meter" style="--w:66.8%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint">1.214<small class="block font-normal whitespace-nowrap">1.205-1.227</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">0.935<small class="block font-normal whitespace-nowrap">0.926-0.941</small><span class="meter" style="--w:77.1%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
<div><p class="subhead mb-[.5em]">RTT p99 under saturation, ms</p>
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3 ChaCha20<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec ChaCha20</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1 stream<small class="block">out</small></th>
<td class="bg-tint">3.40<small class="block font-normal whitespace-nowrap">3.01-3.81</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">1.19<small class="block font-normal whitespace-nowrap">1.04-1.33</small><span class="meter" style="--w:35%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">in</small></th>
<td class="bg-tint">3.54<small class="block font-normal whitespace-nowrap">3.03-3.97</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">1.23<small class="block font-normal whitespace-nowrap">1.15-1.36</small><span class="meter" style="--w:34.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1 stream<small class="block">both</small></th>
<td class="bg-tint">2.80<small class="block font-normal whitespace-nowrap">2.62-2.95</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">2.50<small class="block font-normal whitespace-nowrap">2.09-3.35</small><span class="meter" style="--w:89.3%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">8 streams<small class="block">out</small></th>
<td class="bg-tint">8.37<small class="block font-normal whitespace-nowrap">6.06-9.12</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">1.85<small class="block font-normal whitespace-nowrap">1.76-1.98</small><span class="meter" style="--w:22.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">in</small></th>
<td class="bg-tint">8.36<small class="block font-normal whitespace-nowrap">6.25-8.57</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">1.65<small class="block font-normal whitespace-nowrap">1.57-2.36</small><span class="meter" style="--w:19.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">8 streams<small class="block">both</small></th>
<td class="bg-tint">6.18<small class="block font-normal whitespace-nowrap">4.35-7.60</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td class="td-best">4.30<small class="block font-normal whitespace-nowrap">3.77-5.41</small><span class="meter" style="--w:69.6%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
<div><p class="subhead mb-[.5em]">Packet rate, Mpps</p>
<div class="overflow-x-auto" tabindex="0">
<table class="data-table data-table-wide max-sm:whitespace-normal [&_:is(td,th)]:px-[.6ch] [&_tbody_th]:pl-0">
<thead>
<tr>
<td></td>
<th scope="col" class="bg-acc font-bold text-bg">ranet3 ChaCha20<small class="text-bg">user</small></th>
<th scope="col"><span class="whitespace-nowrap">IPsec ChaCha20</span><small><i class="swatch" style="--c:var(--mark-6)"></i>kernel</small></th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">64<small class="block">bytes, out</small></th>
<td class="bg-tint td-best">0.318<small class="block font-normal whitespace-nowrap">0.310-0.320</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.265<small class="block font-normal whitespace-nowrap">0.263-0.271</small><span class="meter" style="--w:83.2%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, in</small></th>
<td class="bg-tint td-best">0.321<small class="block font-normal whitespace-nowrap">0.314-0.326</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.281<small class="block font-normal whitespace-nowrap">0.279-0.284</small><span class="meter" style="--w:87.7%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">64<small class="block">bytes, both</small></th>
<td class="bg-tint td-best">0.615<small class="block font-normal whitespace-nowrap">0.608-0.627</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.468<small class="block font-normal whitespace-nowrap">0.463-0.473</small><span class="meter" style="--w:76.1%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
<tbody>
<tr>
<th scope="row">1400<small class="block">bytes, out</small></th>
<td class="bg-tint td-best">0.291<small class="block font-normal whitespace-nowrap">0.282-0.297</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.203<small class="block font-normal whitespace-nowrap">0.201-0.205</small><span class="meter" style="--w:69.5%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, in</small></th>
<td class="bg-tint td-best">0.288<small class="block font-normal whitespace-nowrap">0.284-0.294</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.214<small class="block font-normal whitespace-nowrap">0.211-0.215</small><span class="meter" style="--w:74.1%;--fill:var(--mark-6)"></span></td>
</tr>
<tr>
<th scope="row">1400<small class="block">bytes, both</small></th>
<td class="bg-tint td-best">0.528<small class="block font-normal whitespace-nowrap">0.515-0.534</small><span class="meter" style="--w:100%;--fill:var(--mark)"></span></td><td>0.332<small class="block font-normal whitespace-nowrap">0.324-0.335</small><span class="meter" style="--w:62.8%;--fill:var(--mark-6)"></span></td>
</tr>
</tbody>
</table>
</div>
</div>
</div>
</div>
</details>
</div>
</section>

<section class="section">
<h2 id="setup" class="text-[1.5em] font-bold text-fg">Setup</h2>
<h3 class="subhead mt-[1em]">Dataplanes</h3>
<div class="overflow-x-auto mt-[.8em]" tabindex="0">
<table class="data-table data-table-left max-sm:whitespace-normal">
<thead>
<tr>
<th scope="col">Dataplane</th>
<th scope="col">Runs in</th>
<th scope="col">Protocol and cipher</th>
</tr>
</thead>
<tbody>
<tr class="tr-accent"><th scope="row"><i class="swatch" style="--c:var(--mark)"></i>ranet3</th><td>Userspace</td><td>ESP in UDP, <span class="whitespace-nowrap">AES-256-GCM</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark)"></i>ranet3</th><td>Userspace</td><td>ESP in UDP, <span class="whitespace-nowrap">ChaCha20-Poly1305</span>, in All figures</td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-1)"></i><span class="whitespace-nowrap">wireguard-go</span></th><td>Userspace</td><td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-2)"></i>Tailscale</th><td>Userspace</td><td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-3)"></i>NetBird</th><td>Userspace</td><td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-4)"></i>NetBird</th><td>Kernel</td><td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-5)"></i>WireGuard</th><td>Kernel</td><td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</th><td>Kernel (xfrm)</td><td>ESP in UDP, <span class="whitespace-nowrap">AES-256-GCM</span></td></tr>
<tr><th scope="row"><i class="swatch" style="--c:var(--mark-6)"></i>IPsec</th><td>Kernel (xfrm)</td><td>ESP in UDP, <span class="whitespace-nowrap">ChaCha20-Poly1305</span>, in All figures</td></tr>
</tbody>
</table>
</div>
<h3 class="subhead mt-[3em]">Hardware</h3>
<dl class="terms">
<dt>Hosts</dt>
<dd>2 x Dell PowerEdge C6420</dd>
<dt>Processors</dt>
<dd>2 x Intel Xeon Gold 6130 in each host, 16 cores and 32 threads each</dd>
<dt>Memory</dt>
<dd>192 GiB</dd>
<dt>NIC</dt>
<dd>Intel X710</dd>
<dt>Connector</dt>
<dd>SFP+</dd>
<dt>Bandwidth</dt>
<dd>10 Gbit/s each way</dd>
<dt>Switch</dt>
<dd>Both hosts on the same Dell S5296F-ON</dd>
</dl>
<h3 class="subhead mt-[3em]">Software</h3>
<dl class="terms wrap-anywhere">
<dt>ranet3</dt>
<dd><a href="https://github.com/ranet3/ranet3/commit/81675924fd2ad5c3812789fe2b675cd0bf4ffa21" class="link">2026.912.0+8167592</a></dd>
<dt>OS</dt>
<dd>NixOS 26.11.20261025.acc2ec7</dd>
<dt>Kernel</dt>
<dd><a href="https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.3" class="link">Linux 7.3.0</a></dd>
<dt>wireguard-go</dt>
<dd><a href="https://git.zx2c4.com/wireguard-go/tag/?h=0.0.20250522" class="link">0.0.20250522</a></dd>
<dt>wireguard-tools</dt>
<dd><a href="https://git.zx2c4.com/wireguard-tools/tag/?h=v1.0.20260223" class="link">1.0.20260223</a></dd>
<dt>Tailscale</dt>
<dd><a href="https://github.com/tailscale/tailscale/releases/tag/v1.104.2" class="link">1.104.2</a></dd>
<dt>headscale</dt>
<dd><a href="https://github.com/juanfont/headscale/releases/tag/v0.29.5" class="link">0.29.5</a></dd>
<dt>NetBird</dt>
<dd><a href="https://github.com/netbirdio/netbird/releases/tag/v0.81.2" class="link">0.81.2</a></dd>
<dt>iproute2</dt>
<dd><a href="https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tag/?h=v7.1.0" class="link">7.1.0</a></dd>
<dt>iperf3</dt>
<dd><a href="https://github.com/esnet/iperf/releases/tag/3.21" class="link">3.21</a></dd>
</dl>
<h3 class="subhead mt-[3em]">Method</h3>
<dl class="terms">
<dt>Traffic</dt>
<dd>TCP with cubic over IPv6 at inner MTU 1400, and UDP for packet rate and the lightest load</dd>
<dt>Streams</dt>
<dd>1, 2, 4, 8 and 16 for throughput, 1 and 8 for CPU cost and latency, 8 for packet rate</dd>
<dt>Load</dt>
<dd>Saturated for throughput and latency, 3 Gbit/s each way for CPU cost and latency, and 100 kbit/s of UDP for latency at the lightest load</dd>
<dt>Direction</dt>
<dd>One way in each direction and both ways at once</dd>
<dt>Runs</dt>
<dd>10 runs of 10 seconds with the dataplanes interleaved, about 3800 pings a test</dd>
<dt>Paths</dt>
<dd>Direct between the hosts for every dataplane, with no relay, checked on every run. A run that sent traffic through a relay was discarded and repeated</dd>
<dt>Control</dt>
<dd>headscale for Tailscale and NetBird's own servers on one host, at most 0.002 cores during a run</dd>
<dt>Outer IP</dt>
<dd>IPv4 for every dataplane</dd>
<dt>CPU cost</dt>
<dd>Busy cores from /proc/stat summed over both hosts with every dataplane unpinned</dd>
<dt>Line limit</dt>
<dd>8.84 Gbit/s of TCP payload one way after ESP in UDP framing and 18.77 Gbit/s both ways without a tunnel</dd>
</dl>
</section>
