---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "ranet3"
description: "High performance policy routed IPsec mesh SD-WAN with userspace ESP, IKEv2, an embedded Babel speaker and SRv6 steering."
created: 2026-10-06
updated: 2026-10-21
vetted: 2026-10-21
layout: bare
---

<div class="flex min-h-[calc(100svh-7rem)] flex-col items-center justify-center px-4 py-[72px] text-center text-[15px] leading-[1.55] text-fg md:px-14">
<div class="text-[clamp(7px,3.4vw,15px)]">
<pre class="m-0 cursor-default text-left leading-none text-fg select-none" role="img" aria-label="The ranet3 logo, a core node inside 2 broken orbits, each carrying a peer">
              <span class="text-mute">..::----::..</span>
          <span class="text-mute">.:-++++++++++++++-:.</span>
        <span class="text-mute">:=+++-:..      ..:-+++=:</span>
      <span class="text-mute">:=++-.                .-+-.</span>
    <span class="text-mute">.=++-.</span>       ::::::       <span class="text-mute">.</span>   .::.
   <span class="text-mute">:++=.</span>     :+#@@@@@@@@#+:      *@@@@=
  <span class="text-mute">:++=</span>     -#@@%*+-::-+*%@@#-   :@@@@@@
 <span class="text-mute">.++=</span>    .*@@#-          -#@@*. .#@@@@*
 <span class="text-mute">-++.</span>   .#@@=              =@@#.  -++:
<span class="text-mute">.++-</span>    *@@-      <span class="text-acc">:++:</span>      -@@*
<span class="text-mute">:++.</span>   .@@#     <span class="text-acc">-%@@@@%-</span>     #@@.   <span class="text-mute">.--:</span>
<span class="text-mute">-++</span>    .++:     <span class="text-acc">%@@@@@@%</span>     +@@:    <span class="text-mute">++-</span>
<span class="text-mute">-++</span>             <span class="text-acc">%@@@@@@%</span>     +@@:    <span class="text-mute">++-</span>
<span class="text-mute">:++.</span>    .=+-.   <span class="text-acc">-%@@@@%-</span>     #@@.   <span class="text-mute">.++:</span>
<span class="text-mute">.++-</span>   :%@@@%:    <span class="text-acc">:++:</span>      -@@*    <span class="text-mute">-++.</span>
 <span class="text-mute">-++.</span>  =@@@@@=             =@@#.   <span class="text-mute">.++-</span>
 <span class="text-mute">.++=</span>   +%@%+            -#@@*.    <span class="text-mute">=++.</span>
  <span class="text-mute">:++=</span>         =*+-::-+*%@@#-     <span class="text-mute">=++:</span>
   <span class="text-mute">:++=.</span>      .#@@@@@@@@#+:     <span class="text-mute">.=++:</span>
    <span class="text-mute">.=++-.</span>       ::::::       <span class="text-mute">.-++=.</span>
      <span class="text-mute">:=++-.                .-++=:</span>
        <span class="text-mute">:=+++-:..      ..:-+++=:</span>
          <span class="text-mute">.:-++++++++++++++-:.</span>
              <span class="text-mute">..::----::..</span>
</pre>
</div>
<h1 class="mt-14 max-w-[28ch] text-[clamp(32px,6vw,52px)] leading-[1.1] font-bold tracking-[-.01em] text-balance">Mesh network, reimagined.</h1>
<div class="mt-9 flex flex-wrap justify-center gap-3">
<a href="mailto:mesh@ranet3.com?subject=ranet3%20demo" class="btn-primary">Request a Demo</a>
<a href="/docs/getting-started/" class="btn-secondary after:content-['\00a0\2192']">Get started</a>
</div>
</div>

<div class="grid border-y border-bg2 text-[15px] leading-[1.55] md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.4fr)]">
<div class="px-6 py-10 md:border-r md:border-bg2 md:px-12"><div class="text-[clamp(44px,4.6vw,64px)] leading-none font-bold whitespace-nowrap text-acc">95%</div><p class="mt-3.5 text-fg2">of the 10 GbE payload limit, 1 stream one way</p><p class="label mt-1">8.39 of 8.84 Gbit/s</p></div>
<div class="border-t border-bg2 px-6 py-10 md:border-t-0 md:border-r md:px-12"><div class="text-[clamp(44px,4.6vw,64px)] leading-none font-bold whitespace-nowrap text-acc">1.6-2.1x</div><p class="mt-3.5 text-fg2">kernel WireGuard throughput</p><p class="label mt-1">All 6 tests</p></div>
<div class="flex flex-col justify-center gap-3.5 border-t border-bg2 px-6 py-10 text-fg2 md:border-t-0 md:px-12">
<div class="flex gap-[2ch]"><span class="text-acc">+</span><span>1.2-1.5x wireguard-go throughput, all 6 tests</span></div>
<div class="flex gap-[2ch]"><span class="text-acc">+</span><span>1.91-4.96 ms RTT p99 under saturation, kernel dataplanes 0.85-2.51 ms</span></div>
<div class="flex gap-[2ch]"><span class="text-acc">+</span><span>Medians of 3 runs under saturation</span></div>
<a href="/benchmarks/" class="link mt-1.5">Benchmarks</a>
</div>
</div>

<div class="mx-auto mt-24 flex w-full max-w-[760px] flex-col border-t border-bg2 px-4 text-[15px] leading-[1.55] md:px-0">
<a href="/why/#standard-protocols" class="index-row"><span class="text-mute">01</span><span>Standard protocols</span></a>
<a href="/why/#latency-routing" class="index-row"><span class="text-mute">02</span><span>Latency routing</span></a>
<a href="/why/#segment-routing" class="index-row"><span class="text-mute">03</span><span>Segment routing</span></a>
<a href="/benchmarks/" class="index-row"><span class="text-mute">04</span><span>Benchmarks, measured on 2026-10-15</span></a>
<a href="/benchmarks/#setup" class="index-row"><span class="text-mute">05</span><span>Setup: hardware, software and method</span></a>
</div>
