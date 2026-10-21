---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "ranet3"
description: "High performance policy routed IPsec mesh SD-WAN with userspace ESP, IKEv2, an embedded Babel speaker and SRv6 steering."
created: 2026-10-06
updated: 2026-10-21
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
<h1 class="mt-14 text-[clamp(36px,7vw,52px)] leading-[1.1] font-bold tracking-[-.01em]">ranet3</h1>
<p class="mt-6 max-w-[58ch] text-[18px] text-balance text-acc">High performance <span class="whitespace-nowrap">policy routed</span> IPsec mesh <span class="whitespace-nowrap">SD-WAN</span></p>
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
<a href="#benchmarks" class="link mt-1.5">Benchmarks</a>
</div>
</div>

<div class="mx-auto mt-24 flex w-full max-w-[760px] flex-col border-t border-bg2 px-4 text-[15px] leading-[1.55] md:px-0">
<a href="#standard-protocols" class="index-row"><span class="text-mute">01</span><span>Standard protocols</span></a>
<a href="#latency-routing" class="index-row"><span class="text-mute">02</span><span>Latency routing</span></a>
<a href="#segment-routing" class="index-row"><span class="text-mute">03</span><span>Segment routing</span></a>
<a href="#benchmarks" class="index-row"><span class="text-mute">04</span><span>Benchmarks, measured on 2026-10-15</span></a>
<a href="#setup" class="index-row"><span class="text-mute">05</span><span>Setup: hardware, software and method</span></a>
</div>

<div class="mx-4 mt-24 grid gap-10 bg-bg2 p-8 text-[15px] leading-[1.55] sm:grid-cols-2 md:mx-14 md:p-12 lg:grid-cols-4">
<div class="flex flex-col gap-2"><span class="label">Transport</span><span class="text-fg">Userspace ESP <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc4303/">RFC 4303</a>)</span> in tunnel mode over UDP <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc3948/">RFC 3948</a>)</span></span></div>
<div class="flex flex-col gap-2"><span class="label">Handshake</span><span class="text-fg">IKEv2 <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc7296/">RFC 7296</a>)</span> with hybrid ML-KEM <span class="text-mute">(<a class="link whitespace-nowrap" href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a>)</span> key exchange <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc9370/">RFC 9370</a>)</span></span></div>
<div class="flex flex-col gap-2"><span class="label">Routing</span><span class="text-fg">Embedded Babel speaker <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc8966/">RFC 8966</a>)</span> with RTT metrics <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc9616/">RFC 9616</a>)</span> and source specific routes <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc9079/">RFC 9079</a>)</span></span></div>
<div class="flex flex-col gap-2"><span class="label">Steering</span><span class="text-fg">SRv6 <span class="text-mute">(<a class="link whitespace-nowrap" href="https://www.rfc-editor.org/info/rfc8986/">RFC 8986</a>)</span> by source/destination prefix</span></div>
<div class="flex flex-col gap-2"><span class="label">Source</span><span class="text-fg"><a class="link" href="https://github.com/ranet3/ranet3">github:ranet3/ranet3</a></span></div>
<div class="flex flex-col gap-2"><span class="label">License</span><span class="text-fg"><a class="link" href="https://github.com/ranet3/ranet3/blob/master/licenses/FSL-1.1-ALv2.txt">FSL-1.1-ALv2</a> / <a class="link" href="https://www.apache.org/licenses/LICENSE-2.0">Apache-2.0</a></span></div>
<div class="flex flex-col gap-2"><span class="label">Email</span><span class="text-fg"><a class="link" href="mailto:mesh@ranet3.com">mesh@ranet3.com</a></span></div>
<div class="flex flex-col gap-2"><span class="label">Powering</span><span class="text-fg"><a class="link" href="https://bgp.tools/as/10779">AS10779</a> / <a class="link" href="https://bgp.tools/as/18932">AS18932</a></span></div>
</div>

<section class="page-section" id="why" aria-labelledby="why-h">
        <h2 id="why-h" class="text-[1.5em] font-bold text-fg">Why ranet3</h2>
        <h3 class="subhead mt-[1em]" id="standard-protocols">Standard protocols</h3>
        <p class="mt-[.6em] text-fg2">Peers only need standard IKEv2, ESP, Babel and SRv6.</p>
        <p class="note">Interoperability is checked against:</p>
        <dl class="spec-list">
          <dt>strongSwan</dt>
          <dd>IKEv2 and ESP sessions with Ed25519 keys</dd>
          <dt>BIRD</dt>
          <dd>Babel routes with RTT metrics, matched route for route</dd>
          <dt>Linux</dt>
          <dd>Kernel seg6local acts on the SRv6 headers ranet3 writes</dd>
        </dl>
        <p class="note">Any other router or switch that supports IKEv2 with Ed25519 keys, Babel and SRv6 should interoperate as well.</p>
        <p class="callout">Common mesh VPN and SD-WAN tools (Tailscale, NetBird, ZeroTier, Nebula, etc.) admit only nodes that run their own agent, and ranet3 runs beside them on the same host.</p>
        <h3 class="subhead mt-[3em]" id="latency-routing">Latency routing</h3>
        <p class="mt-[.6em] text-fg2">Babel measures the round trip of every link and routes through a relay whenever the direct link is slower.</p>
        <figure class="mt-[1.4em]">
          <svg width="100%" height="176" role="img" aria-label="Nodes A and C linked directly at 265 ms and through relay B at 40 ms per hop, with traffic taking the relay" class="block overflow-visible">
            <line class="stroke-2 stroke-bar [stroke-dasharray:5_5]" x1="10%" y1="132" x2="90%" y2="132" />
            <line class="stroke-2 stroke-acc" x1="10%" y1="132" x2="50%" y2="34" />
            <line class="stroke-2 stroke-acc" x1="50%" y1="34" x2="90%" y2="132" />
            <circle cx="10%" cy="132" r="6" class="fill-bg stroke-2 stroke-acc" />
            <circle cx="50%" cy="34" r="6" class="fill-bg stroke-2 stroke-acc" />
            <circle cx="90%" cy="132" r="6" class="fill-bg stroke-2 stroke-acc" />
            <text x="10%" y="160" text-anchor="middle" class="fill-fg2">A</text>
            <text x="50%" y="16" text-anchor="middle" class="fill-fg2">B</text>
            <text x="90%" y="160" text-anchor="middle" class="fill-fg2">C</text>
            <text class="fill-acc" x="27%" y="80" text-anchor="end">40 ms</text>
            <text class="fill-acc" x="73%" y="80">40 ms</text>
            <text class="fill-mute text-[.85em]" x="50%" y="156" text-anchor="middle">265 ms</text>
          </svg>
          <figcaption class="mt-[1em] flex flex-wrap gap-x-[3ch] text-fg2"><span><span class="mr-[1ch] inline-block w-[3ch] border-t-2 align-middle border-acc"></span>Chosen path through B, 80 ms</span><span><span class="mr-[1ch] inline-block w-[3ch] border-t-2 align-middle border-dashed border-bar"></span>Direct link, 265 ms</span></figcaption>
        </figure>
        <p class="note">RTT is measured continuously, and packet loss and outages count against a link. Traffic always takes the fastest path, moving back to the direct link once it is faster again.</p>
        <h3 class="subhead mt-[3em]" id="segment-routing">Segment routing</h3>
        <p class="mt-[.6em] text-fg2">A policy on source and destination prefix sends traffic through chosen waypoints and out at a chosen exit. Segment routing is implemented in userspace and works even on macOS, whose XNU kernel has no support for it.</p>
        <figure class="mt-[1.4em]">
          <svg width="100%" height="146" role="img" aria-label="Steered traffic leaves the laptop through a waypoint and an exit, while unsteered traffic takes the default route" class="block overflow-visible">
            <line class="stroke-2 stroke-bar [stroke-dasharray:5_5]" x1="8%" y1="104" x2="92%" y2="104" />
            <line class="stroke-2 stroke-acc" x1="8%" y1="104" x2="38%" y2="46" />
            <line class="stroke-2 stroke-acc" x1="38%" y1="46" x2="68%" y2="46" />
            <line class="stroke-2 stroke-acc" x1="68%" y1="46" x2="92%" y2="104" />
            <circle cx="8%" cy="104" r="6" class="fill-bg stroke-2 stroke-acc" />
            <circle cx="38%" cy="46" r="6" class="fill-bg stroke-2 stroke-acc" />
            <circle cx="68%" cy="46" r="6" class="fill-bg stroke-2 stroke-acc" />
            <circle class="fill-bg stroke-2 stroke-bar" cx="92%" cy="104" r="6" />
            <text x="38%" y="14" text-anchor="middle" class="fill-fg2">Waypoint</text>
            <text class="fill-mute text-[.85em]" x="38%" y="31" text-anchor="middle">End</text>
            <text x="68%" y="14" text-anchor="middle" class="fill-fg2">Exit</text>
            <text class="fill-mute text-[.85em]" x="68%" y="31" text-anchor="middle">End.DT46</text>
            <text x="8%" y="132" text-anchor="middle" class="fill-fg2">Laptop</text>
            <text x="92%" y="132" text-anchor="middle" class="fill-fg2">Internet</text>
            <text class="fill-mute text-[.85em]" x="50%" y="128" text-anchor="middle">Default route</text>
          </svg>
        </figure>
        <p class="note">Waypoints can come in any order the user specifies and may repeat, e.g. A->B->C->B->D with D as the exit.</p>
      </section>

<section class="page-section" id="benchmarks" aria-labelledby="bench-h">
        <h2 id="bench-h" class="text-[1.5em] font-bold text-fg">Benchmarks</h2>
        <div class="overflow-x-auto mt-[1em]">
          <table class="data-table data-table-left max-sm:whitespace-normal">
            <thead>
              <tr>
                <th scope="col">Dataplane</th>
                <th scope="col">Runs in</th>
                <th scope="col">Protocol and cipher</th>
              </tr>
            </thead>
            <tbody>
              <tr class="row-accent">
                <th scope="row">ranet3</th>
                <td>Userspace</td>
                <td>ESP in UDP, <span class="whitespace-nowrap">AES-256-GCM</span></td>
              </tr>
              <tr>
                <th scope="row"><span class="whitespace-nowrap">wireguard-go</span></th>
                <td>Userspace</td>
                <td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td>
              </tr>
              <tr>
                <th scope="row">WireGuard</th>
                <td>Kernel</td>
                <td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td>
              </tr>
              <tr>
                <th scope="row">IPsec</th>
                <td>Kernel (xfrm)</td>
                <td>ESP in UDP, <span class="whitespace-nowrap">AES-256-GCM</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="note">Medians of 3 runs under saturation</p>
        <h3 class="subhead mt-[3em]" id="head-to-head">Head to head</h3>
        <div class="overflow-x-auto mt-[1em]">
          <table class="data-table data-table-left data-table-ruled max-sm:whitespace-normal">
            <thead>
              <tr>
                <th scope="col">Dataplane</th>
                <th scope="col">Throughput<small>higher is better</small></th>
                <th scope="col">CPU per Gbit/s<small>lower is better</small></th>
                <th scope="col">Latency p99<small>lower is better</small></th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row"><span class="whitespace-nowrap">wireguard-go</span> <small>user</small></th>
                <td><span class="font-bold whitespace-nowrap text-win">1.2-1.5x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-win">0.8-0.9x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-mute">0.2-1.0x</span> <small>mixed</small></td>
              </tr>
              <tr>
                <th scope="row">WireGuard <small>kernel</small></th>
                <td><span class="font-bold whitespace-nowrap text-win">1.6-2.1x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-win">0.6x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-lose">1.9-2.4x</span> <small>worse</small></td>
              </tr>
              <tr>
                <th scope="row">IPsec <small>kernel</small></th>
                <td><span class="font-bold whitespace-nowrap text-win">1.8-3.9x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-lose">1.1-1.7x</span> <small>worse</small></td>
                <td><span class="font-bold whitespace-nowrap text-lose">1.6-2.0x</span> <small>worse</small></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="note">Each range is ranet3's result divided by the other dataplane's across the 6 tests below.</p>
        <h3 class="subhead mt-[3em]" id="kernel-and-userspace">Kernel and userspace</h3>
        <p class="mt-[.6em] text-fg2">Userspace dataplanes copy every packet into their own process and are usually expected to be slower than kernel ones.</p>
        <div class="overflow-x-auto mt-[1em]">
          <table class="data-table max-sm:whitespace-normal">
            <thead>
              <tr>
                <th scope="col" class="pl-0 text-left"><small>1 stream, Gbit/s</small></th>
                <th scope="col">One way</th>
                <th scope="col">Both ways</th>
                <th scope="col">Share of line<small>one way</small></th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">Line limit <span class="whitespace-nowrap">(10 GbE)</span></th>
                <td>8.84</td>
                <td>18.76<sup>*</sup></td>
                <td>100%</td>
              </tr>
              <tr>
                <th scope="row">Kernel, <span class="whitespace-nowrap">best of 2</span></th>
                <td>5.35</td>
                <td>7.46</td>
                <td>61%</td>
              </tr>
              <tr>
                <th scope="row">Userspace, <span class="whitespace-nowrap">wireguard-go</span></th>
                <td>6.77</td>
                <td>10.78</td>
                <td>77%</td>
              </tr>
              <tr class="row-accent">
                <th scope="row">Userspace, ranet3</th>
                <td>8.39</td>
                <td>14.87</td>
                <td>95%</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="note">* Plain TCP without tunnel</p>
        <p class="note">Kernel WireGuard stays at 5.1 to 5.4 Gbit/s one way.</p>
        <p class="note">Kernel IPsec stays at 4.0 to 4.7 Gbit/s because its single flow lands on 1 NIC receive queue.</p>
        <h3 class="subhead mt-[3em]" id="full-results">Full results</h3>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Throughput, saturated</b><span class="text-mute">Gbit/s received</span><span class="text-dir">Higher is better</span></figcaption>
          <div class="overflow-x-auto">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <th scope="col"></th>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint cell-best">8.39<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.77<span class="meter" style="--w:80.7%"></span></td>
                  <td>5.35<span class="meter" style="--w:63.8%"></span></td>
                  <td>4.67<span class="meter" style="--w:55.7%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint cell-best">8.37<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.95<span class="meter" style="--w:83%"></span></td>
                  <td>5.10<span class="meter" style="--w:60.9%"></span></td>
                  <td>4.44<span class="meter" style="--w:53%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint cell-best">14.87<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>10.78<span class="meter" style="--w:72.5%"></span></td>
                  <td>7.46<span class="meter" style="--w:50.2%"></span></td>
                  <td>4.67<span class="meter" style="--w:31.4%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint cell-best">8.52<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.06<span class="meter" style="--w:71.1%"></span></td>
                  <td>5.14<span class="meter" style="--w:60.3%"></span></td>
                  <td>3.97<span class="meter" style="--w:46.6%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint cell-best">8.48<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.72<span class="meter" style="--w:79.2%"></span></td>
                  <td>5.12<span class="meter" style="--w:60.4%"></span></td>
                  <td>4.06<span class="meter" style="--w:47.9%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint cell-best">15.79<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>10.33<span class="meter" style="--w:65.4%"></span></td>
                  <td>7.41<span class="meter" style="--w:46.9%"></span></td>
                  <td>4.10<span class="meter" style="--w:26%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </figure>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>CPU cost at 3 Gbit/s offered</b><span class="text-mute">Busy cores per Gbit/s, both hosts</span><span class="text-dir">Lower is better</span></figcaption>
          <div class="overflow-x-auto">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <th scope="col"></th>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint">0.909<span class="meter meter-accent" style="--w:60.2%"></span></td>
                  <td>1.079<span class="meter" style="--w:71.4%"></span></td>
                  <td>1.511<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.672<span class="meter" style="--w:44.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint">0.925<span class="meter meter-accent" style="--w:60.7%"></span></td>
                  <td>1.092<span class="meter" style="--w:71.6%"></span></td>
                  <td>1.525<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.664<span class="meter" style="--w:43.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint">0.898<span class="meter meter-accent" style="--w:59.7%"></span></td>
                  <td>0.996<span class="meter" style="--w:66.2%"></span></td>
                  <td>1.504<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.525<span class="meter" style="--w:34.9%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint">0.996<span class="meter meter-accent" style="--w:57.2%"></span></td>
                  <td>1.213<span class="meter" style="--w:69.7%"></span></td>
                  <td>1.740<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.845<span class="meter" style="--w:48.6%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint">0.990<span class="meter meter-accent" style="--w:56.6%"></span></td>
                  <td>1.182<span class="meter" style="--w:67.6%"></span></td>
                  <td>1.748<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.866<span class="meter" style="--w:49.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint">0.948<span class="meter meter-accent" style="--w:63.2%"></span></td>
                  <td>1.087<span class="meter" style="--w:72.5%"></span></td>
                  <td>1.500<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.620<span class="meter" style="--w:41.3%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="note">In the "both" rows kernel IPsec carried only 4.67 and 4.14 of the 6 Gbit/s offered.</p>
        </figure>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Latency under saturation</b><span class="text-mute">RTT p99, ms</span><span class="text-dir">Lower is better</span></figcaption>
          <div class="overflow-x-auto">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <th scope="col"></th>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint">2.01<span class="meter meter-accent" style="--w:95.7%"></span></td>
                  <td>2.10<span class="meter" style="--w:100%"></span></td>
                  <td>1.07<span class="meter" style="--w:51%"></span></td>
                  <td class="cell-best">1.04<span class="meter" style="--w:49.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint">1.91<span class="meter meter-accent" style="--w:87.6%"></span></td>
                  <td>2.18<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">0.85<span class="meter" style="--w:39%"></span></td>
                  <td>1.23<span class="meter" style="--w:56.4%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint">3.17<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>3.15<span class="meter" style="--w:99.4%"></span></td>
                  <td class="cell-best">1.65<span class="meter" style="--w:52.1%"></span></td>
                  <td>1.76<span class="meter" style="--w:55.5%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint">2.77<span class="meter meter-accent" style="--w:16.9%"></span></td>
                  <td>16.40<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">1.26<span class="meter" style="--w:7.7%"></span></td>
                  <td>1.53<span class="meter" style="--w:9.3%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint">2.86<span class="meter meter-accent" style="--w:56.2%"></span></td>
                  <td>5.09<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">1.17<span class="meter" style="--w:23%"></span></td>
                  <td>1.50<span class="meter" style="--w:29.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint">4.96<span class="meter meter-accent" style="--w:64.5%"></span></td>
                  <td>7.69<span class="meter" style="--w:100%"></span></td>
                  <td class="cell-best">2.48<span class="meter" style="--w:32.2%"></span></td>
                  <td>2.51<span class="meter" style="--w:32.6%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </figure>
      </section>

<section class="page-section" id="setup" aria-labelledby="setup-h">
        <h2 id="setup-h" class="text-[1.5em] font-bold text-fg">Setup</h2>
        <h3 class="subhead mt-[1em]" id="hardware">Hardware</h3>
        <dl class="spec-list">
          <dt>Hosts</dt>
          <dd>2 x Dell PowerEdge C6420</dd>
          <dt>Processor</dt>
          <dd>Intel Xeon Gold 6130 with 16 cores and 32 threads</dd>
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
        <h3 class="subhead mt-[3em]" id="software">Software</h3>
        <dl class="spec-list">
          <dt>OS</dt>
          <dd>Debian 13</dd>
          <dt>Kernel</dt>
          <dd><a href="https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12.111" class="link">Linux 6.12.111</a></dd>
          <dt>wireguard-go</dt>
          <dd><a href="https://git.zx2c4.com/wireguard-go/tag/?h=0.0.20250522" class="link">0.0.20250522</a></dd>
          <dt>wireguard-tools</dt>
          <dd><a href="https://git.zx2c4.com/wireguard-tools/tag/?h=v1.0.20260223" class="link">1.0.20260223</a></dd>
          <dt>iproute2</dt>
          <dd><a href="https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tag/?h=v7.1.0" class="link">7.1.0</a></dd>
          <dt>iperf3</dt>
          <dd><a href="https://github.com/esnet/iperf/releases/tag/3.21" class="link">3.21</a></dd>
        </dl>
        <h3 class="subhead mt-[3em]" id="method">Method</h3>
        <dl class="spec-list">
          <dt>Traffic</dt>
          <dd>TCP with cubic at inner MTU 1400</dd>
          <dt>Streams</dt>
          <dd>1 and 8</dd>
          <dt>Load</dt>
          <dd>Saturated for throughput and latency and 3 Gbit/s each way for CPU cost</dd>
          <dt>Direction</dt>
          <dd>One way in each direction and both ways at once</dd>
          <dt>Runs</dt>
          <dd>Median of 3 runs of 10 seconds with the dataplanes interleaved</dd>
          <dt>CPU cost</dt>
          <dd>Busy cores from /proc/stat summed over both hosts with every dataplane unpinned</dd>
          <dt>Line limit</dt>
          <dd>8.84 Gbit/s of TCP payload one way after ESP in UDP framing and 18.76 Gbit/s both ways without a tunnel</dd>
        </dl>
      </section>

<div class="mx-auto flex max-w-[92ch] flex-wrap items-center gap-6 px-4 pt-12 pb-14 text-[15px]">
<h2 class="mr-auto text-[28px] font-bold text-fg">See it on your network.</h2>
<a href="mailto:mesh@ranet3.com?subject=ranet3%20demo" class="btn-primary">Request a Demo</a>
</div>
