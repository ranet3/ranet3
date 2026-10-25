---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "ranet3"
description: "High performance policy routed IPsec mesh SD-WAN with userspace ESP, IKEv2, an embedded Babel speaker and SRv6 steering."
created: 2026-10-06
updated: 2026-10-25
vetted: 2026-10-25
layout: bare
---

<div class="hero items-end gap-x-14 pb-18 text-fg">
<div>
<h1 class="text-[clamp(40px,5vw,64px)] leading-[1.05] font-bold tracking-[-.02em] text-balance">Mesh network, reimagined.</h1>
<p class="mt-7 max-w-[56ch] text-[18px] text-pretty text-fg2 max-lg:mx-auto max-sm:text-[16px]">High performance policy routed IPsec mesh SD-WAN with userspace ESP, IKEv2, an embedded Babel speaker and SRv6 steering.</p>
<div class="mt-9 flex flex-wrap gap-3 max-lg:justify-center">
<a href="/contact/" class="btn-primary">Request a demo</a>
<a href="/docs/getting-started/" class="btn-secondary arrow">Get started</a>
</div>
</div>
<div class="hero-mark">
<ui-ascii-mark></ui-ascii-mark>
</div>
</div>

<div class="border-y border-line">
<div class="mx-auto grid max-w-6xl px-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.4fr)] md:px-6">
<div class="py-10 md:border-r md:border-line md:pr-14"><div class="text-[clamp(44px,5.6vw,72px)] leading-none font-bold whitespace-nowrap text-acc">99%</div><p class="mt-3.5 text-fg2">of the 10 GbE payload limit, 1 stream one way</p><p class="label mt-1">8.79 of 8.84 Gbit/s</p></div>
<div class="border-t border-line py-10 md:border-t-0 md:border-r md:px-14"><div class="text-[clamp(44px,5.6vw,72px)] leading-none font-bold whitespace-nowrap text-acc">2.7x</div><p class="mt-3.5 text-fg2">kernel WireGuard throughput, at best</p><p class="label mt-1">1.98-2.73x across all tests</p></div>
<div class="flex flex-col justify-center gap-3.5 border-t border-line py-10 text-fg2 md:border-t-0 md:pl-14">
<div class="flex gap-[2ch]"><span class="text-acc">+</span><span>1.3-1.5x Tailscale and wireguard-go throughput, all tests</span></div>
<div class="pl-[3ch]">2.63-7.81 ms RTT p99 under saturation, kernel dataplanes 1.00-2.98 ms</div>
<div class="pl-[3ch]"><span class="label">2 runs under saturation</span></div>
<a href="/benchmarks/" class="link mt-1.5">Benchmarks</a>
</div>
</div>
</div>

<div class="split mt-24">
<h2 class="title">We bring ISP grade networking magic to everyone</h2>
<div class="flex flex-col border-t border-line">
<details class="fold">
<summary class="row"><span class="text-mute">01</span><span>Interoperability<small>Peers only need standard IKEv2, ESP, Babel and SRv6.</small></span></summary>
<div>
<p class="callout mt-0">Common mesh VPN and SD-WAN tools (Tailscale, NetBird, ZeroTier, Nebula, etc.) admit only nodes that run their own agent, and ranet3 runs beside them on the same host.</p>
<p class="mt-[1.2em] text-fg2">Interoperability is checked against:</p>
<dl class="terms">
<dt>strongSwan</dt>
<dd>IKEv2 and ESP sessions with Ed25519 keys</dd>
<dt>BIRD</dt>
<dd>Babel routes with RTT metrics, matched route for route</dd>
<dt>Linux</dt>
<dd>Kernel seg6local acts on the SRv6 headers ranet3 writes</dd>
</dl>
<p class="note">Any other router or switch that supports IKEv2 with Ed25519 keys, Babel and SRv6 should interoperate as well.</p>
</div>
</details>
<details class="fold">
<summary class="row"><span class="text-mute">02</span><span>Latency aware routing<small>Babel measures the round trip of every link and routes through a relay whenever the direct link is slower.</small></span></summary>
<div>
<figure class="mt-[.6em]">
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
<p class="mt-[1em] text-fg2">RTT is measured continuously, and packet loss and outages count against a link. Traffic always takes the fastest path, moving back to the direct link once it is faster again.</p>
</div>
</details>
<details class="fold">
<summary class="row"><span class="text-mute">03</span><span>Segment routing<small>A policy on source and destination prefix sends traffic through chosen waypoints and out at a chosen exit.</small></span></summary>
<div>
<p class="text-fg2">Segment routing is implemented in userspace and works even on macOS, whose XNU kernel has no support for it.</p>
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
<p class="mt-[1em] text-fg2">Waypoints can come in any order the user specifies and may repeat, e.g. <span class="whitespace-nowrap">A->B->C->B->D</span> with D as the exit.</p>
</div>
</details>
<details class="fold">
<summary class="row"><span class="text-mute">04</span><span>Security<small>Hybrid post-quantum key exchange.</small></span></summary>
<div>
<p class="text-fg2">Per-device keys under CA chains of any depth are on the way.</p>
<dl class="terms">
<dt>Authentication</dt>
<dd>Ed25519 signatures</dd>
<dt>Key exchange</dt>
<dd>X25519, <span class="whitespace-nowrap">P-256</span> or <span class="whitespace-nowrap">P-384</span>, alone or followed by <span class="whitespace-nowrap">ML-KEM-768</span> or <span class="whitespace-nowrap">ML-KEM-1024</span></dd>
<dt>Ciphers</dt>
<dd><span class="whitespace-nowrap">AES-GCM</span> or ChaCha20-Poly1305</dd>
</dl>
<p class="note">A node offers X25519 with <span class="whitespace-nowrap">ML-KEM-768</span> first unless it lists its own key exchanges.</p>
</div>
</details>
<details class="fold">
<summary class="row"><span class="text-mute">05</span><span>Auditability<small>Source available, Apache-2.0 after 2 years.</small></span></summary>
<div>
<p class="text-fg2">The codebase is licensed under the <a href="https://github.com/ranet3/ranet3/blob/master/licenses/FSL-1.1-ALv2.txt" class="link whitespace-nowrap">FSL-1.1-ALv2</a>, and each version converts to <a href="https://www.apache.org/licenses/LICENSE-2.0" class="link whitespace-nowrap">Apache-2.0</a> 2 years after its original publication date.</p></div>
</details>
<a href="/benchmarks/" class="row"><span class="text-mute">06</span><span>Benchmarks<small>Higher throughput than Tailscale, NetBird, kernel WireGuard, wireguard-go and kernel IPsec in all tests on 10 GbE.</small></span></a>
</div>
</div>
