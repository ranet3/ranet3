---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Why ranet3"
description: "The standard protocols ranet3 speaks, how it routes by latency, and how it steers traffic with segment routing."
created: 2026-10-21
updated: 2026-10-21
layout: bare
---

<section class="page-section" aria-labelledby="why-h">
        <h1 id="why-h" class="text-[2em] font-bold text-fg">Why ranet3</h1>
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
