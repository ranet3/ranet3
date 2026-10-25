---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Benchmarks"
description: "ranet3 against Tailscale, NetBird, kernel WireGuard, wireguard-go and kernel IPsec on 10 GbE, with the hardware, software and method of the runs."
created: 2026-10-21
updated: 2026-10-25
vetted: 2026-10-25
layout: bare
---

<section class="section">
        <h1 class="text-[2em] font-bold text-fg">Benchmarks</h1>
        <p class="note">Measured on 2026-10-25</p>
        <div class="overflow-x-auto mt-[1em]" tabindex="0">
          <table class="data-table data-table-left max-sm:whitespace-normal">
            <thead>
              <tr>
                <th scope="col">Dataplane</th>
                <th scope="col">Runs in</th>
                <th scope="col">Protocol and cipher</th>
              </tr>
            </thead>
            <tbody>
              <tr class="tr-accent">
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
                <th scope="row">Tailscale</th>
                <td>Userspace</td>
                <td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td>
              </tr>
              <tr>
                <th scope="row">NetBird</th>
                <td>Userspace</td>
                <td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td>
              </tr>
              <tr>
                <th scope="row">WireGuard</th>
                <td>Kernel</td>
                <td>WireGuard, <span class="whitespace-nowrap">ChaCha20-Poly1305</span></td>
              </tr>
              <tr>
                <th scope="row">NetBird</th>
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
        <p class="note">2 runs under saturation</p>
        <h2 class="subhead mt-[3em]">Head to head</h2>
        <div class="overflow-x-auto mt-[1em]" tabindex="0">
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
                <td><span class="font-bold whitespace-nowrap text-good">1.3-1.5x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.8-0.9x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-mute">0.6-1.2x</span> <small>mixed</small></td>
              </tr>
              <tr>
                <th scope="row">Tailscale <small>user</small></th>
                <td><span class="font-bold whitespace-nowrap text-good">1.3-1.5x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.8-0.9x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.2-0.6x</span> <small>better</small></td>
              </tr>
              <tr>
                <th scope="row">NetBird <small>user</small></th>
                <td><span class="font-bold whitespace-nowrap text-good">1.3-1.5x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.8-0.9x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-mute">0.2-1.4x</span> <small>mixed</small></td>
              </tr>
              <tr>
                <th scope="row">WireGuard <small>kernel</small></th>
                <td><span class="font-bold whitespace-nowrap text-good">2.0-2.7x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.5-0.6x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-bad">1.4-4.8x</span> <small>worse</small></td>
              </tr>
              <tr>
                <th scope="row">NetBird <small>kernel</small></th>
                <td><span class="font-bold whitespace-nowrap text-good">2.1-2.6x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-good">0.5-0.6x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-bad">1.6-6.4x</span> <small>worse</small></td>
              </tr>
              <tr>
                <th scope="row">IPsec <small>kernel</small></th>
                <td><span class="font-bold whitespace-nowrap text-good">2.2-4.0x</span> <small>better</small></td>
                <td><span class="font-bold whitespace-nowrap text-bad">1.1-1.6x</span> <small>worse</small></td>
                <td><span class="font-bold whitespace-nowrap text-bad">1.7-5.6x</span> <small>worse</small></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="note">Each range is ranet3's result divided by the other dataplane's across the 6 tests below.</p>
        <h2 class="subhead mt-[3em]">Kernel and userspace</h2>
        <p class="mt-[.6em] text-fg2">Userspace dataplanes copy every packet into their own process and are usually expected to be slower than kernel ones.</p>
        <div class="overflow-x-auto mt-[1em]" tabindex="0">
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
                <th scope="row">Kernel, <span class="whitespace-nowrap">best of 3</span></th>
                <td>4.43</td>
                <td>6.17</td>
                <td>50%</td>
              </tr>
              <tr>
                <th scope="row">Userspace, <span class="whitespace-nowrap">wireguard-go</span></th>
                <td>6.87</td>
                <td>10.60</td>
                <td>78%</td>
              </tr>
              <tr>
                <th scope="row">Userspace, Tailscale</th>
                <td>6.87</td>
                <td>10.98</td>
                <td>78%</td>
              </tr>
              <tr class="tr-accent">
                <th scope="row">Userspace, ranet3</th>
                <td>8.79</td>
                <td>15.81</td>
                <td>99%</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="note">* Plain TCP without tunnel</p>
        <p class="note">Kernel WireGuard stays at 4.0 to 4.4 Gbit/s one way.</p>
        <p class="note">Kernel IPsec stays at 3.5 to 4.5 Gbit/s because its single flow lands on 1 NIC receive queue.</p>
        <h2 class="subhead mt-[3em]">Full results</h2>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Throughput, saturated</b><span class="text-mute">Gbit/s received</span><span class="text-hint">Higher is better</span></figcaption>
          <div class="overflow-x-auto" tabindex="0">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <td></td>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">Tailscale<small>user</small></th>
                  <th scope="col">NetBird<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">NetBird<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint td-best">8.79<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.87<span class="meter" style="--w:78.2%"></span></td>
                  <td>6.87<span class="meter" style="--w:78.2%"></span></td>
                  <td>6.58<span class="meter" style="--w:74.9%"></span></td>
                  <td>4.43<span class="meter" style="--w:50.4%"></span></td>
                  <td>4.18<span class="meter" style="--w:47.6%"></span></td>
                  <td>4.07<span class="meter" style="--w:46.3%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint td-best">8.80<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.86<span class="meter" style="--w:78%"></span></td>
                  <td>6.86<span class="meter" style="--w:78%"></span></td>
                  <td>6.77<span class="meter" style="--w:76.9%"></span></td>
                  <td>4.34<span class="meter" style="--w:49.3%"></span></td>
                  <td>4.10<span class="meter" style="--w:46.6%"></span></td>
                  <td>4.08<span class="meter" style="--w:46.4%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint td-best">15.81<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>10.60<span class="meter" style="--w:67%"></span></td>
                  <td>10.98<span class="meter" style="--w:69.4%"></span></td>
                  <td>10.69<span class="meter" style="--w:67.6%"></span></td>
                  <td>6.17<span class="meter" style="--w:39%"></span></td>
                  <td>6.14<span class="meter" style="--w:38.8%"></span></td>
                  <td>4.45<span class="meter" style="--w:28.1%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint td-best">8.73<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.40<span class="meter" style="--w:73.3%"></span></td>
                  <td>6.34<span class="meter" style="--w:72.6%"></span></td>
                  <td>5.70<span class="meter" style="--w:65.3%"></span></td>
                  <td>4.22<span class="meter" style="--w:48.3%"></span></td>
                  <td>4.00<span class="meter" style="--w:45.8%"></span></td>
                  <td>3.80<span class="meter" style="--w:43.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint td-best">8.74<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>6.52<span class="meter" style="--w:74.6%"></span></td>
                  <td>6.45<span class="meter" style="--w:73.8%"></span></td>
                  <td>6.73<span class="meter" style="--w:77%"></span></td>
                  <td>4.02<span class="meter" style="--w:46%"></span></td>
                  <td>3.97<span class="meter" style="--w:45.4%"></span></td>
                  <td>3.54<span class="meter" style="--w:40.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint td-best">15.24<span class="meter meter-accent" style="--w:100%"></span></td>
                  <td>10.13<span class="meter" style="--w:66.5%"></span></td>
                  <td>10.17<span class="meter" style="--w:66.7%"></span></td>
                  <td>10.20<span class="meter" style="--w:66.9%"></span></td>
                  <td>5.58<span class="meter" style="--w:36.6%"></span></td>
                  <td>5.93<span class="meter" style="--w:38.9%"></span></td>
                  <td>3.81<span class="meter" style="--w:25%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </figure>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>CPU cost at 3 Gbit/s offered</b><span class="text-mute">Busy cores per Gbit/s, both hosts</span><span class="text-hint">Lower is better</span></figcaption>
          <div class="overflow-x-auto" tabindex="0">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <td></td>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">Tailscale<small>user</small></th>
                  <th scope="col">NetBird<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">NetBird<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint">0.926<span class="meter meter-accent" style="--w:56.8%"></span></td>
                  <td>1.070<span class="meter" style="--w:65.6%"></span></td>
                  <td>1.102<span class="meter" style="--w:67.6%"></span></td>
                  <td>1.038<span class="meter" style="--w:63.7%"></span></td>
                  <td>1.569<span class="meter" style="--w:96.3%"></span></td>
                  <td>1.630<span class="meter" style="--w:100%"></span></td>
                  <td class="td-best">0.670<span class="meter" style="--w:41.1%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint">0.914<span class="meter meter-accent" style="--w:55.3%"></span></td>
                  <td>1.081<span class="meter" style="--w:65.4%"></span></td>
                  <td>1.086<span class="meter" style="--w:65.7%"></span></td>
                  <td>1.039<span class="meter" style="--w:62.9%"></span></td>
                  <td>1.577<span class="meter" style="--w:95.5%"></span></td>
                  <td>1.652<span class="meter" style="--w:100%"></span></td>
                  <td class="td-best">0.677<span class="meter" style="--w:41%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint">0.857<span class="meter meter-accent" style="--w:56%"></span></td>
                  <td>1.026<span class="meter" style="--w:67.1%"></span></td>
                  <td>0.968<span class="meter" style="--w:63.3%"></span></td>
                  <td>0.996<span class="meter" style="--w:65.1%"></span></td>
                  <td>1.529<span class="meter" style="--w:100%"></span></td>
                  <td>1.511<span class="meter" style="--w:98.8%"></span></td>
                  <td class="td-best">0.541<span class="meter" style="--w:35.4%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint">0.927<span class="meter meter-accent" style="--w:50.8%"></span></td>
                  <td>1.205<span class="meter" style="--w:66%"></span></td>
                  <td>1.111<span class="meter" style="--w:60.9%"></span></td>
                  <td>1.167<span class="meter" style="--w:63.9%"></span></td>
                  <td>1.788<span class="meter" style="--w:98%"></span></td>
                  <td>1.825<span class="meter" style="--w:100%"></span></td>
                  <td class="td-best">0.864<span class="meter" style="--w:47.3%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint">0.931<span class="meter meter-accent" style="--w:50.4%"></span></td>
                  <td>1.171<span class="meter" style="--w:63.3%"></span></td>
                  <td>1.121<span class="meter" style="--w:60.6%"></span></td>
                  <td>1.163<span class="meter" style="--w:62.9%"></span></td>
                  <td>1.783<span class="meter" style="--w:96.4%"></span></td>
                  <td>1.849<span class="meter" style="--w:100%"></span></td>
                  <td class="td-best">0.849<span class="meter" style="--w:45.9%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint">0.913<span class="meter meter-accent" style="--w:58.8%"></span></td>
                  <td>1.088<span class="meter" style="--w:70%"></span></td>
                  <td>0.982<span class="meter" style="--w:63.2%"></span></td>
                  <td>1.058<span class="meter" style="--w:68.1%"></span></td>
                  <td>1.542<span class="meter" style="--w:99.2%"></span></td>
                  <td>1.554<span class="meter" style="--w:100%"></span></td>
                  <td class="td-best">0.683<span class="meter" style="--w:44%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="note">In the "both" rows kernel IPsec carried only 4.45 and 3.82 of the 6 Gbit/s offered, and NetBird 5.84 at 8 streams.</p>
        </figure>
        <figure class="mt-[2em]">
          <figcaption class="mb-[.6em] flex flex-wrap gap-x-[1.5ch] text-fg"><b>Latency under saturation</b><span class="text-mute">RTT p99, ms</span><span class="text-hint">Lower is better</span></figcaption>
          <div class="overflow-x-auto" tabindex="0">
            <table class="data-table data-table-wide max-sm:whitespace-normal">
              <thead>
                <tr>
                  <td></td>
                  <th scope="col" class="bg-acc font-bold text-bg">ranet3<small class="text-bg">user</small></th>
                  <th scope="col">wireguard-go<small>user</small></th>
                  <th scope="col">Tailscale<small>user</small></th>
                  <th scope="col">NetBird<small>user</small></th>
                  <th scope="col">WireGuard<small>kernel</small></th>
                  <th scope="col">NetBird<small>kernel</small></th>
                  <th scope="col">IPsec<small>kernel</small></th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> out</th>
                  <td class="bg-tint">2.74<span class="meter meter-accent" style="--w:56.3%"></span></td>
                  <td>2.29<span class="meter" style="--w:47%"></span></td>
                  <td>4.87<span class="meter" style="--w:100%"></span></td>
                  <td>2.34<span class="meter" style="--w:48%"></span></td>
                  <td>1.18<span class="meter" style="--w:24.2%"></span></td>
                  <td class="td-best">1.09<span class="meter" style="--w:22.4%"></span></td>
                  <td>1.39<span class="meter" style="--w:28.5%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> in</th>
                  <td class="bg-tint">2.96<span class="meter meter-accent" style="--w:61.5%"></span></td>
                  <td>2.63<span class="meter" style="--w:54.7%"></span></td>
                  <td>4.81<span class="meter" style="--w:100%"></span></td>
                  <td>2.13<span class="meter" style="--w:44.3%"></span></td>
                  <td class="td-best">1.00<span class="meter" style="--w:20.8%"></span></td>
                  <td>1.07<span class="meter" style="--w:22.2%"></span></td>
                  <td>1.26<span class="meter" style="--w:26.2%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">1 stream,</span> both</th>
                  <td class="bg-tint">2.63<span class="meter meter-accent" style="--w:43.7%"></span></td>
                  <td>3.11<span class="meter" style="--w:51.7%"></span></td>
                  <td>6.02<span class="meter" style="--w:100%"></span></td>
                  <td>3.02<span class="meter" style="--w:50.2%"></span></td>
                  <td>1.85<span class="meter" style="--w:30.7%"></span></td>
                  <td>1.67<span class="meter" style="--w:27.7%"></span></td>
                  <td class="td-best">1.57<span class="meter" style="--w:26.1%"></span></td>
                </tr>
              </tbody>
              <tbody>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> out</th>
                  <td class="bg-tint">6.65<span class="meter meter-accent" style="--w:19.1%"></span></td>
                  <td>12.00<span class="meter" style="--w:34.5%"></span></td>
                  <td>25.20<span class="meter" style="--w:72.4%"></span></td>
                  <td>34.80<span class="meter" style="--w:100%"></span></td>
                  <td>1.38<span class="meter" style="--w:4%"></span></td>
                  <td class="td-best">1.35<span class="meter" style="--w:3.9%"></span></td>
                  <td>1.42<span class="meter" style="--w:4.1%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> in</th>
                  <td class="bg-tint">7.81<span class="meter meter-accent" style="--w:25.9%"></span></td>
                  <td>7.76<span class="meter" style="--w:25.7%"></span></td>
                  <td>30.20<span class="meter" style="--w:100%"></span></td>
                  <td>6.65<span class="meter" style="--w:22%"></span></td>
                  <td>1.91<span class="meter" style="--w:6.3%"></span></td>
                  <td class="td-best">1.22<span class="meter" style="--w:4%"></span></td>
                  <td>1.39<span class="meter" style="--w:4.6%"></span></td>
                </tr>
                <tr>
                  <th scope="row"><span class="whitespace-nowrap">8 streams,</span> both</th>
                  <td class="bg-tint">4.63<span class="meter meter-accent" style="--w:24.5%"></span></td>
                  <td>6.03<span class="meter" style="--w:31.9%"></span></td>
                  <td>18.90<span class="meter" style="--w:100%"></span></td>
                  <td>8.57<span class="meter" style="--w:45.3%"></span></td>
                  <td>2.98<span class="meter" style="--w:15.8%"></span></td>
                  <td class="td-best">2.53<span class="meter" style="--w:13.4%"></span></td>
                  <td>2.63<span class="meter" style="--w:13.9%"></span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </figure>
      </section>

<section class="section">
        <h2 class="text-[1.5em] font-bold text-fg">Setup</h2>
        <h3 class="subhead mt-[1em]">Hardware</h3>
        <dl class="terms">
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
        <h3 class="subhead mt-[3em]">Software</h3>
        <dl class="terms">
          <dt>OS</dt>
          <dd>Debian 13</dd>
          <dt>Kernel</dt>
          <dd><a href="https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12.111" class="link">Linux 6.12.111</a></dd>
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
          <dd>TCP with cubic at inner MTU 1400</dd>
          <dt>Streams</dt>
          <dd>1 and 8</dd>
          <dt>Load</dt>
          <dd>Saturated for throughput and latency and 3 Gbit/s each way for CPU cost</dd>
          <dt>Direction</dt>
          <dd>One way in each direction and both ways at once</dd>
          <dt>Runs</dt>
          <dd>2 runs of 10 seconds with the dataplanes interleaved, throughput and CPU cost averaged, RTT p99 over both runs' pings</dd>
          <dt>Paths</dt>
          <dd>Direct between the hosts for every dataplane, with no relay, checked on every run</dd>
          <dt>Control</dt>
          <dd>headscale for Tailscale and NetBird's own servers on one host, at most 0.002 cores during a run</dd>
          <dt>Outer IP</dt>
          <dd>IPv4, except where Tailscale and NetBird chose IPv6, whose header adds about 1.3% on the wire</dd>
          <dt>CPU cost</dt>
          <dd>Busy cores from /proc/stat summed over both hosts with every dataplane unpinned</dd>
          <dt>Line limit</dt>
          <dd>8.84 Gbit/s of TCP payload one way after ESP in UDP framing and 18.76 Gbit/s both ways without a tunnel</dd>
        </dl>
      </section>
