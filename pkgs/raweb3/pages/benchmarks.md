---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Benchmarks"
description: "ranet3 against kernel WireGuard, wireguard-go and kernel IPsec on 10 GbE, with the hardware, software and method of the runs."
created: 2026-10-21
updated: 2026-10-21
layout: bare
---

<section class="page-section" aria-labelledby="bench-h">
        <h1 id="bench-h" class="text-[2em] font-bold text-fg">Benchmarks</h1>
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
