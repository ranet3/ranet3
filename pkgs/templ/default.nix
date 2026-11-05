# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

{ pkgsPrev, buildGoLatestModule }:

pkgsPrev.templ.override { buildGoModule = buildGoLatestModule; }
