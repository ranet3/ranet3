<!-- SPDX-FileCopyrightText: 2026 Yifei Sun -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<!-- deno-fmt-ignore-start -->
<div align="center">
<pre>
              ..::----::..              
          .:-++++++++++++++-:.          
        :=+++-:..      ..:-+++=:        
      :=++-.                .-+-.       
    .=++-.       ::::::       .   .::.  
   :++=.     :+#@@@@@@@@#+:      *@@@@= 
  :++=     -#@@%*+-::-+*%@@#-   :@@@@@@ 
 .++=    .*@@#-          -#@@*. .#@@@@* 
 -++.   .#@@=              =@@#.  -++:  
.++-    *@@-      :++:      -@@*        
:++.   .@@#     -%@@@@%-     #@@.   .--:
-++    .++:     %@@@@@@%     +@@:    ++-
-++             %@@@@@@%     +@@:    ++-
:++.    .=+-.   -%@@@@%-     #@@.   .++:
.++-   :%@@@%:    :++:      -@@*    -++.
 -++.  =@@@@@=             =@@#.   .++- 
 .++=   +%@%+            -#@@*.    =++. 
  :++=         =*+-::-+*%@@#-     =++:  
   :++=.      .#@@@@@@@@#+:     .=++:   
    .=++-.       ::::::       .-++=.    
      :=++-.                .-++=:      
        :=+++-:..      ..:-+++=:        
          .:-++++++++++++++-:.          
              ..::----::..              
</pre>
</div>
<!-- deno-fmt-ignore-end -->

This monorepo contains the source code of [`ranet3`](https://ranet3.com), a mesh networking toolkit
with userspace IPsec, latency-aware Babel routing, source-specific routes and
segment routing.

## License

The codebase is licensed under the [FSL-1.1-ALv2](licenses/FSL-1.1-ALv2.txt).
Each version converts to
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) two years after its
original publication date.

The codebase began as a fork of
[NickCao/ranet-lite](https://github.com/NickCao/ranet-lite) and
[NickCao/ranet](https://github.com/NickCao/ranet), and the portions derived
from them remain under the [MIT](licenses/MIT.txt) license.

[`pkgs/wireguard`](pkgs/wireguard) holds a copy of
[wireguard-go](https://git.zx2c4.com/wireguard-go) with changes from
[tailscale's fork](https://github.com/tailscale/wireguard-go) of it. The copied
files are licensed under the [MIT](licenses/MIT.txt) license, and each names
its copyright holders in its header or in
[`pkgs/wireguard/REUSE.toml`](pkgs/wireguard/REUSE.toml).
