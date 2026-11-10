# End-to-end tests

Two suites check what barbican does to real traffic, in throwaway VMs under QEMU: the host's firewall and network
are never touched.

```sh
e2e/run.sh                # both suites
e2e/run.sh server         # one of them
KEEP_VM=1 e2e/run.sh      # leave the VMs running afterwards
```

The host needs `qemu-system-x86_64`, `qemu-img`, `genisoimage` (or `mkisofs`), `ssh`, `curl` and read/write access to
`/dev/kvm`, and mise's tools (zig and cargo-zigbuild build static binaries). The first run downloads a Debian cloud
image, OpenWrt's x86-64 image and DB-IP's country database, into `~/.cache/barbican-e2e`, and provisions the server's
image there (cloud-init installs the packages and Docker, a minute or two): `server-<hash>.qcow2`, made again when the
provisioning in `vm.sh` changes. Each run boots both VMs from their images on throwaway disks, while the binaries
build. CI runs the same on a GitHub runner with KVM, with the images cached.

`e2e/vm.sh <server|router> <up|ssh|put|down|destroy>` manages one VM. The two are joined by a UDP tunnel between their
QEMUs: the server is 10.99.0.1, the router's WAN 10.99.0.2. Each is reached over SSH through user-mode networking.

## The server suite (`server.sh`)

Runs in the Debian VM as root. Attackers live in network namespaces: `att` with 203.0.113.10 and 1.0.1.10 (an
address the country database puts in China), `by` (a bystander) with 198.51.100.10. barbican runs as the systemd
service, as packaged (its own user, `CAP_NET_ADMIN`), reading a Traefik access log (a file), the journal and a
container's log. It checks that:

- the table is in place when the service reports ready, and the agent doesn't run as root;
- a probe bans its address within seconds, bystanders get through, and replies to the host's own connections to a
  banned address still pass;
- lifting works, and the allow list beats the rules;
- thresholds count (one unknown user from the journal isn't enough, two are), and a container's log is read;
- a blocked country is dropped (thousands of prefixes) and unblocking works;
- bans run out in the kernel with the agent stopped;
- after a reboot (the table deleted), the blocks are back by the time the agent reports ready;
- the edge API refuses requests without a token, and gives an edge the whole state;
- with the UI on a unix socket, the image's UI proxy, run read-only, without capabilities, as nobody with the
  `barbican-ui` group, serves the UI and reaches the agent (bans and lifts through it, also after the agent
  restarts), the Origin check still holds, and a container without the group is refused.

## The router suite (`router.sh`)

Runs from the host after the server suite: barbican-edge and its LuCI pages are installed in the OpenWrt VM and
follow the server's agent. The attacker is 203.0.113.77 on the server's link to the router; probes are pings to the
router's WAN address. It checks that a ban reaches the router and is dropped there for that address only, that a lift
reaches it within the long poll, that after a reboot with the agent down the blocks are back, and that it follows
the agent again once it returns. It checks that the LuCI views are served too.
