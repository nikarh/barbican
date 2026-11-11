---
title: Behind a reverse proxy
description: Serving the UI from a container behind a reverse proxy that authenticates users; the agent's socket, who may use it, and why there is no other way.
sidebar:
  order: 5
---

The UI is full control over the agent: whoever can use it bans, lifts, allows, and changes every rule. It has no login of its own, so it is only ever reachable in two ways, both closed to everything else on the host:

- **The agent's unix socket** (`ui.socket`), where the UI and its API are served. Only root, the agent's own user, and members of the socket's group (`ui.socket_group`, as their primary or a supplementary group) may connect: the socket's directory and the socket itself are that group's alone (modes 2770 and 0660), and the agent checks the credentials of every process that connects (the kernel's `SO_PEERCRED` and `SO_PEERGROUPS`), refusing and logging anyone else whatever the file modes say. There is no TCP listener: a port on the host would be open to every program on it.
- **`barbican ui-proxy` in a container**, which serves the UI to browsers and passes `/api` (the WebSocket included) to the socket. It answers only requests from your reverse proxy's addresses (`--trusted-proxy`, required: it refuses to start without), and with `--user-header` only those naming the user the proxy authenticated. Put it on a network only that reverse proxy reaches, and put the reverse proxy's authentication (forward auth such as Authelia, basic auth) in front of it.

The proxy is supported in a container only. On the host, anything that reaches its port, localhost included, would have the UI; it warns when it doesn't seem to run in a container.

## The agent's socket

```toml title="/etc/barbican/config.toml"
[ui]
socket = "/run/barbican-ui/ui.sock"
socket_group = "barbican-ui"
```

The packages make the group `barbican-ui` and the directory `/run/barbican-ui` (from the archive: `barbican.sysusers` and `barbican.tmpfiles`). The agent makes a new socket each time it starts; a container mounts the directory, not the socket.

From the host itself, as root or a member of `barbican-ui`, you reach the UI without a container through SSH from your machine: OpenSSH forwards a local port to a remote unix socket, and connects as your user, who must be in the group.

```sh
ssh -L 7381:/run/barbican-ui/ui.sock you@server.example.com
# then http://localhost:7381/
```

## The UI container

The image `ghcr.io/nikarh/barbican` (amd64, arm64) runs `barbican ui-proxy`. With Traefik and Authelia's forward auth:

```yaml title="compose.yaml"
services:
  barbican:
    image: ghcr.io/nikarh/barbican:latest
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    user: "65534:65534"
    # The gid of barbican-ui on the host (getent group barbican-ui): the container knows no group names.
    group_add: ["${BARBICAN_UI_GID}"]
    volumes:
      # The directory, not the socket: the agent makes a new socket each time it starts.
      - /run/barbican-ui:/run/barbican-ui:ro
    environment:
      # Only requests Traefik forwarded (its address on the network below), naming the user Authelia authenticated.
      BARBICAN_TRUSTED_PROXIES: 172.30.0.2/32
      BARBICAN_USER_HEADER: Remote-User
    networks:
      barbican: {}
    labels:
      traefik.enable: "true"
      traefik.docker.network: barbican
      traefik.http.routers.barbican.rule: Host(`barbican.example.com`)
      traefik.http.routers.barbican.middlewares: authelia@docker
      traefik.http.services.barbican.loadbalancer.server.port: "8080"

  traefik:
    # ...
    networks:
      barbican:
        ipv4_address: 172.30.0.2

networks:
  # Only Traefik and the UI: no other container reaches it.
  barbican:
    ipam:
      config: [{ subnet: 172.30.0.0/29 }]
```

- **No published port, no host network, no shared IPC.** The container is on a network of its own with the reverse proxy alone; nothing on the host or in other containers reaches port 8080.
- **`BARBICAN_TRUSTED_PROXIES`** (`--trusted-proxy <cidr>`, repeatable; comma-separated in the variable): the reverse proxy's addresses. Required. Give the reverse proxy a fixed address on the network, as above.
- **`BARBICAN_USER_HEADER`** (`--user-header <name>`): only requests carrying this header with a value: the user your reverse proxy authenticated. Authelia's forward auth sets `Remote-User`. Without it, any request from the trusted addresses passes, authenticated or not; set it whenever your proxy names the user.
- `read_only`, `cap_drop: [ALL]`, `no-new-privileges`: the image is one static binary (`FROM scratch`) that writes nothing and needs no privileges.
- `user`: any uid works; `group_add` is what grants the socket. Connecting to a socket on a read-only mount works.
- It listens on 8080 (`--listen <address>`), for the agent's socket at `/run/barbican-ui/ui.sock` (`--socket <path>`). `/healthz` answers anyone while the proxy runs: the image's healthcheck (`barbican healthcheck`) asks it.
- While the agent can't be reached (stopped, restarting, a missing socket or one the container may not use) the API answers 502, the UI says so and why, and it reconnects on its own. The reason is what the proxy answers on `/api/proxy` (JSON: the socket, and the error with what to check).

The UI is a single page and one WebSocket (`/api/ws`), and works under a path prefix. The agent also refuses a WebSocket whose `Origin` doesn't match `Host` (or `X-Forwarded-Host`): another site can't use a signed-in browser's cookies to reach it. The proxy passes the browser's headers through unchanged.
