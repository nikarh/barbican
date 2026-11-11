---
title: Behind a reverse proxy
description: Serving the UI behind a reverse proxy with authentication, from the host or from a container next to your other services.
sidebar:
  order: 5
---

The UI has no login of its own. Put it behind your reverse proxy's authentication (forward auth such as Authelia, basic auth) or a VPN, and keep `ui.listen` on an address only the proxy reaches: localhost, a private address, or a Docker bridge's address.

The UI is a single page and one WebSocket (`/api/ws`), and works under a path prefix. The WebSocket is refused when its `Origin` doesn't match `Host` (or `X-Forwarded-Host`): another site can't use a signed-in browser's cookies to reach it. Clients that send no `Origin` (scripts, not browsers) aren't checked.

## Traefik, with the agent on the host

With Traefik in Docker and barbican on the host, a route of the file provider does it:

```yaml title="dynamic/barbican.yml"
http:
  routers:
    barbican:
      rule: Host(`barbican.example.com`)
      service: barbican
      middlewares: [auth]
  services:
    barbican:
      loadBalancer:
        servers:
          - url: http://172.17.0.1:7381   # ui.listen on the docker0 address
```

with `listen = "172.17.0.1:7381"` under `[ui]`, and `auth` a middleware of yours (forward auth, basic auth). The agent starts before Docker; it listens once the address exists.

Any other proxy works the same way: pass `/` and the WebSocket upgrade of `/api/ws` to `ui.listen`, and keep the `Host` header (or set `X-Forwarded-Host`).

## The UI in a container

The agent has to run on the host (it changes the host's firewall, early in boot), but the UI can be a container next to your other ones, routed and authenticated like them. The agent then serves the UI's API on a unix socket instead of a port, and the image `ghcr.io/nikarh/barbican` (amd64, arm64) runs `barbican ui-proxy`: it serves the UI and passes `/api` (the WebSocket included) to the socket. Nothing listens on a port of the host.

The socket's directory, `/run/barbican-ui`, and the socket belong to the group `barbican-ui` (both made by the packages; modes 2770 and 0660), so only containers given that group can use it.

```toml title="/etc/barbican/config.toml"
[ui]
socket = "/run/barbican-ui/ui.sock"
socket_group = "barbican-ui"
```

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
    labels:
      traefik.enable: "true"
      traefik.http.routers.barbican.rule: Host(`barbican.example.com`)
      traefik.http.routers.barbican.middlewares: auth
      traefik.http.services.barbican.loadbalancer.server.port: "8080"
```

- `read_only`, `cap_drop: [ALL]`, `no-new-privileges`: the image is one static binary (`FROM scratch`) that writes nothing and needs no privileges.
- `user`: any uid works; `group_add` is what grants the UI. Connecting to a socket on a read-only mount works.
- It listens on 8080 (`barbican ui-proxy --listen <address>`), for the agent's socket at `/run/barbican-ui/ui.sock` (`--socket <path>`). `/healthz` answers while the proxy runs, and the image's healthcheck (`barbican healthcheck`) asks it.
- While the agent can't be reached (stopped, restarting, a missing socket or one the container may not use) the API answers 502, the UI says so and why, and it reconnects on its own. The reason is what the proxy answers on `/api/proxy` (JSON: the socket, and the error with what to check), which works with `curl` too.
- The `Origin` check is the agent's, on the headers the browser sent: the proxy passes them through unchanged.

Installed from the [archive](/install/linux/), the group and the directory come from `barbican.sysusers` and `barbican.tmpfiles`.
