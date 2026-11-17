# Outline split

A local app for an Outline (Shadowsocks) access key. You save the key, destination addresses, domains, and applications. Listed addresses and domains go through the tunnel from every program. A selected application sends its traffic through the tunnel, except addresses on the local network. Everything else keeps its normal route.

Open **Outline split** from the app grid. The window has a connect switch, and the same switch is on the top bar. Turn on **Tunnel all traffic** to send every connection through the tunnel except addresses on this machine's local network. With that off, only the destinations, domains, and applications you add are tunneled.

The first time you connect, Ubuntu asks for your password. That starts the tunnel service. Closing the window leaves the icon on the top bar. Quit from that icon turns the tunnel off.

Disconnect the Outline desktop app before you connect. It installs a default route of its own.

```bash
python3 /home/sungs/bsuir/vpn/app/desktop.py
```

## Docker

The browser page is still available if you run the container. It listens on loopback only, at [http://127.0.0.1:8787](http://127.0.0.1:8787). Starting the desktop app stops that container, because both use the `outline0` interface.

```bash
docker-compose up -d --build
```

Check one listed address:

```bash
ip route get 203.0.113.10
```

When that address is in the list, the route uses `outline0`. An address that is not in the list stays on the normal gateway. The tunnel routes live in table `20819`:

```bash
ip route show table 20819
```

Stop the tunnel from the page, or stop the container:

```bash
docker-compose stop
```

`docker-compose stop` removes the routes. `docker-compose start` brings back the last saved list.

## What you can set

- **Access keys.** Add more than one Shadowsocks key and choose which one the tunnel uses. The choice is in the window and under Key on the top-bar icon. **Add VPNBook keys** reads the free Outline keys from VPNBook. Press it again after VPNBook changes the keys: each server is refreshed in place, and the tunnel reconnects when the key in use changed.
- **Tunnel all traffic.** Sends every connection through the tunnel except the local network and the tunnel server. Turn it off to go back to the destination list and selected applications.
- **Shadowsocks key.** An Outline `ss://` access key. Newer keys include a `prefix`. The app keeps that prefix and writes it on the TCP connection before the Shadowsocks bytes. The password is stored in `data/state.json` and is not printed back.
- **Destination list.** IPv4 or IPv6 addresses and networks, such as `203.0.113.10` or `203.0.113.0/24`. Traffic is chosen by destination IP.
- **Domains.** A name such as `example.com`. That name and its subdomains go through the tunnel from every program. Other names stay on the normal route. A browser that uses its own secure DNS, instead of the system resolver, can skip this list.
- **Applications.** Pick an installed program, or type an absolute path such as `/usr/bin/firefox`. Matching processes are placed in the `outline-split` cgroup. Their packets are marked and sent through `outline0`. Local-network addresses and the tunnel server stay on the normal route.

The server address itself stays on the normal route so the tunnel can connect.

## Limits

Routes are added on the host. Programs on the host follow them. A container on a Docker bridge has its own routing table, so it keeps the normal path unless it uses host networking.

`0.0.0.0/0` or `::/0` sends all traffic of that family through the tunnel. The page asks before applying a default route.

The key file is `data/state.json`. `data/` is not meant to be committed.
