#!/usr/bin/env bash
# Disposable VMs for the end-to-end tests: a Debian server and an OpenWrt router.
#
# QEMU/KVM runs as the current user. Each VM reaches the host only through user-mode networking (for SSH), so
# nothing on the host (firewall, network, packages) is touched. A second network, a UDP tunnel between the two
# QEMUs on 127.0.0.1, joins the VMs: the server is 10.99.0.1, the router 10.99.0.2.
#
#   e2e/vm.sh <server|router> up        boot the VM on a fresh disk, wait until it is ready
#   e2e/vm.sh <server|router> ssh ...   run a command in the VM, or open a shell
#   e2e/vm.sh <server|router> put <local> <remote>   copy a file into the VM
#   e2e/vm.sh <server|router> down      stop the VM (its disk is thrown away)
#   e2e/vm.sh <server|router> destroy   stop the VM and delete its images
#
# Each boot starts from an image, on a throwaway disk. The server's image is provisioned once (cloud-init installs
# the packages and Docker, a minute or two) and kept as server-<hash of the provisioning>.qcow2; a change to the
# provisioning makes a new one.
#
# Needs qemu-system-x86_64, qemu-img, genisoimage (or mkisofs), ssh, curl, and read/write access to /dev/kvm.
set -euo pipefail

STATE_DIR="${BARBICAN_VM_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/barbican-e2e}"
DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
OPENWRT_VERSION="25.12.6"
OPENWRT_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
OPENWRT_SHA256="f8538784d0288b4133a99ac2a68443e4922ffde6343e80df56a5882364b9d499"
KEY="${STATE_DIR}/id_ed25519"
# The tunnel between the VMs: each QEMU sends to the other's port.
LINK_SERVER_PORT="${BARBICAN_VM_LINK_PORT:-4471}"
LINK_ROUTER_PORT="$((LINK_SERVER_PORT + 1))"

vm="${1:-}"
cmd="${2:-}"
case "${vm}" in
  server)
    SSH_PORT="${BARBICAN_VM_SERVER_SSH_PORT:-2231}"
    SSH_USER=debian
    MEMORY="${BARBICAN_VM_SERVER_MEMORY:-2G}"
    CPUS="${BARBICAN_VM_SERVER_CPUS:-2}"
    ;;
  router)
    SSH_PORT="${BARBICAN_VM_ROUTER_SSH_PORT:-2232}"
    SSH_USER=root
    MEMORY=256M
    CPUS=1
    ;;
  *)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
DIR="${STATE_DIR}/${vm}"
DISK="${DIR}/disk.qcow2"
PIDFILE="${DIR}/qemu.pid"
CONSOLE_LOG="${DIR}/console.log"

ssh_opts=(
  -i "${KEY}"
  -p "${SSH_PORT}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o IdentitiesOnly=yes
  -o ConnectTimeout=5
)

log() { printf '[vm %s] %s\n' "${vm}" "$*" >&2; }

is_running() {
  [[ -f "${PIDFILE}" ]] && kill -0 "$(cat "${PIDFILE}")" 2>/dev/null
}

vm_ssh() {
  ssh "${ssh_opts[@]}" "${SSH_USER}@127.0.0.1" "$@"
}

download() { # url file [sha256]
  [[ -f "$2" ]] && return
  log "downloading $1"
  curl -fL --progress-bar -o "$2.part" "$1"
  if [[ -n "${3:-}" ]]; then
    echo "$3  $2.part" | sha256sum -c --quiet
  fi
  mv "$2.part" "$2"
}

server_user_data() {
  cat <<EOF
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${KEY}.pub")
package_update: true
packages:
  - conntrack
  - curl
  - iproute2
  - ipset
  - jq
  - nftables
  - openssl
  - python3
  - socat
  - sqlite3
runcmd:
  - curl -fsSL https://get.docker.com | sh
  - usermod -aG docker debian
  # The image of the server suite's container.
  - docker pull alpine:3
  - apt-get clean
  - touch /var/lib/barbican-e2e-ready
EOF
}

# The provisioned image, named by what provisioning does (and the key it lets in).
server_image() {
  local hash
  hash=$(server_user_data | sha256sum | cut -c1-16)
  echo "${STATE_DIR}/server-${hash}.qcow2"
}

# cloud-init's seed: on the provisioned image the same instance, so it does nothing again.
server_seed() {
  local seed_dir="${DIR}/seed"
  mkdir -p "${seed_dir}"
  printf 'instance-id: barbican-e2e\nlocal-hostname: barbican-e2e\n' >"${seed_dir}/meta-data"
  server_user_data >"${seed_dir}/user-data"
  local mkiso
  mkiso="$(command -v genisoimage || command -v mkisofs)"
  "${mkiso}" -quiet -output "${DIR}/seed.iso" -volid cidata -joliet -rock \
    "${seed_dir}/user-data" "${seed_dir}/meta-data"
}

# Boots the Debian cloud image once with cloud-init, and keeps the result as the server's image.
provision_server() {
  local image base="${STATE_DIR}/debian-13-genericcloud-amd64.qcow2"
  image=$(server_image)
  download "${DEBIAN_URL}" "${base}"
  log "provisioning ${image##*/} (a minute or two, once)"
  qemu-img create -q -f qcow2 -F qcow2 -b "${base}" "${DISK}" 20G
  boot
  wait_ready 900
  # Unused blocks discarded, so that the image is only what is in it.
  vm_ssh 'sudo fstrim -a && sudo poweroff' 2>/dev/null || true
  wait_exit 120 || { log "didn't power off; see ${CONSOLE_LOG}"; exit 1; }
  rm -f "${STATE_DIR}"/server-*.qcow2
  qemu-img convert -q -f qcow2 -O qcow2 "${DISK}" "${image}.part"
  mv "${image}.part" "${image}"
  rm -f "${DISK}"
  log "provisioned"
}

create_router() {
  local base="${STATE_DIR}/openwrt-${OPENWRT_VERSION}.img"
  if [[ ! -f "${base}" ]]; then
    download "${OPENWRT_URL}" "${base}.gz" "${OPENWRT_SHA256}"
    # The image has padding after the compressed data, which gzip warns about (exit status 2).
    gzip -dc "${base}.gz" >"${base}.part" || [[ $? -eq 2 ]]
    mv "${base}.part" "${base}"
  fi
  qemu-img create -q -f qcow2 -F raw -b "${base}" "${DISK}" 512M
}

create_server() {
  local image
  image=$(server_image)
  [[ -f "${image}" ]] || provision_server
  qemu-img create -q -f qcow2 -F qcow2 -b "${image}" "${DISK}" 20G
}

boot() {
  local args=(
    -name "barbican-e2e-${vm}"
    -machine q35,accel=kvm
    -cpu host
    -smp "${CPUS}"
    -m "${MEMORY}"
    -drive "file=${DISK},if=virtio,discard=unmap"
    -display none
    -serial "file:${CONSOLE_LOG}"
    -daemonize
    -pidfile "${PIDFILE}"
  )
  if [[ "${vm}" == server ]]; then
    server_seed
    args+=(
      -drive "file=${DIR}/seed.iso,if=virtio,media=cdrom"
      -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
      -device virtio-net-pci,netdev=mgmt
      -netdev "dgram,id=link,local.type=inet,local.host=127.0.0.1,local.port=${LINK_SERVER_PORT},remote.type=inet,remote.host=127.0.0.1,remote.port=${LINK_ROUTER_PORT}"
      -device virtio-net-pci,netdev=link,mac=52:54:00:99:00:01
    )
  else
    # OpenWrt's first interface is its LAN (192.168.1.1), where SSH is allowed; the second is its WAN.
    args+=(
      -netdev "user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:${SSH_PORT}-192.168.1.1:22"
      -device virtio-net-pci,netdev=lan
      -netdev "dgram,id=link,local.type=inet,local.host=127.0.0.1,local.port=${LINK_ROUTER_PORT},remote.type=inet,remote.host=127.0.0.1,remote.port=${LINK_SERVER_PORT}"
      -device virtio-net-pci,netdev=link,mac=52:54:00:99:00:02
    )
  fi
  log "booting (console log: ${CONSOLE_LOG})"
  qemu-system-x86_64 "${args[@]}"
}

wait_ready() { # <seconds>
  local deadline=$((SECONDS + $1))
  until ready; do
    if ((SECONDS > deadline)); then
      log "timed out; see ${CONSOLE_LOG}"
      exit 1
    fi
    if ! is_running; then
      log "VM exited; see ${CONSOLE_LOG}"
      exit 1
    fi
    sleep 1
  done
}

wait_exit() { # <seconds>: until QEMU has exited
  local pid deadline=$((SECONDS + $1))
  pid="$(cat "${PIDFILE}" 2>/dev/null)" || return 0
  while kill -0 "${pid}" 2>/dev/null; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
  rm -f "${PIDFILE}"
}

up() {
  mkdir -p "${DIR}"
  # Both VMs may boot at once.
  (
    flock 9
    [[ -f "${KEY}" ]] || ssh-keygen -q -t ed25519 -N '' -f "${KEY}"
  ) 9>"${STATE_DIR}/.key.lock"
  if is_running; then
    log "already running"
  else
    rm -f "${DISK}"
    "create_${vm}"
    boot
  fi
  log "waiting until it is ready"
  wait_ready 300
  log "ready"
}

ready() {
  if [[ "${vm}" == server ]]; then
    vm_ssh test -f /var/lib/barbican-e2e-ready 2>/dev/null
  else
    router_ready
  fi
}

# A fresh OpenWrt lets root in over SSH without a password; the first connection installs the key and sets the
# WAN up on the link to the server.
router_ready() {
  if ! vm_ssh true 2>/dev/null; then
    local plain=(-p "${SSH_PORT}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
      -o ConnectTimeout=5 -o PubkeyAuthentication=no -o PasswordAuthentication=no
      -o KbdInteractiveAuthentication=no)
    ssh "${plain[@]}" root@127.0.0.1 \
      "cat > /etc/dropbear/authorized_keys && chmod 600 /etc/dropbear/authorized_keys" <"${KEY}.pub" 2>/dev/null ||
      return 1
    vm_ssh true 2>/dev/null || return 1
  fi
  vm_ssh 'if [ "$(uci -q get network.wan.ipaddr)" != 10.99.0.2 ]; then
      uci set network.wan.proto=static
      uci set network.wan.ipaddr=10.99.0.2
      uci set network.wan.netmask=255.255.255.0
      uci -q delete network.wan6
      uci commit network
      /etc/init.d/network reload
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do ip -4 addr show dev eth1 | grep -q 10.99.0.2 && exit 0; sleep 1; done
    exit 1' 2>/dev/null
}

put() {
  # OpenWrt has no sftp server: copy over a plain ssh pipe.
  vm_ssh "cat > '$2'" <"$1"
}

down() {
  if is_running; then
    # The disk is thrown away: no need to shut down cleanly.
    local pid
    pid="$(cat "${PIDFILE}")"
    kill "${pid}" 2>/dev/null || true
    wait_exit 10 || kill -9 "${pid}" 2>/dev/null || true
    log "stopped"
  fi
  rm -f "${PIDFILE}" "${DISK}"
}

destroy() {
  down
  rm -rf "${DIR}"
  if [[ "${vm}" == server ]]; then
    rm -f "${STATE_DIR}"/server-*.qcow2
  fi
  log "images deleted (the downloads are kept in ${STATE_DIR})"
}

case "${cmd}" in
  up) up ;;
  ssh) shift 2; vm_ssh "$@" ;;
  put) put "$3" "$4" ;;
  down) down ;;
  destroy) destroy ;;
  *)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
