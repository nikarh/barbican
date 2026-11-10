pre_remove() {
  systemctl disable --now barbican >/dev/null 2>&1 || true
  nft delete table inet barbican >/dev/null 2>&1 || true
}
