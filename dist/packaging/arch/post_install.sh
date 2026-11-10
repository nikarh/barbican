post_install() {
  systemctl daemon-reload
  echo "barbican: review /etc/barbican/config.toml (its sources), then: systemctl enable --now barbican"
}
