# The body of the function nfpm wraps it in.
systemctl daemon-reload
echo "barbican: review /etc/barbican/config.toml (its sources), then: systemctl enable --now barbican"
