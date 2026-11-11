# The body of the function nfpm wraps it in.
systemctl daemon-reload
# A running agent restarts with the new version (its UI too); its blocks stay in place meanwhile.
systemctl try-restart barbican
