"""
policy.py
---------
Simple defensive policy configuration - when to automatically block a
sustained attacker instead of waiting for a manual click on the
dashboard.

Kept as plain constants for a 3-day prototype. In a larger build this
would move to config/defender.yaml alongside the other settings.
"""

AUTO_BLOCK_ENABLED = True

# If the same attacker (by MAC) has been continuously sending forged
# ARP packets for at least this many seconds, block them automatically.
AUTO_BLOCK_AFTER_SECONDS = 90  # 1.5 minutes
