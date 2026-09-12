# reset_demo.ps1
# ---------------
# Windows equivalent of reset_demo.sh. Run this between practice runs
# so leftover firewall block rules and ARP entries from a previous
# session don't make the next demo look like "nothing is happening".
#
# Run from an Administrator PowerShell:
#   .\reset_demo.ps1

Write-Host "Resetting ARP Guard demo environment (Windows)..."

$rules = Get-NetFirewallRule -DisplayName "ARPGuard_*" -ErrorAction SilentlyContinue
if ($rules) {
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) ARP Guard firewall rule(s)."
} else {
    Write-Host "No ARP Guard firewall rules to remove."
}

arp -d * 2>$null
Write-Host "ARP cache cleared."

Write-Host ""
Write-Host "Done. Run the agent from an Administrator terminal with:"
Write-Host "    python main.py"
