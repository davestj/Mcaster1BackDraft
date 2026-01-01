<?php
/**
 * freshclam-status.php — Check ClamAV signature freshness
 * Schedule: Every 6 hours
 */
echo "=== BackDraft ClamAV Signature Status ===\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

// Check signature files
$sig_files = [
    'main.cld' => '/var/lib/clamav/main.cld',
    'daily.cld' => '/var/lib/clamav/daily.cld',
    'bytecode.cld' => '/var/lib/clamav/bytecode.cld',
];

$oldest_age = 0;
foreach ($sig_files as $name => $path) {
    if (file_exists($path)) {
        $age_hours = round((time() - filemtime($path)) / 3600, 1);
        $size_mb = round(filesize($path) / 1048576, 1);
        echo "  {$name}: {$size_mb}MB, {$age_hours}h old\n";
        $oldest_age = max($oldest_age, $age_hours);
    } else {
        echo "  {$name}: MISSING!\n";
        $oldest_age = 99999;
    }
}

// Check freshclam service
$service_status = trim(shell_exec('systemctl is-active clamav-freshclam 2>/dev/null'));
echo "\nfreshclam service: {$service_status}\n";

// Check clamd
$clamd_status = trim(shell_exec('systemctl is-active clamav-daemon 2>/dev/null'));
echo "clamd service: {$clamd_status}\n";

// Get version info
$version = trim(shell_exec('clamscan --version 2>/dev/null'));
echo "Version: {$version}\n";

echo "\nOldest signature: {$oldest_age}h\n";
echo "Status: " . ($oldest_age > 48 ? "WARNING — signatures over 48h old!" : "OK") . "\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";
