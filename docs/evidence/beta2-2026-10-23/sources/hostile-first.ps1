$ErrorActionPreference='Stop'
$d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
$record=[ordered]@{case='wifi-hostile-first';result='incomplete';started_utc=[DateTime]::UtcNow.ToString('o');phone_observation='pending'}
$client=$null
try {
    $devices=@(& adb devices | Where-Object {$_ -match '^\S+\s+device$'})
    if($devices.Count -ne 1){throw 'device precondition'}
    $route=(& adb shell ip -4 route show dev wlan0) -join ' '
    $m=[regex]::Match($route,'\bsrc\s+(\d+\.\d+\.\d+\.\d+)')
    if(-not $m.Success){throw 'route precondition'}
    $ip=[Net.IPAddress]::Parse($m.Groups[1].Value)
    $b=$ip.GetAddressBytes()
    if(-not ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))){throw 'private address precondition'}
    $client=[Net.Sockets.TcpClient]::new()
    $client.ConnectAsync($ip,47140).WaitAsync([TimeSpan]::FromSeconds(5)).GetAwaiter().GetResult()
    $stream=$client.GetStream(); $stream.ReadTimeout=10000; $stream.WriteTimeout=5000
    # Deliberately invalid fixed header; no protocol payload, identity or key material.
    $invalid=[byte[]]::new(28)
    $stream.Write($invalid,0,$invalid.Length)
    $stream.Flush()
    $record.invalid_header_sent=$true
    try {
        $byte=$stream.ReadByte()
        if($byte -ne -1){throw 'unexpected response'}
        $record.peer_result='closed-without-response'
    } catch [IO.IOException] {
        $inner=$_.Exception.InnerException
        if($inner -isnot [Net.Sockets.SocketException] -or $inner.SocketErrorCode -ne [Net.Sockets.SocketError]::ConnectionReset){throw}
        $record.peer_result='reset-without-response'
    }
    $record.result='automated-checks-passed-awaiting-observation'
} catch {
    $record.result='failed'; $record.failure_category='connection-or-rejection-check-failed'
} finally {
    if($null -ne $client){$client.Dispose()}
    $record.finished_utc=[DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json | Set-Content (Join-Path $d ('wifi-hostile-first-'+[Guid]::NewGuid().ToString('N')+'.json'))
}
$record | ConvertTo-Json
if($record.result -eq 'failed'){exit 1}
