# NetWatch.ps1
# Network & Security Toolkit - NetWatch
# Encoding: UTF-8

chcp 65001
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# =============================================
# ASCII
# =============================================
function Show-ASCII {
@"
................................:::......:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
................................:--......::::-#=::::::=#-::::::::::=-:::::::::::::::::::::::::::::::
...............................:#%#=......::::%#*::::*#%::::::::::=%%#::::::::::::::::::::::::::::::
..............................=##%###-....::::::::::::::::::::::-#%%%%%=::::::::::::::::::::::::::::
.............................*%%%%%#%###*+=::::=*%%#%*=::::=+*#%%%%%%%%%*:::::::::::::::::::::::::::
............................+%#=.....=##%%-.:-#%%%%%%%%#-::-%%%#+:::::=#%*::::::::::::::::::::::::::
...........................=#:.........-#-..-%%%%%%%#%%%#=::-#=:::::::::-#+:::::::::::::::::::::::::
..........................:+...............:%%%%%%%%%%##%%-:::::::::::::::+-::::::::::::::::::::::::
..........................:................*%%%%%%%%%%%%%%*::::::::::::::::-::::::::::::::::::::::::
.......................................-..:#%#*=:.....-*%%#::.-:::::::::::::::::::::::::::::::::::::
....................................:+#+..:##:..:=%%+...:*#:..*%*:::::::::::::::::::::::::::::::::::
...............................:=*##%##*...*=...:####:...=#:..*###%##=::::::::::::::::::::::::::::::
..............................%###=........+#+...:==:...=#+......::+#%%%::::::::::::::::::::::::::::
.............................:%##-..........#%##=----=*%%#:.........-#%%::::::::::::::::::::::::::::
..............................%#+.......::..:#%%%%#%#%###:..:-......:+%#::::::::::::::::::::::::::::
..............................*#-......-##:...*%%%#####*:..:#%-......-%*::::::::::::::::::::::::::::
..............................-%:....-*###-:...:=*##*=....:-#%%*-....:%=::::::::::::::::::::::::::::
..............................:#:...:####-..................-%%%#::..:#:::::::::::::::::::::::::::::
...............................--....+###-..................-%##*.::.=-.::.:::::::::::::::::::::::::
......................................###-..................-%##:.::.:..::::::::::::::::::::::::::::
......................................-##=..................=%#=..:::...::::::::::::::::::::::::::::
.......................................*#+..................+#*:..:.:::::::.::::::::::::::::::::::::
.......................................:##..................#%:....:::::::::::::::::::::::::::::::::
........................................-%=................=%=......::::::::.:::::::::::::::::::::::
.........................................+*:..............:**:..::::::::::::::::::::::::::::::::::::
..........................................*=..............=*.......:::::::::.:::::::::::::::::::::::
..........................................:#:............:#:.....::::::::::::..:::::::::::::::::::::
...........................................:*:...........*:......:::::::::::...:::::::::::::::::::::
............................................:=..........=:.....:::::::::::::....::::::::::::::::::::
..............................................-........-.......:.::::::::::.....::::::::::::::::::::
"@ | ForEach-Object { Write-Host $_ -ForegroundColor Blue }
}

# =============================================
# Alternância de cores
# =============================================
$Global:ColorToggle = $true

function Write-Option {
    param([string]$Text)

    if ($Global:ColorToggle) {
        Write-Host $Text -ForegroundColor Cyan
        $Global:ColorToggle = $false
    } else {
        Write-Host $Text -ForegroundColor Blue
        $Global:ColorToggle = $true
    }
}

function Read-Option {
    param([string]$Prompt = "Escolha")

    if ($Global:ColorToggle) {
        $color = "Cyan"
        $Global:ColorToggle = $false
    } else {
        $color = "Blue"
        $Global:ColorToggle = $true
    }

    Write-Host ""
    Write-Host -NoNewline "$Prompt : " -ForegroundColor $color
    return (Read-Host)
}

# =============================================
# Executor de comandos
# =============================================
function Execute-Command {
    param(
        [string]$Command,
        [string]$LogFilePrefix = "log"
    )

    try {
        $output = Invoke-Expression $Command 2>&1 | Out-String
    } catch {
        $output = $_.Exception.Message
    }

    Write-Host "`n===== RESULTADO =====" -ForegroundColor Green
    Write-Host $output

    $logChoice = Read-Option "Deseja gerar log? (s/n)"

    if ($logChoice -and $logChoice.ToLower() -eq "s") {
        $dir = "$env:USERPROFILE\NetWatch_Logs"
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory | Out-Null }

        $file = "$dir\$LogFilePrefix-$(Get-Date -Format yyyyMMdd_HHmmss).txt"
        $output | Out-File $file -Encoding UTF8

        Write-Host "Log salvo em: $file" -ForegroundColor Yellow
    }

    Read-Host "Pressione Enter para continuar..."
}

# =============================================
# TELNET EM NOVA JANELA (NOVO)
# =============================================
function Start-TelnetWindow {
    param([string]$HostPort)

    $cmd = "telnet $HostPort"
    Start-Process powershell.exe -ArgumentList "-NoExit","-Command $cmd"
}

# =============================================
# MENU PRINCIPAL
# =============================================
function Show-MainMenu {
    Clear-Host
    Show-ASCII
    $Global:ColorToggle = $true

    Write-Option ""
    Write-Option "==================================================="
    Write-Option "                 NetWatch"
    Write-Option "==================================================="
    Write-Option "1 - Redes"
    Write-Option "2 - Sec Defensiva"
    Write-Option "3 - Auditoria"
    Write-Option "4 - Threat Hunting"
    Write-Option "5 - Windows Defender"
    Write-Option "6 - Captura de Pacotes (Pktmon)"
    Write-Option "0 - Sair"
}

# =============================================
# MENU REDES
# =============================================
function Show-NetworkMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------------- REDES -------------"
        Write-Option "1 - Ping"
        Write-Option "2 - Ping Infinito"
        Write-Option "3 - Traceroute"
        Write-Option "4 - Nslookup"
        Write-Option "5 - Resolve DNS"
        Write-Option "6 - Telnet (Nova Janela)"
        Write-Option "7 - Netstat -a"
        Write-Option "8 - Netstat -b"
        Write-Option "9 - Netstat -n"
        Write-Option "10 - Ping multiplos hosts"
        Write-Option "11 - Ipconfig renew/release"
        Write-Option "12 - Ipconfig flushdns"
        Write-Option "0 - Voltar"

        $c = Read-Option "Escolha"

        switch ($c) {
            "1" { $h = Read-Option "Host/IP"; Execute-Command "ping $h" "ping" }
            "2" { $h = Read-Option "Host/IP"; Execute-Command "ping -t $h" "ping_t" }
            "3" { $h = Read-Option "Host/IP"; Execute-Command "tracert $h" "tracert" }
            "4" { $h = Read-Option "Host/IP"; Execute-Command "nslookup $h" "nslookup" }
            "5" { $h = Read-Option "DNS"; Execute-Command "Resolve-DnsName -Name $h" "dns" }
            "6" { 
                $h = Read-Option "Host/IP:Porta"
                Start-TelnetWindow $h
            }
            "7" { Execute-Command "netstat -a" }
            "8" { Execute-Command "netstat -b" }
            "9" { Execute-Command "netstat -n" }
            "10" {
                $list = Read-Option "Hosts separados por vírgula"
                ($list -split ",") | ForEach-Object {
                    Execute-Command "ping $($_.Trim()) -n 4"
                }
            }
            "11" {
                Execute-Command "ipconfig /release"
                Execute-Command "ipconfig /renew"
            }
            "12" {
                Execute-Command "ipconfig /flushdns"
            }
            "0" { return }
        }
    }
}

# =============================================
# SEGURANÇA DEFENSIVA
# =============================================
function Show-SecDefensivaMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------ SEG DEFENSIVA ------"
        Write-Option "1 - Portas TCP"
        Write-Option "2 - Firewall status"
        Write-Option "3 - Regras Firewall"
        Write-Option "4 - Políticas Firewall"
        Write-Option "5 - SMBv1"
        Write-Option "6 - Serviços inseguros"
        Write-Option "7 - RDP ativo?"
        Write-Option "8 - NLA do RDP"
        Write-Option "9 - Portas + processos"
        Write-Option "10 - Hash SHA256"
        Write-Option "0 - Voltar"

        $c = Read-Option "Escolha"

        switch ($c) {
            "1" { Execute-Command "Get-NetTCPConnection | Format-Table -AutoSize" }
            "2" { Execute-Command "Get-NetFirewallProfile | ft -AutoSize" }
            "3" { Execute-Command "Get-NetFirewallRule | ? Enabled -eq True | ft -AutoSize" }
            "4" { Execute-Command "Get-NetFirewallProfile | ft -AutoSize" }
            "5" { Execute-Command "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" }
            "6" { Execute-Command "Get-Service | ? Name -match 'telnet|ftp|upnp|RemoteRegistry'" }
            "7" { Execute-Command '(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections' }
            "8" { Execute-Command '(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication' }
            "9" { Execute-Command "Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ft -AutoSize" }
            "10" { 
                $p = Read-Option "Caminho do arquivo"
                Execute-Command "Get-FileHash -Path `"$p`" -Algorithm SHA256"
            }
            "0" { return }
        }
    }
}

# =============================================
# AUDITORIA
# =============================================
function Show-AuditoriaMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------ AUDITORIA ------"
        Write-Option "1 - Logs 4625"
        Write-Option "2 - Firewall Log"
        Write-Option "3 - Executáveis recentes Downloads"
        Write-Option "0 - Voltar"

        $c = Read-Option "Escolha"
        switch ($c) {
            "1" { Execute-Command 'Get-WinEvent -LogName Security -FilterXPath "*[System/EventID=4625]" -MaxEvents 30' }
            "2" { Execute-Command 'Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"' }
            "3" { Execute-Command 'Get-ChildItem "$env:USERPROFILE\Downloads" | ? { $_.Extension -match "exe|ps1|bat" } | sort LastWriteTime -Desc' }
            "0" { return }
        }
    }
}

# =============================================
# THREAT HUNTING
# =============================================
function Show-ThreatMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------ THREAT HUNTING ------"
        Write-Option "1 - Live TCP Monitor"
        Write-Option "2 - Top CPU"
        Write-Option "0 - Voltar"

        switch (Read-Option "Escolha") {
            "1" {
                Write-Host "Ctrl+C para parar" -ForegroundColor Yellow
                try {
                    while ($true) {
                        Clear-Host
                        Show-ASCII
                        Get-NetTCPConnection -State Established | ft -AutoSize
                        Start-Sleep 2
                    }
                } catch {}
            }
            "2" { Execute-Command 'Get-Process | sort CPU -Desc | select -First 15' }
            "0" { return }
        }
    }
}

# =============================================
# WINDOWS DEFENDER
# =============================================
function Show-DefenderMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------ WINDOWS DEFENDER ------"
        Write-Option "1 - Status"
        Write-Option "2 - Quarentena"
        Write-Option "3 - Scan rápido"
        Write-Option "0 - Voltar"

        switch (Read-Option "Escolha") {
            "1" { Execute-Command "Get-MpComputerStatus" }
            "2" { Execute-Command "Get-MpThreat" }
            "3" { Execute-Command "Start-MpScan -ScanType QuickScan" }
            "0" { return }
        }
    }
}

# =============================================
# PKTMON
# =============================================
function Show-PktmonMenu {
    while ($true) {
        Clear-Host
        Show-ASCII
        $Global:ColorToggle = $true

        Write-Option "`n------ PKTMON ------"
        Write-Option "1 - Iniciar Captura"
        Write-Option "2 - Parar Captura"
        Write-Option "3 - Converter ETL → PCAPNG"
        Write-Option "0 - Voltar"

        switch (Read-Option "Escolha") {
            "1" { Execute-Command "pktmon start --capture --pkt-size 0" }
            "2" { Execute-Command "pktmon stop" }
            "3" {
                $etl = Read-Option "Arquivo ETL"
                $out = Read-Option "Arquivo PCAPNG"
                Execute-Command "pktmon etl2pcap `"$etl`" --out `"$out`""
            }
            "0" { return }
        }
    }
}

# =============================================
# LOOP PRINCIPAL
# =============================================
function Start-Toolkit {
    while ($true) {
        Show-MainMenu
        $choice = Read-Option "Escolha"
        switch ($choice) {
            "1" { Show-NetworkMenu }
            "2" { Show-SecDefensivaMenu }
            "3" { Show-AuditoriaMenu }
            "4" { Show-ThreatMenu }
            "5" { Show-DefenderMenu }
            "6" { Show-PktmonMenu }
            "7" { Show-SecOfensivaMenu }
            "0" { Write-Option "Saindo..."; return }
        }
    }
}

Start-Toolkit
