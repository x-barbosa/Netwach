# NetWatch

## 📌 Visão Geral

**NetWatch** é um toolkit em **PowerShell** criado para centralizar, em um único menu interativo, diversas ferramentas **nativas do Windows** voltadas para **suporte técnico, redes, auditoria e segurança da informação**.

O projeto nasceu de uma necessidade prática do dia a dia de suporte: a perda de tempo causada pela abertura de múltiplos prompts e execução manual de comandos repetitivos. O NetWatch resolve isso oferecendo um **menu estruturado (switch)** que organiza e executa essas tarefas de forma rápida, padronizada e eficiente.

---

## 🎯 Objetivos do Projeto

* Centralizar comandos e ferramentas nativas do Windows
* Reduzir o tempo operacional em atividades de suporte
* Padronizar diagnósticos técnicos
* Facilitar o uso de comandos PowerShell para analistas de diferentes níveis
* Servir como base extensível para novos módulos e funcionalidades

---

## 🛠️ Tecnologias Utilizadas

* **PowerShell (Windows PowerShell 5.1+)**
* Ferramentas nativas do Windows, como:

  * `ping`, `tracert`, `nslookup`, `netstat`
  * `Resolve-DnsName`
  * `Get-NetTCPConnection`
  * `Get-NetFirewallProfile`
  * `Get-WinEvent`
  * `pktmon`
  * Windows Defender (`Get-MpComputerStatus`, `Start-MpScan`)

Não há dependências externas obrigatórias.

---

## 📂 Estrutura do Toolkit

O NetWatch é organizado em menus temáticos:

### 🌐 Redes

* Ping (normal e contínuo)
* Traceroute
* Nslookup
* Resolução DNS
* Telnet em nova janela
* Netstat (a, b, n)
* Ping múltiplos hosts
* Ipconfig (release / renew / flushdns)

### 🛡️ Segurança Defensiva

* Portas TCP ativas
* Status e políticas de Firewall
* Regras de Firewall ativas
* Status do SMBv1
* Serviços inseguros (telnet, ftp, RemoteRegistry, etc.)
* Status do RDP e NLA
* Portas associadas a processos
* Geração de hash SHA256

### 📋 Auditoria

* Logs de falha de autenticação (Event ID 4625)
* Logs do Firewall do Windows
* Executáveis recentes na pasta Downloads

### 🔎 Threat Hunting

* Monitoramento TCP em tempo real
* Processos com maior consumo de CPU

### 🧰 Windows Defender

* Status do Defender
* Itens em quarentena
* Scan rápido

### 📡 Captura de Pacotes (Pktmon)

* Iniciar captura
* Parar captura
* Conversão de ETL para PCAPNG

### ⚔️ Segurança Ofensiva (Laboratório)

* Coleta de banner via Netcat
* Coleta de banner via TCP em PowerShell

---

## 📄 Logs

O NetWatch permite gerar logs opcionais das execuções:

* Os logs são salvos em:
  `C:\Users\<usuário>\NetWatch_Logs`
* Formato: `.txt`
* Codificação: **UTF-8**
* Nome do arquivo inclui data e hora da execução

---

## ▶️ Como Executar

1. Faça o download do arquivo `NetWatch.ps1`
2. Abra o PowerShell **como Administrador**
3. Caso necessário, permita a execução de scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

4. Execute o script:

```powershell
.\NetWatch.ps1
```

---

## ⚠️ Requisitos e Observações

* Recomendado executar como **Administrador**
* Algumas funções exigem:

  * Windows 10 / 11
  * PowerShell 5.1 ou superior
* Telnet deve estar habilitado no Windows (opcional)
* `pktmon` disponível a partir do Windows 10 (builds mais recentes)

---

## 🚀 Extensibilidade

O NetWatch foi desenvolvido para ser facilmente extensível. Novas funcionalidades podem ser adicionadas por meio de:

* Novos menus
* Novas funções PowerShell
* Integração com ferramentas externas
