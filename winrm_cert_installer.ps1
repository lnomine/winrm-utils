#Requires -Version 3.0

# Configure a Windows host for remote management with Ansible
# -----------------------------------------------------------

function Import-Certificate {

    [CmdletBinding()]
	param
	(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true, Position=0, ParameterSetName="CertFile")]
		[System.IO.FileInfo]
        $CertFile,

        [Parameter(ValueFromPipeline=$true,Mandatory=$true, Position=0, ParameterSetName="Cert")]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Cert,

        [Parameter(Position=1)]
		    [string[]] $StoreNames = "My",

        [Parameter(Position=2)]
        [string]$StoreType = "LocalMachine",

        [Parameter(Position=3)]
        [string] $CertPassword
	)

	begin
	{
		[void][System.Reflection.Assembly]::LoadWithPartialName("System.Security")
	}

	process
	{
        switch ($pscmdlet.ParameterSetName) {
            "CertFile" {
        		try {
                    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $($CertFile.FullName),$CertPassword
                }
                catch {
        			Write-Error ("Error reading '$CertFile': $_ .") -ErrorAction:Continue
        		}
            }
            "Cert" {

            }
            default {
                Write-Error "Missing parameter:`nYou need to specify either a certificate or a certificate file name."
            }
	    }

        if ( $Cert ) {
			$StoreNames | ForEach-Object {
				$StoreName = $_

                $env:subjectName = $($Cert.Subject).split(',')[0].split('=')[1]
                $env:thumbprint = $($Cert.Thumbprint)

				if (Test-Path "cert:\$StoreType\$StoreName") {
					try
					{
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreType
						$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
						$store.Add($Cert)
                        if ( $CertFile ) {
        					Write-Verbose " [Import-Certificate] :: Successfully added '$CertFile' to 'cert:\$StoreType\$StoreName'."
        				} else {
        					Write-Verbose " [Import-Certificate] :: Successfully added '$($Cert.Subject) ($($Cert.Thumbprint))' to 'cert:\$StoreType\$StoreName'."
                        }
                    }
					catch
					{
						Write-Error ("Error adding '$($Cert.Subject) ($($Cert.Thumbprint))' to 'cert:\$StoreType\$StoreName': $_ .") -ErrorAction:Continue
					}
                    if ( $store ) {
                        $store.Close()
                    }
				}
                else {
					Write-Warning "Certificate store '$StoreName' does not exist. Skipping..."
				}
			}
		} else {
            Write-Warning "No certificates found."
        }
	}

}

if ([Environment]::OSVersion.Version.Minor -gt 1 -or [Environment]::OSVersion.Version.Major -gt 6)

{

ls "C:\" -filter "*.p12" | Import-pfxcertificate -CertStoreLocation cert:\localmachine\My -outvariable pfxproperties | out-null
$env:thumbprint = $pfxproperties.Thumbprint
$env:subjectName = $($pfxproperties.Subject).split(',')[0].split('=')[1]

}

else

{

ls "C:\" -filter "*.p12" | Import-Certificate -StoreNames My -StoreType LocalMachine

}

Function Write-Log
{
    $Message = $args[0]
    Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1 -Message $Message
}

Function Write-VerboseLog
{
    $Message = $args[0]
    Write-Verbose $Message
    Write-Log $Message
}

Function Write-HostLog
{
    $Message = $args[0]
    Write-Host $Message
    Write-Log $Message
}

# Setup error handling.
Trap
{
    $_
    Exit 1
}
$ErrorActionPreference = "Stop"

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if (-Not $myWindowsPrincipal.IsInRole($adminRole))
{
    Write-Host "ERROR: You need elevated Administrator privileges in order to run this script."
    Write-Host "       Start Windows PowerShell by using the Run as Administrator option."
    Exit 2
}

$EventSource = $MyInvocation.MyCommand.Name
If (-Not $EventSource)
{
    $EventSource = "Powershell CLI"
}

If ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False)
{
    New-EventLog -LogName Application -Source $EventSource
}

# Find and start the WinRM service.
Write-Verbose "Verifying WinRM service."
If (!(Get-Service "WinRM"))
{
    Write-Log "Unable to find the WinRM service."
    Throw "Unable to find the WinRM service."
}
ElseIf ((Get-Service "WinRM").Status -ne "Running")
{
    Write-Verbose "Starting WinRM service."
    Start-Service -Name "WinRM" -ErrorAction Stop
    Write-Log "Started WinRM service."
    Write-Verbose "Setting WinRM service to start automatically on boot."
    Set-Service -Name "WinRM" -StartupType Automatic
    Write-Log "Set WinRM service to start automatically on boot."

}

# Make sure there is a SSL listener.
$listeners = Get-ChildItem WSMan:\localhost\Listener
If (!($listeners | Where {$_.Keys -like "TRANSPORT=HTTPS"}))
{

    # Create the hashtables of settings to be used.
    $valueset = @{
        Hostname = $env:subjectName
        CertificateThumbprint = $env:thumbprint
    }

    $selectorset = @{
        Transport = "HTTPS"
        Address = "*"
    }

    Write-Verbose "Enabling SSL listener."
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    Write-Log "Enabled SSL listener."
}
Else
{
    Write-Verbose "SSL listener is already active."
    }

# Check for basic authentication.
$basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where {$_.Name -eq "Basic"}
If (($basicAuthSetting.Value) -eq $false)
{
    Write-Verbose "Enabling basic auth support."
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
    Write-Log "Enabled basic auth support."
}
Else
{
    Write-Verbose "Basic auth is already enabled."
}

# Configure firewall to allow WinRM HTTPS connections.
$fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
$fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
If ($fwtest1.count -lt 5)
{
    Write-Verbose "Adding firewall rule to allow WinRM HTTPS."
    netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
    Write-Log "Added firewall rule to allow WinRM HTTPS."
}
ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5))
{
    Write-Verbose "Updating firewall rule to allow WinRM HTTPS for any profile."
    netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
    Write-Log "Updated firewall rule to allow WinRM HTTPS for any profile."
}
Else
{
    Write-Verbose "Firewall rule already exists to allow WinRM HTTPS."
}
