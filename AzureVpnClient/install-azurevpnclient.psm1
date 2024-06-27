<#
 .Synopsis
  Downloads and configures the Azure VPN Client

 .Description
  As well as downloading the VPN client, any private DNS resolver will be automatically configured.

 .Parameter Gateway
  (optional) The name of the Azure VPN Gateway resource. Can be specified if there are more than
  one gateway deployed to the subscription. If there are more than one and this parameter is not
  specified, the user is prompted to select a gateway.

 .Parameter Name
  (optional) The name of the VPN in the Azure VPN client will default to the name of the virtual network.
  Use this parameter to override the name that appears in the client.

 .Parameter AdditionalDNS
  (optional) A list of additional DNS servers to be added to the VPN configuration. Specified as an
  array of strings with IP v4 addresses.

 .Example
   # Install the VPN client where there is only one gateway in the subscription.
   Install-AzureVpnClient

 .Example
   # Install the VPN client where there is only one gateway in the subscription, overiding the name
   Install-AzureVpnClient -Name 'My VPN'

 .Example
   # Install the VPN client specifying a gateway in the subscription, and overiding the name
   Install-AzureVpnClient -Gateway 'gw-devgateway' -Name 'My Dev VPN'

 .Example
   # Install the VPN client where there is only one gateway in the subscription, overiding the name and
   # specifying additional custom DNS
   Install-AzureVpnClient -Name 'My VPN' -AdditionalDNS '10.10.2.5'
#>
function Install-AzureVpnClient {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[string] $Gateway = $null,

		[Parameter(Mandatory = $false)]
		[string] $Name = $null,

		[Parameter(Mandatory = $false)]
		[array] $AdditionalDNS = $null
	)

	# Check prerequitistes

	# Azure VPN
	if ((Get-Command -Type Application -Name 'azurevpn' -ErrorAction SilentlyContinue).Count -eq 0) {
		Write-Error "Please install the Azure VPN Client first."
		Start-Process 'ms-windows-store://pdp/?ProductId=9np355qt2sqb'
		return
	}

	# Azcopy
	$azcopyInstalled = $false
	if ((Get-Command -Type Application -Name 'azcopy' -ErrorAction SilentlyContinue).Count -gt 0) {
		$azcopyInstalled = $true
	}

	$vpnProcess = Get-Process -Name AzVpnAppx -ErrorAction SilentlyContinue
	if ($null -ne $vpnProcess) {
		Write-Error "Azure VPN Client is running. Please close the app first."
		return
	}

	# Check Azure Powershell and signed in.
	$azpwshSignedin = $false;
	if ($null -ne (Get-Module -ListAvailable -Name 'Az.Accounts' -Refresh)) {
		$azCtx = Get-AzContext
		if ($null -ne $azCtx) {
			Write-Verbose "Azure Powershell subscription set to `"$($azCtx.Subscription.Name)`""
			$azpwshSignedin = $true;
		}
	}

	if (!$azpwshSignedin) {
		Write-Error "Please ensure Azure Powershell is installed and signed in."
		return
	}

	if ($null -eq (Get-Module -ListAvailable -Name 'Az.DnsResolver')) {
		Write-Error "Please ensure the module Az.DnsResolver is installed."
		return
	}

	$gateways = Get-AzResource -ResourceType 'Microsoft.Network/virtualNetworkGateways'

	if ($gateways.Length -eq 0) {
		Write-Error "There are no Virtual Network Gateways in the subscription."
		return
	}

	if ($gateways.Length -gt 1) {
		if ([string]::IsNullOrEmpty($Gateway)) {
			$n = 0
			$gwChoices = $gateways | ForEach-Object { $n++; [System.Management.Automation.Host.ChoiceDescription]::new("&$($n) $($_.Name)", $_.Id) }
			$choice = $Host.UI.PromptForChoice("Select Gateway", "There are more than one Virtual Network Gateways in the subscription.", $gwChoices, 0)

			$rgName = $gateways[$choice].ResourceGroupName
			$Gateway = $gateways[$choice].Name
		}
		else {
			$gw = $gateways | Where-Object Name -EQ $Gateway
			if ($null -eq $gw) {
				Write-Error "The gateway `"$Gateway`" could not be found in the subscription."
				return
			}
			$rgName = $gw.ResourceGroupName
			$Gateway = $gw.Name
		}
	}
	else {
		$rgName = $gateways[0].ResourceGroupName
		$Gateway = $gateways[0].Name
	}

	Write-Verbose "Setting up client for VPN gateway `"$Gateway`" in RG `"$rgName`""

	$vng = Get-AzVirtualNetworkGateway -ResourceGroupName $rgName -Name $Gateway

	if ($null -eq $vng) {
		Write-Error "Cannot find virtual network gateway"
		return
	}

	$subNetId = $vng.IpConfigurations[0].Subnet.Id
	$vnetId = $subNetId.Substring(0, $subNetId.IndexOf('/subnets/'))

	$dnsResolverInbound = Get-AzResource -ResourceType 'Microsoft.Network/dnsResolvers/inboundEndpoints'

	foreach ($d in $dnsResolverInbound) {
		$nameparts = $d.Name.Split('/')
		$dnsep = Get-AzDnsResolverInboundEndpoint -ResourceGroupName $d.ResourceGroupName -DnsResolverName $nameparts[0] -Name $nameparts[1]
		$dnsResolverSubnetId = $dnsep.IpConfiguration[0].SubnetId
		$dnsResolverVnetId = $dnsResolverSubnetId.Substring(0, $dnsResolverSubnetId.IndexOf('/subnets/'))

		if ($dnsResolverVnetId -eq $vnetId) {
			Write-Verbose "Found Private DNS Resolver `"$($nameparts[0])`" in RG $($d.ResourceGroupName) that matches the vnet"
			$dnsEndpoint = $dnsep
			break;
		}
	}

	if ($null -eq $dnsEndpoint) {
		Write-Error "Cannot find DNS private resolver endpoint, contining without custom DNS."
	}

	Write-Output "Generating the VPN Client configuration. This may take a minute, or so."
	$clientConfig = New-AzVpnClientConfiguration -ResourceGroupName $rgName -Name $Gateway -AuthenticationMethod "EapTls"

	$tmpFile = New-TemporaryFile
	$tmpFolder = New-TemporaryFile
	Remove-Item $tmpFolder -Force

	# Use azcopy if available to download, otherwaise fall-back to Invoke-WebRequest
	if ($azcopyInstalled) {
		azcopy cp $clientConfig.VPNProfileSASUrl $tmpFile.FullName --output-level=quiet --log-level=NONE
	}
	else {
		Invoke-WebRequest -Uri $clientConfig.VPNProfileSASUrl -OutFile $tmpFile.FullName
	}

	Expand-Archive -Path $tmpFile.FullName $tmpFolder.FullName

	Remove-Item $tmpFile -Force

	if (Test-Path "$($tmpFolder.FullName)/AzureVPN/azurevpnconfig.xml" -PathType Leaf) {
		[xml]$vpnconf = get-content "$($tmpFolder.FullName)/AzureVPN/azurevpnconfig.xml"
	}
	elseif (Test-Path "$($tmpFolder.FullName)/AzureVPN/azurevpnconfig_aad.xml" -PathType Leaf) {
		[xml]$vpnconf = get-content "$($tmpFolder.FullName)/AzureVPN/azurevpnconfig_aad.xml"
	}

	if ($null -eq $vpnconf) {
		Write-Error "Cannot find vpn config file"
		return
	}

	$configFile = "$env:localappdata\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\azurevpnconfig.xml"

	$dnsServerList = @()

	if ($null -ne $dnsEndpoint) {
		$dnsServerList += $dnsEndpoint.IPConfiguration.PrivateIPAddress
	}

	foreach ($dns in $AdditionalDNS)
	{
		$address=[IPAddress]$null
		if ([IPAddress]::TryParse($dns, [ref]$address))
		{
			$dnsServerList += $dns
		}
	}

	if ($dnsServerList.Length -gt 0)
	{
		$dnsservers = $vpnconf.AzVpnProfile.clientconfig.AppendChild($vpnconf.CreateElement("dnsservers", "http://schemas.datacontract.org/2004/07/"))
		foreach ($dns in $dnsServerList)
		{
			$dnsEntry = $dnsservers.AppendChild($vpnconf.CreateElement("dnsserver", "http://schemas.datacontract.org/2004/07/"))
			$dnsEntry.InnerText = $dns
		}
		$vpnconf.AzVpnProfile.clientconfig.RemoveAllAttributes()
	}

	if (![string]::IsNullOrEmpty($Name)) {
		$vpnconf.AzVpnProfile.name = $Name
	}

	$vpnconf.Save($configFile)

	Remove-Item $tmpFolder.FullName -Recurse -Force

	& azurevpn -i azurevpnconfig.xml

	Remove-Item $configFile -Force
}

# SIG # Begin signature block
# MIIoAgYJKoZIhvcNAQcCoIIn8zCCJ+8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCJPp3iewCsWA+X
# e3EX35PngFXXdHqDtsoo76qGOdZ4UaCCIQUwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHRDCCBSyg
# AwIBAgIQAtn9muwul8xnLPeaJzbCuzANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMDYxOTAwMDAwMFoXDTI2MDcwNTIzNTk1OVowTDELMAkGA1UEBhMCR0Ix
# DTALBgNVBAcTBEJhdGgxFjAUBgNVBAoTDVN0ZXBoZW4gQXNrZXcxFjAUBgNVBAMT
# DVN0ZXBoZW4gQXNrZXcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDY
# 4EU96pEX+4pFhYOI+xZ9Aok38vbTyXGNdvU0LAeGQO/UhLld1tFKHAgqtzsivgDR
# 1dNAocUCLITBqclH+n1HqiCFENi3oJQr1aDIeZBu6YINUcfHS2j9whENsyvnufwe
# 1TIUk4LtsnZ7Y1px1w3B/L8NnLk9gQqJuTmH6eEk060rVUDY87uV/apyXxLa9dqV
# jupqJ4opoazKp3JRdrbav0RFwO7F4D9lREn0Bhuo1kz4Cj0J5y36E+Xl7W+tji05
# jQY4yMv2QZMIkiaByASSpbx8FqBQG5Oe+zUzu0ObRuTPodmgSXWHj+T0YhFj+QiL
# tf88cJZTZQlbOX890ea3maqU6+2dj78bhJyIaOLu3ckPnQNyfWtpsnWJXP3/Xt5T
# KSNK+/dvLYypdtDCEI/9cbiYu9OBjUVHzKb/qOW8zR5mlyEHqSE0ZBHmM0M0QQAO
# 2GmzZxvwgLfxajLmKdGhgDpoj2uWpj7rJ+cZ2sa1nFN/CYUpulp2be5bGF1LSZPw
# Je//c/ONdaHqv49m1M0XNzFlgoViqVJtiPnzLRx15pl0WQqFpkfJcjGG6BWS7aPg
# A99Iw2somSj5Ye6gK9nRlrRMIBGCOUDN12QVFko9ameuOs289a+uFzhpeFYTrgrk
# ErmZwTYlXq6pZinKqSgbjhUUlgb8kY98UszhpkEOdwIDAQABo4ICAzCCAf8wHwYD
# VR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFMr7jHp8BCat
# ACLnS+004YGanySKMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwPgYDVR0g
# BDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2Vy
# dC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZT
# SEEzODQyMDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBu
# oO8d7/9MnGq39+hMdsroT9j8I3GzJMmIz97UAZyEAGi3jOX4lK8SIYYhCWO2EDUV
# IrrQ97yC5596+faDCkKIXnFlOoElT0epBETNB3Y8C6g4XNKT9oofUhZdM3h22FVn
# Iw0ZoDDWOKJmc1ceuDuq9V0D9esaojc+3BLES3o36srKQVCRvF9N6Bb6K8AHYVC4
# IoE1nuRXgRwqk7pZGsNVCznL7j2WctTNYe67LIQeiKixVKkL/o53c5Rr/nng9GHY
# K792SLH9zelAtxKEJYUKRZbSD09bY6+DmxBY6KyqqnSE7asjMfuUkX55ERLdDp7d
# Mr2igKd58WLH9zb3Pz70fXu1XKmZKtvbNDTIb/q5gghvSWihWLTUEZtFXakjFSj8
# R46HQpqg7b4VMCB3tx0vpyUN74GU/TJyJZRUF13W0Cil7a3/YybpxYi4OYQIqEXh
# oIEK40yqJzk041fOVRrM7a/DlWCxgODS+QIj9Qg6xX8XfPnVArp91nd8+cotGZ9r
# lhvVn/FQzduvu+cv/Cf9D8uzrO4NldRzNMeP+C9XHTorjaKB0UR453T0DVO3OPMK
# IeS6glH/PIJWvKCvyjqAM4wD1cQUdT60it3o1DLUNCU6R4R9l3RQCKYTKBaY99r9
# 5AQb30arTW7ySroVh5Z2VJcr5gn7BVo3ho3iRaDcjjGCBlMwggZPAgEBMH0waTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAy
# MDIxIENBMQIQAtn9muwul8xnLPeaJzbCuzANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDS
# OmIg3uWZYXUe7FEuwHvCzCqQCRODjJJh41OX45akMjANBgkqhkiG9w0BAQEFAASC
# AgBYTLweVVz7UC7J0LMzanUud4FTeEvZurS+i1fD9frSgepK5sQCb49lCaQ3oimV
# 4e94TdtEY2KUK0fK01ymnbpBWBK5bptoU1JChfNiETfuLfoovbcv8qhDNfj233Hy
# NWNSbyKrEYiW4YV8ZNJ3Q2yYwo2xCor/fI8gfnZDXJtNjyTs6RSOfngbDbTl/ev1
# 3dSL4G46YwzO3DN9izEYoeXyorIXN0VrgOYQCyeJ2iOOHjdypeYCCboXrKB7ktPw
# KnaU5zIyyUnkVV3lfPkyEz6QRcu7w6bZmfFjBg58L8GkEQ/tjw27qAZoie3wK9+a
# bDH7LIk9kqFhgMSmIadQaQtdkALq6SN0tVdxCoRylxIoslHNdjsp7nzgtbCFIYxs
# pgLMBapClJtuAvN31CyTUgG2+ilkFLM488SuXZqrAR6LHyJXTiEF1q2t4iyJsheV
# XYcc09jzZCgj/AmURpeLE3ZD9fO4YWVKUBdtJenfHMMO8FsbydTRNCFygYn9lzcS
# SNh3J+lgHYKjPzjZLDzT4kweulYCmR5HxFnVvoESLKqg3zNitV2nqZkBx+GuV8PM
# rPNyefW/J0EBL1bHnIwvsvTZurfaN9LnaQtHAczIXdzaDG4gUyJ9DS+ilUpDdtEq
# LaJUm9VxA8gGyRHPHLMpPt4ECZ+dCDFmcnAUfN1qZR7BwaGCAyAwggMcBgkqhkiG
# 9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNDA2MjcxNzE0MzlaMC8GCSqGSIb3DQEJBDEiBCDNLO8Pt83YdY8vo3R+
# TJnxoiwmYToZXLC7bwLFntf1VTANBgkqhkiG9w0BAQEFAASCAgBriA0FDDws6SXy
# moAQIMvc9WTqoydGLZ0i2QX0PcREhLhYqj9VS9gFiv5+9cL7CmW73qsDAfSVUhLb
# 7jNkeZCR603/RtUpMjEGPlsobKQXMLxvvBYIW4VvsfKMO3drJwZhHgBfmo9n8Sx0
# dEq6L5zE+EpIMlSNQlLeMqpHt6eseLhK9kDTu1hmfzHvOHbMY6YRAFEfCl7938RY
# an/Q5q4KioAKgEykoX4o9Qv31oxWCLocW92Qfs7uy7REltYCGzTHavNCkwC48cB3
# kcz0wWDHPb3/nFez0ZbaArGZ0d/MFD1bPyor25SrxNhmqIUArbolJpEnl2SXRc0A
# YiGfW94H1bkG36FlVb0BzHjBjb45632FWP54c82NK1hNP4zySFC9wmj6WJz05iLt
# toyv5+9ekC7hpxlJcIdKTpAFBKXsJz1hWipbN36pbT8D93afivqPH65Zuxq0i+Fl
# IETPToWCKpi2L6mxE7OjdPnhIlIm9nIizJY98zuzUAzaFq2z1UtUY06NOyO0D2y3
# XmAfNfVZL2OnoY9B6d7jRlrgy5m4yq0Pnii2u1PcvJUHKgsEmoMmUN0INJtKOdSs
# CDm0Rimt2ty0yIQvlqvNCVkQzHcB7qpjEK4iPGMqOWw8SyOWUBmJq4xNwlCXDx/E
# LrTgoSZojcjxgl9jLJQACbP4WvocAw==
# SIG # End signature block
