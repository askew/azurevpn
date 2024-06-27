# Azure VPN Client Helper

This module contains one CmdLet `Install-AzureVpnClient` that simplifies the process of setting up the Azure VPN client. In particular, adding a custom DNS resolver to the VPN configuration. Note this currently only supports the Windows VPN client.

When using the [Azure VPN Client][vpnclient], the client configuration downloaded from the portal will not have any custom DNS configured. If you are using the [Azure Private DNS Resolver][dnsresolver] or hosting a custom DNS server, then you need to hand edit the VPN configuration to include this DNS server. This PowerShell module has a cmdlet that makes this much simpler.

## Install

The module can be installed from the [PowerShell Gallery](https://www.powershellgallery.com/packages/AzureVpnClient)

```pwsh
Install-Module AzureVpnClient
```

## Using

```pwsh
Install-AzureVpnClient [[-Gateway] <String>] [[-Name] <String>] [[-AdditionalDNS] <Array>]
```

This CmdLet will search for an Azure VPN Gateway in the subscription currently selected as the Azure PowerShell default (use `Get-AzContext` to check). It there are more than one it will prompt to select one, or the gateway name can be specified with the `-Gateway` parameter.

The CmdLet will then look for a [Private DNS Resolver][dnsresolver] linked to the same virtual network as the VPN gateway. If found, the IP address of the inbound endpoint will be added to the VPN client configuration.

Additional DNS entries can be added via the `-AdditionalDNS` parameter. This can also be used when a custom DNS server is used instead of the Azure Private DNS Resolver.

The CmdLet finally launches the Azure VPN Client, loading the new VPN profile. By default, the name of the VPN profile is set to the name of the virtual network in Azure. Use the `-Name` parameter to override this and give the profile a more meaningful name.

### Prerequisites

  * __Microsoft Azure PowerShell__
    The CmdLet is dependent on [Azure PowerShell][azpwsh]. [Az version 12.0.0](https://www.powershellgallery.com/packages/Az/12.0.0) or later should be used as this includes the required __Az.DnsResolver__ module.

  * __Azure VPN Client__
    The [Azure VPN Client](https://go.microsoft.com/fwlink/?linkid=2117554) must be installed, but not running. If it's already running it cannot import the new profile.

  * __AzCopy__
    [AzCopy][azcopy] is not required, however if present on the system the CmdLet will use it to download the VPN configuration package. If azcopy is not installed `Invoke-WebRequest` will be used.



[vpnclient]: https://learn.microsoft.com/azure/vpn-gateway/point-to-site-entra-vpn-client-windows
[dnsresolver]: https://learn.microsoft.com/azure/dns/dns-private-resolver-overview
[azpwsh]: https://github.com/Azure/azure-powershell/ "Microsoft Azure PowerShell"
[azcopy]: https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10 "Get started with AzCopy"
