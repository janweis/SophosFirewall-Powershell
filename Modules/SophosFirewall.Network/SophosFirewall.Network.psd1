@{
    RootModule           = 'SophosFirewall.Network.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = 'c0ed538a-3f1f-4dbb-9f42-672fb8f40f4c'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing the network configuration of Sophos XGS / SFOS 22.0 firewalls via API: interfaces, VLANs, zones, gateways, DNS, DHCP, ARP and tunnels.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.0'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosDNSHostEntryMember',
        'Add-SfosDNSRequestRouteMember',
        'Get-SfosAlias',
        'Get-SfosARPConfiguration',
        'Get-SfosBridgePair',
        'Get-SfosCellularWAN',
        'Get-SfosDHCPRelay',
        'Get-SfosDHCPServer',
        'Get-SfosDHCPServerIpv6',
        'Get-SfosDNS',
        'Get-SfosDNSHostEntry',
        'Get-SfosDNSRequestRoute',
        'Get-SfosDynamicDNS',
        'Get-SfosGatewayConfiguration',
        'Get-SfosGreRoute',
        'Get-SfosGreTunnel',
        'Get-SfosInterface',
        'Get-SfosIPTunnel',
        'Get-SfosLAG',
        'Get-SfosREDDevice',
        'Get-SfosRouterAdvertisement',
        'Get-SfosStaticARP',
        'Get-SfosTAP',
        'Get-SfosVLAN',
        'Get-SfosWiFi6Interface',
        'Get-SfosZone',
        'New-SfosAlias',
        'New-SfosBridgePair',
        'New-SfosBridgePairMSSConfiguration',
        'New-SfosDHCPRelay',
        'New-SfosDHCPServer',
        'New-SfosDHCPServerIpv6',
        'New-SfosDNSHostEntry',
        'New-SfosDNSHostEntryAddress',
        'New-SfosDNSIPv4Settings',
        'New-SfosDNSIPv6Settings',
        'New-SfosDNSRequestRoute',
        'New-SfosDynamicDNS',
        'New-SfosGatewayConfigurationGateway',
        'New-SfosGreRoute',
        'New-SfosGreTunnel',
        'New-SfosInterfaceIPv4Configuration',
        'New-SfosInterfaceIPv6Configuration',
        'New-SfosInterfaceMSSConfiguration',
        'New-SfosIPTunnel',
        'New-SfosLAG',
        'New-SfosLAGMSSConfiguration',
        'New-SfosREDDevice',
        'New-SfosRouterAdvertisement',
        'New-SfosStaticARP',
        'New-SfosTAP',
        'New-SfosVLAN',
        'New-SfosWiFi6Interface',
        'New-SfosZone',
        'Remove-SfosAlias',
        'Remove-SfosBridgePair',
        'Remove-SfosDHCPRelay',
        'Remove-SfosDHCPServer',
        'Remove-SfosDHCPServerIpv6',
        'Remove-SfosDNSHostEntry',
        'Remove-SfosDNSHostEntryMember',
        'Remove-SfosDNSRequestRoute',
        'Remove-SfosDNSRequestRouteMember',
        'Remove-SfosDynamicDNS',
        'Remove-SfosGreRoute',
        'Remove-SfosGreTunnel',
        'Remove-SfosIPTunnel',
        'Remove-SfosLAG',
        'Remove-SfosREDDevice',
        'Remove-SfosRouterAdvertisement',
        'Remove-SfosStaticARP',
        'Remove-SfosTAP',
        'Remove-SfosVLAN',
        'Remove-SfosWiFi6Interface',
        'Remove-SfosZone',
        'Set-SfosAlias',
        'Set-SfosARPConfiguration',
        'Set-SfosBridgePair',
        'Set-SfosCellularWAN',
        'Set-SfosDHCPRelay',
        'Set-SfosDHCPServer',
        'Set-SfosDHCPServerIpv6',
        'Set-SfosDHCPServerStatus',
        'Set-SfosDNS',
        'Set-SfosDNSHostEntry',
        'Set-SfosDNSRequestRoute',
        'Set-SfosDynamicDNS',
        'Set-SfosGatewayConfiguration',
        'Set-SfosGreRoute',
        'Set-SfosGreTunnel',
        'Set-SfosInterface',
        'Set-SfosIPTunnel',
        'Set-SfosLAG',
        'Set-SfosREDDevice',
        'Set-SfosRouterAdvertisement',
        'Set-SfosStaticARP',
        'Set-SfosTAP',
        'Set-SfosVLAN',
        'Set-SfosWiFi6Interface',
        'Set-SfosZone'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Network', 'DNS', 'DHCP', 'VLAN', 'Security')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Network/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Network'
        }
    }
}