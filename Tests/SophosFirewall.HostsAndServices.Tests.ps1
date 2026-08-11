#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.HostsAndServices module

.DESCRIPTION
    Tests for cmdlet functionality, parameter validation, and structure.
    Integration tests (actual API calls) are skipped.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

# Get module path - use relative paths that work in any environment
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.HostsAndServices\SophosFirewall.HostsAndServices.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module manifest not found: $ModulePath"
    exit 1
}

# Import modules
Import-Module $CoreModulePath -Force
Import-Module $ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.HostsAndServices module should load' {
        Get-Module SophosFirewall.HostsAndServices | Should -Not -BeNullOrEmpty
    }
    
    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }
}

Describe 'IP Host Functions' {
    It 'Get-SfosIPHost function should exist' {
        Get-Command Get-SfosIPHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosIPHost function should exist' {
        Get-Command New-SfosIPHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosIPHost function should exist' {
        Get-Command Set-SfosIPHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosIPHost function should exist' {
        Get-Command Remove-SfosIPHost | Should -Not -BeNullOrEmpty
    }
    
    Context 'Get-SfosIPHost Parameters' {
        It 'Should have NameLike parameter' {
            (Get-Command Get-SfosIPHost).Parameters.Keys | Should -Contain 'NameLike'
        }
        
        It 'Should have Firewall parameter' {
            (Get-Command Get-SfosIPHost).Parameters.Keys | Should -Contain 'Firewall'
        }
        
        It 'Should have Port parameter' {
            (Get-Command Get-SfosIPHost).Parameters.Keys | Should -Contain 'Port'
        }
    }
    
    Context 'New-SfosIPHost Parameters' {
        It 'Should have Name parameter' {
            (Get-Command New-SfosIPHost).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have HostType parameter' {
            (Get-Command New-SfosIPHost).Parameters.Keys | Should -Contain 'HostType'
        }
        
        It 'Should support IP parameter set' {
            (Get-Command New-SfosIPHost).ParameterSets.Name | Should -Contain 'IP'
        }
        
        It 'HostType should have valid ValidateSet values' {
            $hostTypeParam = (Get-Command New-SfosIPHost).Parameters['HostType']
            $hostTypeParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | 
                ForEach-Object { $_.ValidValues } | Should -Contain 'IP'
        }
    }
    
    Context 'Set-SfosIPHost Parameters' {
        It 'Should have Name parameter' {
            (Get-Command Set-SfosIPHost).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have Description parameter' {
            (Get-Command Set-SfosIPHost).Parameters.Keys | Should -Contain 'Description'
        }
    }
}

Describe 'IP Host Group Functions' {
    It 'Get-SfosIPHostGroup function should exist' {
        Get-Command Get-SfosIPHostGroup | Should -Not -BeNullOrEmpty
    }
    
    It 'Add-SfosIPHostGroupMember function should exist' {
        Get-Command Add-SfosIPHostGroupMember | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosIPHostGroupMember function should exist' {
        Get-Command Remove-SfosIPHostGroupMember | Should -Not -BeNullOrEmpty
    }
    
    Context 'Add-SfosIPHostGroupMember Parameters' {
        It 'Should have Name parameter (for group name)' {
            (Get-Command Add-SfosIPHostGroupMember).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have members parameter' {
            (Get-Command Add-SfosIPHostGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
    
    Context 'Remove-SfosIPHostGroupMember Parameters' {
        It 'Should have Name parameter (for group name)' {
            (Get-Command Remove-SfosIPHostGroupMember).Parameters.Keys | Should -Contain 'Name'
        }
        
        It 'Should have members parameter' {
            (Get-Command Remove-SfosIPHostGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
}

Describe 'FQDN Host Functions' {
    It 'Get-SfosFQDNHost function should exist' {
        Get-Command Get-SfosFQDNHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosFQDNHost function should exist' {
        Get-Command New-SfosFQDNHost | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosFQDNHost function should exist' {
        Get-Command Set-SfosFQDNHost | Should -Not -BeNullOrEmpty
    }
}

Describe 'MAC Host Functions' {
    It 'Get-SfosMACHost function should exist' {
        Get-Command Get-SfosMACHost | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosMACHost function should exist' {
        Get-Command New-SfosMACHost | Should -Not -BeNullOrEmpty
    }
}

Describe 'Service Functions' {
    It 'Get-SfosService function should exist' {
        Get-Command Get-SfosService | Should -Not -BeNullOrEmpty
    }
    
    It 'New-SfosService function should exist' {
        Get-Command New-SfosService | Should -Not -BeNullOrEmpty
    }
    
    It 'Set-SfosService function should exist' {
        Get-Command Set-SfosService | Should -Not -BeNullOrEmpty
    }
    
    Context 'Get-SfosService Parameters' {
        It 'Should have ProtocolLike parameter for filtering' {
            (Get-Command Get-SfosService).Parameters.Keys | Should -Contain 'ProtocolLike'
        }
    }
    
    Context 'New-SfosService Parameters' {
        It 'Should have DstPort parameter (not Port)' {
            (Get-Command New-SfosService).Parameters.Keys | Should -Contain 'DstPort'
        }
        
        It 'Should have SrcPort parameter' {
            (Get-Command New-SfosService).Parameters.Keys | Should -Contain 'SrcPort'
        }
    }
}

Describe 'Service Group Functions' {
    It 'Get-SfosServiceGroup function should exist' {
        Get-Command Get-SfosServiceGroup | Should -Not -BeNullOrEmpty
    }
    
    It 'Add-SfosServiceGroupMember function should exist' {
        Get-Command Add-SfosServiceGroupMember | Should -Not -BeNullOrEmpty
    }
    
    It 'Remove-SfosServiceGroupMember function should exist' {
        Get-Command Remove-SfosServiceGroupMember | Should -Not -BeNullOrEmpty
    }
    
    Context 'Add-SfosServiceGroupMember Parameters' {
        It 'Should name the group parameter Name, like every other member cmdlet' {
            # It used to be called ServiceGroupName, which broke Get-SfosServiceGroup |
            # Add-SfosServiceGroupMember: no matching property, so PowerShell fell back to
            # binding the whole object by value and produced a 61-character "name".
            (Get-Command Add-SfosServiceGroupMember).Parameters.Keys | Should -Contain 'Name'
        }

        It 'Should keep ServiceGroupName as an alias for existing callers' {
            (Get-Command Add-SfosServiceGroupMember).Parameters['Name'].Aliases | Should -Contain 'ServiceGroupName'
        }
        
        It 'Should have members parameter' {
            (Get-Command Add-SfosServiceGroupMember).Parameters.Keys | Should -Contain 'members'
        }
    }
}

Describe 'Export/Import Functions' {
    It 'Export-SfosIPHosts function should exist' {
        Get-Command Export-SfosIPHosts | Should -Not -BeNullOrEmpty
    }
    
    It 'Import-SfosIPHosts function should exist' {
        Get-Command Import-SfosIPHosts | Should -Not -BeNullOrEmpty
    }
    
    It 'Export-SfosServices function should exist' {
        Get-Command Export-SfosServices | Should -Not -BeNullOrEmpty
    }
    
    Context 'Export-SfosIPHosts Parameters' {
        It 'Should have FilePath parameter' {
            (Get-Command Export-SfosIPHosts).Parameters.Keys | Should -Contain 'FilePath'
        }
    }
}

Describe 'Pipeline Support' {
    Context 'Name Parameter Pipeline Support' {
        It 'Set-SfosIPHost Name should support ValueFromPipeline' {
            $cmd = Get-Command Set-SfosIPHost
            $nameParam = $cmd.Parameters['Name']
            $pipelineAttribs = $nameParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            ($pipelineAttribs | Where-Object { $_.ValueFromPipeline -eq $true }) | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Request XML Generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $okResponse = @'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost><Status code="200">Configuration applied successfully.</Status></IPHost>
  <IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup>
  <Services><Status code="200">Configuration applied successfully.</Status></Services>
</Response>
'@
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
            [PSCustomObject]@{ Content = $okResponse }
        }
    }

    Context 'New-SfosIPHost' {
        It 'Should build a Set/add request for a single IP' {
            New-SfosIPHost -Name 'WebServer01' -HostType IP -IPAddress '10.0.1.100' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>WebServer01</Name>' -and
                $InnerXml -match '<HostType>IP</HostType>' -and
                $InnerXml -match '<IPAddress>10\.0\.1\.100</IPAddress>'
            }
        }

        It 'Should emit the subnet for a network host' {
            New-SfosIPHost -Name 'Office' -HostType Network -IPAddress '192.168.10.0' -Subnet '255.255.255.0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Subnet>255\.255\.255\.0</Subnet>'
            }
        }

        It 'Should XML-escape the object name' {
            New-SfosIPHost -Name 'Web&Co' -HostType IP -IPAddress '10.0.1.1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Name>Web&amp;Co</Name>'
            }
        }
    }

    Context 'Remove-SfosIPHost' {
        It 'Should build a Remove request' {
            Remove-SfosIPHost -Name 'WebServer01' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>WebServer01</Name>'
            }
        }

        It 'Should not call the API with -WhatIf' {
            Remove-SfosIPHost -Name 'WebServer01' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'New-SfosService' {
        It 'Should build a Set/add request with source and destination port' {
            New-SfosService -Name 'CustomHTTPS' -Protocol TCP -DstPort '8443' -SrcPort '1:65535' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Name>CustomHTTPS</Name>' -and
                $InnerXml -match '<DestinationPort>8443</DestinationPort>'
            }
        }
    }

    Context 'Server-side filtering' {
        It 'Should send exactly one Filter block with one key' {
            # SFOS evaluates only the first key of the first Filter - more than one is a bug
            Get-SfosIPHost -NameLike 'Web' -DescriptionLike 'prod' @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                ([regex]::Matches($InnerXml, '<Filter>')).Count -eq 1 -and
                ([regex]::Matches($InnerXml, '<key ')).Count -eq 1
            }
        }

        It 'Should never send an unsupported Description key - it would return everything' {
            Get-SfosIPHost -DescriptionLike 'prod' @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch 'name="Description"'
            }
        }
    }
}

Describe 'Client-side Filtering' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
            [PSCustomObject]@{ Content = @'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost><Name>WebProd</Name><HostType>IP</HostType><IPAddress>10.0.0.1</IPAddress><Description>production</Description></IPHost>
  <IPHost><Name>WebTest</Name><HostType>IP</HostType><IPAddress>10.0.0.2</IPAddress><Description>staging</Description></IPHost>
  <IPHost><Name>DbProd</Name><HostType>Network</HostType><IPAddress>10.1.0.0</IPAddress><Subnet>255.255.255.0</Subnet><Description>production</Description></IPHost>
</Response>
'@
            }
        }
    }

    It 'Should combine several filters with AND, not OR' {
        $result = @(Get-SfosIPHost -NameLike 'Web' -DescriptionLike 'production' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'WebProd'
    }

    It 'Should filter on fields the API ignores' {
        $result = @(Get-SfosIPHost -HostTypeLike 'Network' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'DbProd'
    }

    It 'Should apply the same filtering to -AsXml' {
        $result = @(Get-SfosIPHost -NameLike 'Web' -DescriptionLike 'production' -AsXml @conn)

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
    }

    It 'Should return an empty array when nothing matches' {
        $result = @(Get-SfosIPHost -NameLike 'DoesNotExist' @conn)

        $result.Count | Should -Be 0
    }
}

Describe 'Pipeline Processing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # Set-SfosIPHost reads the current object before writing, so the mock has to answer
        # a <Get> with a matching host - otherwise the read-modify-write cannot find it.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <IPHost><Name>P1</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.1.0.1</IPAddress><Description>d1</Description></IPHost>
  <IPHost><Name>P2</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.1.0.2</IPAddress><Description>d2</Description></IPHost>
  <IPHost><Name>P3</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.1.0.3</IPAddress><Description>d3</Description></IPHost>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPHost><Status code="200">OK</Status></IPHost></Response>' }
            }
        }
    }

    It 'Set-SfosIPHost should keep the existing description when none is supplied' {
        # SFOS clears anything the update does not send, so Set must carry it over
        Set-SfosIPHost -Name 'P1' -HostType IP -IPAddress '10.1.9.9' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<Description>d1</Description>'
        }
    }

    It 'Set-SfosIPHost should process every object from the pipeline' {
        @(
            [PSCustomObject]@{ Name = 'P1'; HostType = 'IP'; IPAddress = '10.1.0.1' }
            [PSCustomObject]@{ Name = 'P2'; HostType = 'IP'; IPAddress = '10.1.0.2' }
            [PSCustomObject]@{ Name = 'P3'; HostType = 'IP'; IPAddress = '10.1.0.3' }
        ) | Set-SfosIPHost @conn -Confirm:$false

        # Count the writes only - each object also triggers a read for the merge
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 3 -Exactly -ParameterFilter {
            $InnerXml -match '<Set '
        }
    }

    It 'Remove-SfosIPHost should process every object from the pipeline' {
        @('A', 'B') | Remove-SfosIPHost @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 2 -Exactly
    }
}


