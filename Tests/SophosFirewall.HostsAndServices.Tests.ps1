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

#region Extended per-function coverage
#
# Everything below fills in the "funktionsgenau" gap: every one of the 53 exported
# functions gets at least one XML-generation or parsing test, every Set-*/Add-*/Remove-*
# member cmdlet gets a read-modify-write preservation test, and every cmdlet with its own
# error logic gets a test that triggers exactly that path. Mock response shapes are taken
# from abnahme-hostsandservices-matrix.md (live-verified against FW1) and from the
# CLAUDE.md rules for this module (528 passthrough on Remove, the ICMPCode '-1' regression,
# empty-result handling).

Describe 'IPHost - Extended Coverage' {

    Context 'New-SfosIPHost - remaining host types and the parameter-set guard' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost><Status code="200">Configuration applied successfully.</Status></IPHost></Response>' }
            }
        }

        It 'Should build an IPRange request' {
            New-SfosIPHost -Name 'DHCPRange' -HostType IPRange -StartIPAddress '10.0.1.100' -EndIPAddress '10.0.1.200' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<StartIPAddress>10\.0\.1\.100</StartIPAddress>' -and
                $InnerXml -match '<EndIPAddress>10\.0\.1\.200</EndIPAddress>'
            }
        }

        It 'Should build an IPList request with comma-joined addresses' {
            New-SfosIPHost -Name 'DMZServers' -HostType IPList -ListOfIPAddresses @('10.1.1.10', '10.1.1.20') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ListOfIPAddresses>10\.1\.1\.10,10\.1\.1\.20</ListOfIPAddresses>'
            }
        }

        It 'Should throw when -HostType does not match the parameters actually supplied' {
            # -HostType Network lands in the IP parameter set without -Subnet - the body
            # catches this instead of letting the firewall answer with an opaque 501.
            { New-SfosIPHost -Name 'Bad' -HostType Network -IPAddress '10.0.0.1' @conn -Confirm:$false } | Should -Throw "*HostType*"

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Get-SfosIPHost - empty result and error status handling' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It '"No. of records Zero." should return an empty array, not throw' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost transactionid=""><Status>No. of records Zero.</Status></IPHost></Response>' }
            }

            $result = @(Get-SfosIPHost -NameLike 'DoesNotExist' @conn)
            $result.Count | Should -Be 0
        }

        It 'A code-less status other than "No. of records Zero." should throw, not read as empty' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost><Status>Transaction fail</Status></IPHost></Response>' }
            }

            { Get-SfosIPHost @conn } | Should -Throw '*Transaction fail*'
        }

        It 'A failed login should throw rather than being read as an empty result' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failure</status></Login></Response>' }
            }

            { Get-SfosIPHost @conn } | Should -Throw '*login*'
        }
    }

    Context 'Remove-SfosIPHost - documented 528 passthrough on a non-existent object' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Passes the raw firewall 528 message through rather than reporting "not found"' {
            # Live-measured (abnahme-hostsandservices-matrix.md): Remove-Sfos* does not read
            # first, so a repeat remove on an already-deleted object gets this misleading
            # code instead of a "was not found" message. CLAUDE.md "Still open" - not fixed.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost><Status code="528">Trying to update default entities which are not editable.</Status></IPHost></Response>' }
            }

            { Remove-SfosIPHost -Name 'Ghost' @conn -Confirm:$false } | Should -Throw '*528*'
        }
    }

    Context 'Export-SfosIPHosts / Import-SfosIPHosts - round trip and file errors' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost><Name>ExportedHost</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.5.5.5</IPAddress><Description>roundtrip</Description></IPHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHost><Status code="200">Configuration applied successfully.</Status></IPHost></Response>' }
                }
            }
        }

        It 'Exports and re-imports the same host through a CSV file' {
            $csvPath = Join-Path $TestDrive 'iphosts.csv'

            Export-SfosIPHosts -FilePath $csvPath @conn
            Test-Path -Path $csvPath | Should -BeTrue
            (Import-Csv -Path $csvPath).Name | Should -Be 'ExportedHost'

            Import-SfosIPHosts -FilePath $csvPath @conn

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>ExportedHost</Name>' -and
                $InnerXml -match '<IPAddress>10\.5\.5\.5</IPAddress>'
            }
        }

        It 'Export-SfosIPHosts should throw if the target file already exists without -Overwrite' {
            $csvPath = Join-Path $TestDrive 'existing.csv'
            'placeholder' | Out-File -FilePath $csvPath

            { Export-SfosIPHosts -FilePath $csvPath @conn } | Should -Throw '*already exists*'
        }

        It 'Import-SfosIPHosts should throw if the file does not exist' {
            { Import-SfosIPHosts -FilePath (Join-Path $TestDrive 'missing.csv') @conn } | Should -Throw '*was not found*'
        }
    }
}

Describe 'IPHostGroup - Extended Coverage' {

    Context 'Get-SfosIPHostGroup - parsing' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses HostList members into a string array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>WebServers</Name><IPFamily>IPv4</IPFamily><Description>d</Description><HostList><Host>Host1</Host><Host>Host2</Host></HostList></IPHostGroup></Response>' }
            }

            $result = @(Get-SfosIPHostGroup @conn)
            $result.Count | Should -Be 1
            $result[0].HostList | Should -Be @('Host1', 'Host2')
        }

        It 'Returns @() for a group with no HostList element' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>Empty</Name><IPFamily>IPv4</IPFamily></IPHostGroup></Response>' }
            }

            $result = @(Get-SfosIPHostGroup @conn)
            $result[0].HostList | Should -Be @()
        }
    }

    Context 'New-SfosIPHostGroup - XML generation and escaping' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
            }
        }

        It 'Builds a Set/add request with members and an escaped description' {
            New-SfosIPHostGroup -Name 'Group&1' -Members @('Host1', 'Host2') -Description 'A & B' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>Group&amp;1</Name>' -and
                $InnerXml -match '<Description>A &amp; B</Description>' -and
                $InnerXml -match '<Host>Host1</Host>' -and
                $InnerXml -match '<Host>Host2</Host>'
            }
        }
    }

    Context 'Set-SfosIPHostGroup - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>WebServers</Name><IPFamily>IPv4</IPFamily><Description>original</Description><HostList><Host>Host1</Host><Host>Host2</Host></HostList></IPHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
                }
            }
        }

        It 'Keeps the existing Description and HostList when only IPFamily is changed' {
            Set-SfosIPHostGroup -Name 'WebServers' -IPFamily IPv4 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<Host>Host1</Host>' -and
                $InnerXml -match '<Host>Host2</Host>'
            }
        }

        It 'Throws when the target group does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup transactionid=""><Status>No. of records Zero.</Status></IPHostGroup></Response>' }
            }

            { Set-SfosIPHostGroup -Name 'Ghost' @conn -Confirm:$false } | Should -Throw '*was not found*'
        }
    }

    Context 'Add-SfosIPHostGroupMember - preservation and merge' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>WebServers</Name><IPFamily>IPv4</IPFamily><Description>keep-me</Description><HostList><Host>Host1</Host></HostList></IPHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
                }
            }
        }

        It 'Merges the new member with the existing HostList and keeps the Description' {
            Add-SfosIPHostGroupMember -Name 'WebServers' -Members 'Host2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Host>Host1</Host>' -and
                $InnerXml -match '<Host>Host2</Host>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }

        It 'Throws when the target group does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup transactionid=""><Status>No. of records Zero.</Status></IPHostGroup></Response>' }
            }

            { Add-SfosIPHostGroupMember -Name 'Ghost' -Members 'X' @conn -Confirm:$false } | Should -Throw '*was not found*'
        }
    }

    Context 'Remove-SfosIPHostGroupMember - preservation and subtraction' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>WebServers</Name><IPFamily>IPv4</IPFamily><Description>keep-me</Description><HostList><Host>Host1</Host><Host>Host2</Host></HostList></IPHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
                }
            }
        }

        It 'Removes only the specified member and keeps the rest and the Description' {
            Remove-SfosIPHostGroupMember -Name 'WebServers' -Members 'Host1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<Host>Host1</Host>' -and
                $InnerXml -match '<Host>Host2</Host>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }
    }

    Context 'Remove-SfosIPHostGroup - XML generation' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
            }
        }

        It 'Builds a Remove request' {
            Remove-SfosIPHostGroup -Name 'WebServers' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>WebServers</Name>'
            }
        }

        It 'Should not call the API with -WhatIf' {
            Remove-SfosIPHostGroup -Name 'WebServers' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Export-SfosIPHostGroups / Import-SfosIPHostGroups - round trip' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Name>ExportedGroup</Name><IPFamily>IPv4</IPFamily><Description>d</Description><HostList><Host>Host1</Host><Host>Host2</Host></HostList></IPHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPHostGroup><Status code="200">Configuration applied successfully.</Status></IPHostGroup></Response>' }
                }
            }
        }

        It 'Exports and re-imports the same group, splitting HostList back into members' {
            $csvPath = Join-Path $TestDrive 'iphostgroups.csv'

            $exportResult = Export-SfosIPHostGroups -FilePath $csvPath @conn
            $exportResult.SuccessItems | Should -Contain 'ExportedGroup'
            (Import-Csv -Path $csvPath).HostList | Should -Be 'Host1,Host2'

            $importResult = Import-SfosIPHostGroups -FilePath $csvPath @conn
            $importResult.Success | Should -Be 1

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Host>Host1</Host>' -and
                $InnerXml -match '<Host>Host2</Host>'
            }
        }
    }
}

Describe 'FQDNHost - Extended Coverage' {

    Context 'Get-SfosFQDNHost - parsing' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses FQDN and FQDNHostGroupList' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Name>Outlook</Name><Description>d</Description><FQDN>outlook.office365.com</FQDN><FQDNHostGroupList><FQDNHostGroup>SaaS</FQDNHostGroup></FQDNHostGroupList></FQDNHost></Response>' }
            }

            $result = @(Get-SfosFQDNHost @conn)
            $result[0].FQDN | Should -Be 'outlook.office365.com'
            $result[0].FQDNHostGroupList | Should -Be @('SaaS')
        }

        It '"No. of records Zero." should return an empty array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost transactionid=""><Status>No. of records Zero.</Status></FQDNHost></Response>' }
            }

            $result = @(Get-SfosFQDNHost -NameLike 'DoesNotExist' @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'New-SfosFQDNHost - XML generation and escaping' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Status code="200">Configuration applied successfully.</Status></FQDNHost></Response>' }
            }
        }

        It 'Builds a Set/add request with FQDN, description and host group list' {
            New-SfosFQDNHost -Name 'Azure&West' -FQDN '*.westeurope.cloudapp.azure.com' -Description 'A & B' -HostGroup @('SaaS') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>Azure&amp;West</Name>' -and
                $InnerXml -match '<FQDN>\*\.westeurope\.cloudapp\.azure\.com</FQDN>' -and
                $InnerXml -match '<Description>A &amp; B</Description>' -and
                $InnerXml -match '<FQDNHostGroup>SaaS</FQDNHostGroup>'
            }
        }
    }

    Context 'Set-SfosFQDNHost - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Name>Outlook</Name><Description>original</Description><FQDN>outlook.office365.com</FQDN><FQDNHostGroupList><FQDNHostGroup>SaaS</FQDNHostGroup></FQDNHostGroupList></FQDNHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Status code="200">Configuration applied successfully.</Status></FQDNHost></Response>' }
                }
            }
        }

        It 'Keeps the existing Description and FQDNHostGroupList when only FQDN is changed' {
            Set-SfosFQDNHost -Name 'Outlook' -FQDN 'outlook2.office365.com' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<FQDNHostGroup>SaaS</FQDNHostGroup>'
            }
        }

        It 'Throws when the target host does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost transactionid=""><Status>No. of records Zero.</Status></FQDNHost></Response>' }
            }

            { Set-SfosFQDNHost -Name 'Ghost' -FQDN 'ghost.example.com' @conn -Confirm:$false } | Should -Throw '*was not found*'
        }
    }

    Context 'Remove-SfosFQDNHost / Remove-SfosFQDNHostMass - XML generation' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Status code="200">Configuration applied successfully.</Status></FQDNHost></Response>' }
            }
        }

        It 'Remove-SfosFQDNHost builds a single-name Remove request' {
            Remove-SfosFQDNHost -Name 'Outlook' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Outlook</Name>'
            }
        }

        It 'Remove-SfosFQDNHostMass sends every name in a single request' {
            Remove-SfosFQDNHostMass -Names 'Host1', 'Host2', 'Host3' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Name>Host1</Name>' -and
                $InnerXml -match '<Name>Host2</Name>' -and
                $InnerXml -match '<Name>Host3</Name>'
            }
        }

        It 'Remove-SfosFQDNHostMass should not call the API with -WhatIf' {
            Remove-SfosFQDNHostMass -Names 'Host1' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Export-SfosFQDNHosts / Import-SfosFQDNHosts - round trip and file errors' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Name>Exported</Name><Description>d</Description><FQDN>exported.example.com</FQDN></FQDNHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHost><Status code="200">Configuration applied successfully.</Status></FQDNHost></Response>' }
                }
            }
        }

        It 'Exports and re-imports the same FQDN host' {
            $csvPath = Join-Path $TestDrive 'fqdnhosts.csv'

            Export-SfosFQDNHosts -FilePath $csvPath @conn
            Import-SfosFQDNHosts -FilePath $csvPath @conn

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<FQDN>exported\.example\.com</FQDN>'
            }
        }

        It 'Import-SfosFQDNHosts should throw if the file does not exist' {
            { Import-SfosFQDNHosts -FilePath (Join-Path $TestDrive 'missing.csv') @conn } | Should -Throw '*was not found*'
        }
    }
}

Describe 'FQDNHostGroup - Extended Coverage' {

    Context 'Get-SfosFQDNHostGroup - parsing' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses FQDNHostList members into a string array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Name>SaaS</Name><Description>d</Description><FQDNHostList><FQDNHost>Outlook</FQDNHost><FQDNHost>Salesforce</FQDNHost></FQDNHostList></FQDNHostGroup></Response>' }
            }

            $result = @(Get-SfosFQDNHostGroup @conn)
            $result[0].FQDNHostList | Should -Be @('Outlook', 'Salesforce')
        }
    }

    Context 'New-SfosFQDNHostGroup - XML generation' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Set/add request with members' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Status code="200">Configuration applied successfully.</Status></FQDNHostGroup></Response>' }
            }

            New-SfosFQDNHostGroup -Name 'SaaS' -Members @('Outlook') -Description 'SaaS apps' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<FQDNHost>Outlook</FQDNHost>'
            }
        }
    }

    Context 'Set-SfosFQDNHostGroup - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Name>SaaS</Name><Description>original</Description><FQDNHostList><FQDNHost>Outlook</FQDNHost></FQDNHostList></FQDNHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Status code="200">Configuration applied successfully.</Status></FQDNHostGroup></Response>' }
                }
            }
        }

        It 'Keeps the existing Description when only members are changed' {
            Set-SfosFQDNHostGroup -Name 'SaaS' -Members @('Outlook', 'Salesforce') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<FQDNHost>Salesforce</FQDNHost>'
            }
        }
    }

    Context 'Add-SfosFQDNHostGroupMember / Remove-SfosFQDNHostGroupMember - preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Name>SaaS</Name><Description>keep-me</Description><FQDNHostList><FQDNHost>Outlook</FQDNHost></FQDNHostList></FQDNHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Status code="200">Configuration applied successfully.</Status></FQDNHostGroup></Response>' }
                }
            }
        }

        It 'Add-SfosFQDNHostGroupMember merges the new member and keeps the Description' {
            Add-SfosFQDNHostGroupMember -Name 'SaaS' -Members 'Salesforce' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<FQDNHost>Outlook</FQDNHost>' -and
                $InnerXml -match '<FQDNHost>Salesforce</FQDNHost>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }

        It 'Remove-SfosFQDNHostGroupMember drops only the named member and keeps the Description' {
            Remove-SfosFQDNHostGroupMember -Name 'SaaS' -Members 'Outlook' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<FQDNHost>Outlook</FQDNHost>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }
    }

    Context 'Remove-SfosFQDNHostGroup - XML generation' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Remove request' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Status code="200">Configuration applied successfully.</Status></FQDNHostGroup></Response>' }
            }

            Remove-SfosFQDNHostGroup -Name 'SaaS' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>SaaS</Name>'
            }
        }
    }

    Context 'Export-SfosFQDNHostGroups / Import-SfosFQDNHostGroups - round trip' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Name>ExportedGroup</Name><Description>d</Description><FQDNHostList><FQDNHost>Outlook</FQDNHost></FQDNHostList></FQDNHostGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FQDNHostGroup><Status code="200">Configuration applied successfully.</Status></FQDNHostGroup></Response>' }
                }
            }
        }

        It 'Exports and re-imports the same group' {
            $csvPath = Join-Path $TestDrive 'fqdnhostgroups.csv'

            Export-SfosFQDNHostGroups -FilePath $csvPath @conn
            $importResult = Import-SfosFQDNHostGroups -FilePath $csvPath @conn
            $importResult.SuccessItems | Should -Contain 'ExportedGroup'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<FQDNHost>Outlook</FQDNHost>'
            }
        }
    }
}

Describe 'MACHost - Extended Coverage' {

    Context 'Get-SfosMACHost - parsing single address and list' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses a single-address host' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Name>CEO-Laptop</Name><Type>MACAddress</Type><MACAddress>00:11:22:33:44:55</MACAddress><Description>d</Description></MACHost></Response>' }
            }

            $result = @(Get-SfosMACHost @conn)
            $result[0].MACAddress | Should -Be '00:11:22:33:44:55'
            $result[0].MACList | Should -Be @()
        }

        It 'Parses a MACList host' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Name>Dual-NIC</Name><Type>MACList</Type><MACList><MACAddress>00:11:22:33:44:55</MACAddress><MACAddress>00:11:22:33:44:66</MACAddress></MACList></MACHost></Response>' }
            }

            $result = @(Get-SfosMACHost @conn)
            $result[0].MACList | Should -Be @('00:11:22:33:44:55', '00:11:22:33:44:66')
        }
    }

    Context 'New-SfosMACHost - single address and list XML' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Status code="200">Configuration applied successfully.</Status></MACHost></Response>' }
            }
        }

        It 'Builds a single-address request with a MACAddress Type element' {
            New-SfosMACHost -Name 'CEO-Laptop' -MACAddress '00:11:22:33:44:55' -Description 'Executive' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                ($InnerXml -match '<Type>MACAddress</Type>') -and ($InnerXml -match '<MACAddress>00:11:22:33:44:55</MACAddress>')
            }
        }

        It 'Builds a MACList request with a MACList Type element for a comma-separated value' {
            New-SfosMACHost -Name 'Dual-NIC' -MACAddress '00:11:22:33:44:55,00:11:22:33:44:66' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $hasType = $InnerXml -match '<Type>MACList</Type>'
                $hasBoth = $InnerXml -match '<MACList>.*<MACAddress>00:11:22:33:44:55</MACAddress>.*<MACAddress>00:11:22:33:44:66</MACAddress>.*</MACList>'
                $hasType -and $hasBoth
            }
        }
    }

    Context 'Set-SfosMACHost - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Name>CEO-Laptop</Name><Type>MACAddress</Type><MACAddress>00:11:22:33:44:55</MACAddress><Description>original</Description></MACHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Status code="200">Configuration applied successfully.</Status></MACHost></Response>' }
                }
            }
        }

        It 'Keeps the existing Description when only MACAddress is changed' {
            Set-SfosMACHost -Name 'CEO-Laptop' -MACAddress 'AA:BB:CC:DD:EE:FF' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<MACAddress>AA:BB:CC:DD:EE:FF</MACAddress>'
            }
        }
    }

    Context 'Remove-SfosMACHost - documented 528 passthrough (live-verified)' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Passes the raw firewall 528 message through on a second remove of the same object' {
            # abnahme-hostsandservices-matrix.md #34: live-reproduced on FW1. Remove-SfosMACHost
            # does not read first, so this is the exact response the firewall returns, not a
            # "not found" message.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Status code="528">Trying to update default entities which are not editable.</Status></MACHost></Response>' }
            }

            { Remove-SfosMACHost -Name 'CEO-Laptop' @conn -Confirm:$false } | Should -Throw '*528*'
        }

        It 'Should not call the API with -WhatIf' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Status code="200">Configuration applied successfully.</Status></MACHost></Response>' }
            }

            Remove-SfosMACHost -Name 'CEO-Laptop' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Export-SfosMACHosts / Import-SfosMACHosts - round trip flattening MACList' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Name>Dual-NIC</Name><Type>MACList</Type><MACList><MACAddress>00:11:22:33:44:55</MACAddress><MACAddress>00:11:22:33:44:66</MACAddress></MACList></MACHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MACHost><Status code="200">Configuration applied successfully.</Status></MACHost></Response>' }
                }
            }
        }

        It 'Flattens the MACList into the comma-separated MACAddress column and re-imports it' {
            $csvPath = Join-Path $TestDrive 'machosts.csv'

            Export-SfosMACHosts -FilePath $csvPath @conn
            (Import-Csv -Path $csvPath).MACAddress | Should -Be '00:11:22:33:44:55,00:11:22:33:44:66'

            Import-SfosMACHosts -FilePath $csvPath @conn

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Type>MACList</Type>'
            }
        }
    }
}

Describe 'CountryGroup - Extended Coverage' {

    Context 'Get-SfosCountryGroup - parsing the CountryList wire element into Countries' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Exposes the CountryList wire element as the Countries property' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Name>BlockList</Name><Description>d</Description><CountryList><Country>Germany</Country><Country>France</Country></CountryList></CountryGroup></Response>' }
            }

            $result = @(Get-SfosCountryGroup @conn)
            $result[0].Countries | Should -Be @('Germany', 'France')
        }

        It '"No. of records Zero." should return an empty array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup transactionid=""><Status>No. of records Zero.</Status></CountryGroup></Response>' }
            }

            $result = @(Get-SfosCountryGroup -NameLike 'DoesNotExist' @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'New-SfosCountryGroup - sends the CountryList/Country wire elements, not the invented CountryHostGroup element' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Set/add request with the CountryList wrapper' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Status code="200">Configuration applied successfully.</Status></CountryGroup></Response>' }
            }

            New-SfosCountryGroup -Name 'BlockList' -Countries @('Germany', 'France') -Description 'EU' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<CountryList>' -and
                $InnerXml -match '<Country>Germany</Country>' -and
                $InnerXml -match '<Country>France</Country>' -and
                $InnerXml -notmatch 'CountryHostGroup'
            }
        }
    }

    Context 'Set-SfosCountryGroup - read-modify-write preservation and mandatory Countries' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Name>BlockList</Name><Description>original</Description><CountryList><Country>Germany</Country></CountryList></CountryGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Status code="200">Configuration applied successfully.</Status></CountryGroup></Response>' }
                }
            }
        }

        It 'Keeps the existing Description when Countries is extended' {
            Set-SfosCountryGroup -Name 'BlockList' -Countries @('Germany', 'North Korea') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<Country>North Korea</Country>'
            }
        }

        It 'Throws client-side when -Countries is empty (mandatory, ValidateNotNullOrEmpty)' {
            { Set-SfosCountryGroup -Name 'BlockList' -Countries @() @conn -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Remove-SfosCountryGroup - XML generation' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Remove request' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Status code="200">Configuration applied successfully.</Status></CountryGroup></Response>' }
            }

            Remove-SfosCountryGroup -Name 'BlockList' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>BlockList</Name>'
            }
        }

        It 'Should not call the API with -WhatIf' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CountryGroup><Status code="200">Configuration applied successfully.</Status></CountryGroup></Response>' }
            }

            Remove-SfosCountryGroup -Name 'BlockList' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }
}

Describe 'Service - Extended Coverage' {

    Context 'Get-SfosService - parsing every Type' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses a TCPorUDP service' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>HTTPS</Name><Description>d</Description><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><SourcePort>1:65535</SourcePort><DestinationPort>443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>' }
            }

            $result = @(Get-SfosService @conn)
            $result[0].Type | Should -Be 'TCPorUDP'
            $result[0].ServiceDetails.Protocol | Should -Be 'TCP'
            $result[0].ServiceDetails.DestinationPort | Should -Be '443'
        }

        It 'Parses an IP protocol service' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>GRE</Name><Type>IP</Type><ServiceDetails><ServiceDetail><ProtocolName>GRE</ProtocolName></ServiceDetail></ServiceDetails></Services></Response>' }
            }

            $result = @(Get-SfosService @conn)
            $result[0].ServiceDetails.ProtocolName | Should -Be 'GRE'
        }

        It 'Parses an ICMP service, including the text ICMPType/ICMPCode form the firewall returns' {
            # Live-observed: Get-SfosService returns ICMPType/ICMPCode as text ('Echo',
            # 'Any Code'), not the numeric code New-SfosService requires - the documented
            # round-trip defect (CLAUDE.md "Still open").
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>PING</Name><Type>ICMP</Type><ServiceDetails><ServiceDetail><ICMPType>Echo</ICMPType><ICMPCode>Any Code</ICMPCode></ServiceDetail></ServiceDetails></Services></Response>' }
            }

            $result = @(Get-SfosService @conn)
            $result[0].ServiceDetails.ICMPType | Should -Be 'Echo'
            $result[0].ServiceDetails.ICMPCode | Should -Be 'Any Code'
        }

        It 'Parses an ICMPv6 service' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>PING6</Name><Type>ICMPv6</Type><ServiceDetails><ServiceDetail><ICMPv6Type>Echo Request</ICMPv6Type><ICMPv6Code>Any Code</ICMPv6Code></ServiceDetail></ServiceDetails></Services></Response>' }
            }

            $result = @(Get-SfosService @conn)
            $result[0].ServiceDetails.ICMPv6Type | Should -Be 'Echo Request'
        }

        It '"No. of records Zero." should return an empty array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services transactionid=""><Status>No. of records Zero.</Status></Services></Response>' }
            }

            $result = @(Get-SfosService -NameLike 'DoesNotExist' @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'New-SfosService - XML per Type, including the ICMPCode regression fix' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Status code="200">Configuration applied successfully.</Status></Services></Response>' }
            }
        }

        It 'Builds an IP protocol service request' {
            New-SfosService -Name 'GRE-Protocol' -ProtocolName 'GRE' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match "<Type>IP</Type>" -and $InnerXml -match '<ProtocolName>GRE</ProtocolName>'
            }
        }

        It 'REGRESSION (2026-08-12 fix): omitting -ICMPCode sends ICMPCode -1 on the wire, not an empty element' {
            # Live-measured (abnahme-hostsandservices-matrix.md): an empty <ICMPCode></ICMPCode>
            # is rejected by the firewall with 501. Omitting -ICMPCode must default to '-1'
            # ("Any Code") on the wire, exactly like an existing PING service.
            New-SfosService -Name 'ICMP-Echo' -ICMPType '8' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $checks = @(
                    ($InnerXml -match '<Type>ICMP</Type>'),
                    ($InnerXml -match '<ICMPType>8</ICMPType>'),
                    ($InnerXml -match '<ICMPCode>-1</ICMPCode>'),
                    (-not ($InnerXml -match '<ICMPCode></ICMPCode>'))
                )
                $checks -notcontains $false
            }
        }

        It 'An explicit -ICMPCode is sent as supplied' {
            New-SfosService -Name 'ICMP-Echo' -ICMPType '8' -ICMPCode '0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ICMPCode>0</ICMPCode>'
            }
        }

        It 'Omitting -ICMPv6Code likewise defaults to -1 on the wire' {
            New-SfosService -Name 'ICMPv6-EchoRequest' -ICMPv6Type '128' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Type>ICMPv6</Type>' -and
                $InnerXml -match '<ICMPv6Code>-1</ICMPv6Code>'
            }
        }
    }

    Context 'Set-SfosService - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>CustomHTTPS</Name><Description>original</Description><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><SourcePort>1024:65535</SourcePort><DestinationPort>8443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Status code="200">Configuration applied successfully.</Status></Services></Response>' }
                }
            }
        }

        It 'Keeps the existing SrcPort and Description when only DstPort is changed' {
            Set-SfosService -Name 'CustomHTTPS' -Protocol TCP -DstPort '8444' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation=''update''>' -and
                $InnerXml -match '<SourcePort>1024:65535</SourcePort>' -and
                $InnerXml -match '<DestinationPort>8444</DestinationPort>' -and
                $InnerXml -match '<Description>original</Description>'
            }
        }

        It 'Throws when the target service does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services transactionid=""><Status>No. of records Zero.</Status></Services></Response>' }
            }

            { Set-SfosService -Name 'Ghost' -Protocol TCP -DstPort '443' @conn -Confirm:$false } | Should -Throw '*was not found*'
        }
    }

    Context 'Remove-SfosService - XML generation' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Remove request against the Services element' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Status code="200">Configuration applied successfully.</Status></Services></Response>' }
            }

            Remove-SfosService -Name 'CustomHTTPS' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Services>' -and $InnerXml -match '<Name>CustomHTTPS</Name>'
            }
        }

        It 'Should not call the API with -WhatIf' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Status code="200">Configuration applied successfully.</Status></Services></Response>' }
            }

            Remove-SfosService -Name 'CustomHTTPS' @conn -WhatIf

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Export-SfosServices / Import-SfosServices - round trip and the documented ICMP import failure' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Exports a TCPorUDP service and re-imports it' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Name>ExportedSvc</Name><Description>d</Description><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><SourcePort>1:65535</SourcePort><DestinationPort>9443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Services><Status code="200">Configuration applied successfully.</Status></Services></Response>' }
                }
            }

            $csvPath = Join-Path $TestDrive 'services.csv'
            Export-SfosServices -FilePath $csvPath @conn
            $importResult = Import-SfosServices -FilePath $csvPath @conn
            $importResult.SuccessItems | Should -Contain 'ExportedSvc'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match "<Set operation='add'>" -and $InnerXml -match '<DestinationPort>9443</DestinationPort>'
            }
        }

        It 'Reports ICMP rows as named failures instead of attempting an import (documented, CLAUDE.md "Still open")' {
            $csvPath = Join-Path $TestDrive 'icmp-services.csv'
            @([PSCustomObject]@{ Name = 'PING'; Description = ''; Type = 'ICMP'; Protocol = ''; SrcPort = ''; DstPort = ''; ProtocolName = ''; ICMPType = 'Echo'; ICMPCode = 'Any Code'; ICMPv6Type = ''; ICMPv6Code = '' }) |
                Export-Csv -Path $csvPath -NoTypeInformation

            $result = Import-SfosServices -FilePath $csvPath @conn

            $result.Failed | Should -Be 1
            $result.FailedItems[0].Name | Should -Be 'PING'
            $result.FailedItems[0].Error | Should -Match 'ICMP services cannot be imported automatically'
        }

        It 'Reports ICMPv6 rows as named failures the same way' {
            $csvPath = Join-Path $TestDrive 'icmpv6-services.csv'
            @([PSCustomObject]@{ Name = 'PING6'; Description = ''; Type = 'ICMPv6'; Protocol = ''; SrcPort = ''; DstPort = ''; ProtocolName = ''; ICMPType = ''; ICMPCode = ''; ICMPv6Type = 'Echo Request'; ICMPv6Code = 'Any Code' }) |
                Export-Csv -Path $csvPath -NoTypeInformation

            $result = Import-SfosServices -FilePath $csvPath @conn

            $result.Failed | Should -Be 1
            $result.FailedItems[0].Error | Should -Match 'ICMPv6 services cannot be imported automatically'
        }

        It 'Import-SfosServices should throw if the file does not exist' {
            { Import-SfosServices -FilePath (Join-Path $TestDrive 'missing.csv') @conn } | Should -Throw '*was not found*'
        }
    }
}

Describe 'ServiceGroup - Extended Coverage' {

    Context 'Get-SfosServiceGroup - parsing' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Parses ServiceList members into a string array' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Name>WebServices</Name><Description>d</Description><ServiceList><Service>HTTP</Service><Service>HTTPS</Service></ServiceList></ServiceGroup></Response>' }
            }

            $result = @(Get-SfosServiceGroup @conn)
            $result[0].ServiceList | Should -Be @('HTTP', 'HTTPS')
        }
    }

    Context 'New-SfosServiceGroup - members are mandatory (documented API requirement)' {

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
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Status code="200">Configuration applied successfully.</Status></ServiceGroup></Response>' }
            }
        }

        It 'Builds a Set/add request with the ServiceList wrapper' {
            New-SfosServiceGroup -Name 'WebServices' -Members @('HTTP', 'HTTPS') -Description 'Web' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Service>HTTP</Service>' -and
                $InnerXml -match '<Service>HTTPS</Service>'
            }
        }

        It 'Throws client-side when -Members is empty - the API marks Service mandatory, unlike IPHostGroup/FQDNHostGroup' {
            { New-SfosServiceGroup -Name 'Empty' -Members @() @conn -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 0 -Exactly
        }
    }

    Context 'Set-SfosServiceGroup - read-modify-write preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Name>WebServices</Name><Description>original</Description><ServiceList><Service>HTTP</Service></ServiceList></ServiceGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Status code="200">Configuration applied successfully.</Status></ServiceGroup></Response>' }
                }
            }
        }

        It 'Keeps the existing Description when only members are changed' {
            Set-SfosServiceGroup -Name 'WebServices' -Members @('HTTP', 'HTTPS') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<Service>HTTPS</Service>'
            }
        }
    }

    Context 'Add-SfosServiceGroupMember / Remove-SfosServiceGroupMember - preservation' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Name>WebServices</Name><Description>keep-me</Description><ServiceList><Service>HTTP</Service><Service>HTTPS</Service></ServiceList></ServiceGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Status code="200">Configuration applied successfully.</Status></ServiceGroup></Response>' }
                }
            }
        }

        It 'Add-SfosServiceGroupMember merges the new member and keeps the Description' {
            Add-SfosServiceGroupMember -Name 'WebServices' -Members 'FTP' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Service>HTTP</Service>' -and
                $InnerXml -match '<Service>FTP</Service>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }

        It 'Add-SfosServiceGroupMember binds through the legacy ServiceGroupName alias' {
            Add-SfosServiceGroupMember -ServiceGroupName 'WebServices' -Members 'FTP' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Name>WebServices</Name>'
            }
        }

        It 'Remove-SfosServiceGroupMember drops only the named member, keeps the rest and the Description' {
            # Two members in the fixture: removing one must not trip the "would leave the
            # group empty" guard, which only fires when removal empties the list.
            Remove-SfosServiceGroupMember -Name 'WebServices' -Members 'HTTP' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<Service>HTTP</Service>' -and
                $InnerXml -match '<Service>HTTPS</Service>' -and
                $InnerXml -match '<Description>keep-me</Description>'
            }
        }
    }

    Context 'Remove-SfosServiceGroup - XML generation' {

        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        It 'Builds a Remove request' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Status code="200">Configuration applied successfully.</Status></ServiceGroup></Response>' }
            }

            Remove-SfosServiceGroup -Name 'WebServices' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>WebServices</Name>'
            }
        }
    }

    Context 'Export-SfosServiceGroups / Import-SfosServiceGroups - round trip' {

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
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Name>ExportedGroup</Name><Description>d</Description><ServiceList><Service>HTTP</Service></ServiceList></ServiceGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ServiceGroup><Status code="200">Configuration applied successfully.</Status></ServiceGroup></Response>' }
                }
            }
        }

        It 'Exports and re-imports the same group' {
            $csvPath = Join-Path $TestDrive 'servicegroups.csv'

            Export-SfosServiceGroups -FilePath $csvPath @conn
            $importResult = Import-SfosServiceGroups -FilePath $csvPath @conn
            $importResult.SuccessItems | Should -Contain 'ExportedGroup'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.HostsAndServices -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<Service>HTTP</Service>'
            }
        }
    }
}

#endregion Extended per-function coverage

