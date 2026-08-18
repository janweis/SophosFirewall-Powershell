#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Web module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

# Get module path - use relative paths that work in any environment
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Web\SophosFirewall.Web.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module manifest not found: $ModulePath"
    exit 1
}

# Import modules
Import-Module $CoreModulePath -Force
Import-Module $ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Web module should load' {
        Get-Module SophosFirewall.Web | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 54 functions' {
        (Get-Module SophosFirewall.Web).ExportedFunctions.Count | Should -Be 54
    }

    Context 'Private helpers are not exported' {
        # These build the WebFilterPolicy XML internally. If the manifest's
        # FunctionsToExport ever grew to include them by accident, callers could bypass the
        # read-modify-write logic in Set-/Add-/Remove-SfosWebFilterPolicy*.
        It 'ConvertTo-SfosWebFilterPolicyCategoryXml should not be visible' {
            Get-Command ConvertTo-SfosWebFilterPolicyCategoryXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosWebFilterPolicyRuleXml should not be visible' {
            Get-Command ConvertTo-SfosWebFilterPolicyRuleXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosWebFilterPolicyEntityXml should not be visible' {
            Get-Command ConvertTo-SfosWebFilterPolicyEntityXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
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

        # One shared success response covering every entity area exercised in this Describe -
        # Assert-SfosApiReturnSuccess only looks at the <Status> under the object name the
        # calling cmdlet passes, so the unrelated blocks are simply ignored.
        $okResponse = @'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup><Status code="200">Configuration applied successfully.</Status></WebFilterURLGroup>
  <FileType><Status code="200">Configuration applied successfully.</Status></FileType>
  <WebFilterCategory><Status code="200">Configuration applied successfully.</Status></WebFilterCategory>
  <UserActivity><Status code="200">Configuration applied successfully.</Status></UserActivity>
  <WebFilterException><Status code="200">Configuration applied successfully.</Status></WebFilterException>
  <WebFilterPolicy><Status code="200">Configuration applied successfully.</Status></WebFilterPolicy>
</Response>
'@
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = $okResponse }
        }
    }

    Context 'New-SfosWebFilterURLGroup' {
        It 'Should wrap members in the lowercase URLlist element, not URLList' {
            New-SfosWebFilterURLGroup -Name 'AllowedNews' -Members @('news.example.com', 'news2.example.com') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -cmatch '<URLlist>' -and
                $InnerXml -cnotmatch '<URLList>' -and
                $InnerXml -match '<URL>news\.example\.com</URL>' -and
                $InnerXml -match '<URL>news2\.example\.com</URL>' -and
                $InnerXml -match '<Set operation="add">'
            }
        }
    }

    Context 'New-SfosFileType' {
        It 'Should wrap extensions and MIME headers in FileExtensionList/MIMEHeaderList' {
            New-SfosFileType -Name 'Archives' -FileExtension @('zip', 'rar') -MIMEHeader @('application/zip') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<FileExtensionList><FileExtension>zip</FileExtension><FileExtension>rar</FileExtension></FileExtensionList>' -and
                $InnerXml -match '<MIMEHeaderList><MIMEHeader>application/zip</MIMEHeader></MIMEHeaderList>' -and
                $InnerXml -match '<Set operation="add">'
            }
        }
    }

    Context 'New-SfosWebFilterCategory' {
        It 'Should send Classification, QoSPolicy and ConfigureCategory=Local for a domain-matched category' {
            New-SfosWebFilterCategory -Name 'LocalCat' -Classification Productive -QoSPolicy None -Domain 'example.com' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Classification>Productive</Classification>' -and
                $InnerXml -match '<QoSPolicy>None</QoSPolicy>' -and
                $InnerXml -match '<ConfigureCategory>Local</ConfigureCategory>' -and
                $InnerXml -match '<DomainList><Domain>example\.com</Domain></DomainList>' -and
                $InnerXml -match '<Set operation="add">'
            }
        }

        It 'Should send ConfigureCategory=External for a URL-matched category' {
            New-SfosWebFilterCategory -Name 'ExternalCat' -Classification Acceptable -QoSPolicy None -Url 'example.com/list.txt' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ConfigureCategory>External</ConfigureCategory>' -and
                $InnerXml -match '<URLList><URL>example\.com/list\.txt</URL></URLList>'
            }
        }
    }

    Context 'New-SfosWebFilterException' {
        It 'Should send CertValidation and Enabled, and derive the Enable* flags from the supplied lists' {
            New-SfosWebFilterException -Name 'Exception1' -SourceIPAddress '10.0.1.0/24' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<CertValidation>on</CertValidation>' -and
                $InnerXml -match '<Enabled>on</Enabled>' -and
                $InnerXml -match '<EnableSrcIP>yes</EnableSrcIP>' -and
                $InnerXml -match '<EnableDstIP>no</EnableDstIP>' -and
                $InnerXml -match '<EnableURLRegex>no</EnableURLRegex>' -and
                $InnerXml -match '<EnableWebCat>no</EnableWebCat>' -and
                $InnerXml -match '<Set operation="add">'
            }
        }

        It 'Should wrap SrcIp/DstIp/URLRegex/WebCategory in exactly one DomainList' {
            New-SfosWebFilterException -Name 'Exception1' -SourceIPAddress '10.0.1.0/24' -WebCategory 'Gambling' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                ([regex]::Matches($InnerXml, '<DomainList>')).Count -eq 1 -and
                $InnerXml -match '<DomainList>\s*<SrcIp>10\.0\.1\.0/24</SrcIp>\s*<WebCategory>Gambling</WebCategory>'
            }
        }
    }

    Context 'New-SfosWebFilterPolicy' {
        It 'Should build RuleList/Rule/CategoryList/Category with a lowercase type element' {
            $category = New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory
            $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny

            New-SfosWebFilterPolicy -Name 'Restricted' -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<RuleList><Rule><CategoryList><Category><ID>Weapons</ID><type>WebCategory</type></Category></CategoryList>' -and
                $InnerXml -cmatch '<type>WebCategory</type>' -and
                $InnerXml -cnotmatch '<Type>WebCategory</Type>' -and
                $InnerXml -match '<Set operation="add">'
            }
        }
    }
}

Describe 'Read-Modify-Write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosWebFilterURLGroup' {
        BeforeEach {
            # Set-SfosWebFilterURLGroup reads the current group before writing, so the mock
            # has to answer a <Get> with a matching group - otherwise the read-modify-write
            # cannot find it.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup>
    <Name>ExampleGroup</Name>
    <Description>Original description</Description>
    <URLlist><URL>a.example.com</URL><URL>b.example.com</URL></URLlist>
  </WebFilterURLGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
                }
            }
        }

        It 'Should resend the existing URLs when only the description changes' {
            # SFOS replaces the whole entity on update - omitting URLlist would clear it.
            Set-SfosWebFilterURLGroup -Name 'ExampleGroup' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<URL>a\.example\.com</URL>' -and
                $InnerXml -match '<URL>b\.example\.com</URL>'
            }
        }
    }

    Context 'Set-SfosWebFilterPolicy' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterPolicy>
    <Name>ExamplePolicy</Name>
    <Description>Original description</Description>
    <DefaultAction>Allow</DefaultAction>
    <DownloadFileSizeRestriction>100</DownloadFileSizeRestriction>
    <RuleList>
      <Rule>
        <CategoryList><Category><ID>Weapons</ID><type>WebCategory</type></Category></CategoryList>
        <HTTPAction>Deny</HTTPAction>
        <HTTPSAction>Deny</HTTPSAction>
        <FollowHTTPAction>0</FollowHTTPAction>
        <Schedule>All The Time</Schedule>
        <PolicyRuleEnabled>1</PolicyRuleEnabled>
        <CCLRuleEnabled>0</CCLRuleEnabled>
      </Rule>
    </RuleList>
  </WebFilterPolicy>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Status code="200">OK</Status></WebFilterPolicy></Response>' }
                }
            }
        }

        It 'Should resend DownloadFileSizeRestriction and the existing RuleList when only the description changes' {
            # DownloadFileSizeRestriction is mandatory on every write per the API, and an
            # omitted RuleList would be cleared - both must survive an unrelated update.
            Set-SfosWebFilterPolicy -Name 'ExamplePolicy' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<DownloadFileSizeRestriction>100</DownloadFileSizeRestriction>' -and
                $InnerXml -match '<DefaultAction>Allow</DefaultAction>' -and
                $InnerXml -match '<Category><ID>Weapons</ID><type>WebCategory</type></Category>'
            }
        }
    }

    Context 'Set-SfosWebFilterException' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterException>
    <Name>ExampleException</Name>
    <Desc>Original description</Desc>
    <Enabled>on</Enabled>
    <CertValidation>on</CertValidation>
    <EnableSrcIP>yes</EnableSrcIP>
    <EnableDstIP>no</EnableDstIP>
    <EnableURLRegex>no</EnableURLRegex>
    <EnableWebCat>no</EnableWebCat>
    <DomainList><SrcIp>10.0.0.0/24</SrcIp></DomainList>
    <IsDefault>no</IsDefault>
  </WebFilterException>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterException><Status code="200">OK</Status></WebFilterException></Response>' }
                }
            }
        }

        It 'Should resend CertValidation and the existing SourceIPAddress when only the description changes' {
            # CertValidation is undocumented but required on every write [live], and an
            # omitted DomainList entry would clear that match criterion.
            Set-SfosWebFilterException -Name 'ExampleException' -Desc 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Desc>Updated description</Desc>' -and
                $InnerXml -match '<CertValidation>on</CertValidation>' -and
                $InnerXml -match '<EnableSrcIP>yes</EnableSrcIP>' -and
                $InnerXml -match '<SrcIp>10\.0\.0\.0/24</SrcIp>'
            }
        }
    }
}

Describe 'UserActivity NewName safety net' {
    # An update to UserActivity sent without <NewName> answers HTTP 200 / status code 200,
    # but renames the object to an EMPTY name - the object becomes an unreachable orphan under
    # its old name. Set-SfosUserActivity, Add-SfosUserActivityMember and
    # Remove-SfosUserActivityMember all update the object internally, so all three must
    # always send <NewName> - the caller's new name, or the object's current name when the
    # caller is not renaming.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosUserActivity' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
                }
            }
        }

        It 'Should always send NewName set to the current name when -NewName is not supplied' {
            Set-SfosUserActivity -Name 'Activity1' -Desc 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<NewName>Activity1</NewName>'
            }
        }

        It 'Should send the supplied NewName when renaming' {
            Set-SfosUserActivity -Name 'Activity1' -NewName 'Activity1Renamed' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<NewName>Activity1Renamed</NewName>'
            }
        }
    }

    Context 'Add-SfosUserActivityMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
                }
            }
        }

        It 'Should always send NewName set to the current, unchanged name' {
            Add-SfosUserActivityMember -Name 'Activity1' -Members @([PSCustomObject]@{ ID = 'Image Search'; Type = 'web category' }) @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<NewName>Activity1</NewName>'
            }
        }
    }

    Context 'Remove-SfosUserActivityMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList>
      <Category><ID>Search Engines</ID><type>web category</type></Category>
      <Category><ID>Image Search</ID><type>web category</type></Category>
    </CategoryList>
  </UserActivity>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
                }
            }
        }

        It 'Should always send NewName set to the current, unchanged name' {
            Remove-SfosUserActivityMember -Name 'Activity1' -Members @([PSCustomObject]@{ ID = 'Search Engines'; Type = 'web category' }) @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<NewName>Activity1</NewName>'
            }
        }
    }
}

Describe 'Error Paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-* on a non-existent object' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup><Status>No. of records Zero.</Status></WebFilterURLGroup>
</Response>
'@
                }
            }
        }

        It 'Should throw an error naming the entity type and the object name' {
            { Set-SfosWebFilterURLGroup -Name 'DoesNotExist' -Description 'x' @conn -Confirm:$false } |
                Should -Throw '*WebFilterURLGroup*DoesNotExist*'
        }
    }

    Context 'A firewall error response' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup><Status code="500">Operation could not be performed on Entity.</Status></WebFilterURLGroup>
</Response>
'@
                }
            }
        }

        It 'Should throw for New-SfosWebFilterURLGroup' {
            { New-SfosWebFilterURLGroup -Name 'ErrCase' -Members 'x' @conn -Confirm:$false } | Should -Throw
        }
    }

    Context 'New-SfosWebFilterException without any match criterion' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterException><Status code="200">OK</Status></WebFilterException></Response>' }
            }
        }

        It 'Should throw client-side without ever calling the API' {
            { New-SfosWebFilterException -Name 'NoCriteria' @conn -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
        }
    }
}

Describe 'XML Escaping' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
        }
    }

    It 'Should escape ampersand and angle brackets in the object name' {
        New-SfosWebFilterURLGroup -Name 'A&B<C>' -Members 'x' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Name>A&amp;B&lt;C&gt;</Name>'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup><Name>NewsAllow</Name><Description>production</Description><URLlist><URL>news.example.com</URL></URLlist></WebFilterURLGroup>
  <WebFilterURLGroup><Name>NewsBlock</Name><Description>staging</Description><URLlist><URL>badnews.example.com</URL></URLlist></WebFilterURLGroup>
  <WebFilterURLGroup><Name>VendorAllow</Name><Description>production</Description><URLlist><URL>vendor.example.com</URL></URLlist></WebFilterURLGroup>
</Response>
'@
            }
        }
    }

    It 'Should combine NameLike and DescriptionLike with AND, not OR' {
        $result = @(Get-SfosWebFilterURLGroup -NameLike 'News' -DescriptionLike 'production' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'NewsAllow'
    }

    It 'Should apply the same filtering to -AsXml as to the default output' {
        $result = @(Get-SfosWebFilterURLGroup -NameLike 'News' -DescriptionLike 'production' -AsXml @conn)

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
        $result[0].Name | Should -Be 'NewsAllow'
    }

    It 'Should return an empty array when nothing matches' {
        $result = @(Get-SfosWebFilterURLGroup -NameLike 'DoesNotExist' @conn)

        $result.Count | Should -Be 0
    }
}

Describe 'WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
        }
    }

    It 'Remove-SfosWebFilterURLGroup should not call the API with -WhatIf' {
        Remove-SfosWebFilterURLGroup -Name 'Example' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }
}


Describe 'New-SfosWebFilterPolicyRule -InputObject' {

    # Without -InputObject every omitted parameter takes its default, so rebuilding a rule to
    # change one field also resets Schedule and the enabled flags. Editing an existing rule
    # has to leave everything else alone.

    BeforeAll {
        $script:baseRule = [PSCustomObject]@{
            CategoryList      = @([PSCustomObject]@{ ID = 'Extreme'; Type = 'WebCategory' })
            HTTPAction        = 'Deny'
            HTTPSAction       = 'Deny'
            FollowHTTPAction  = '1'
            Schedule          = 'Work hours (5 Day week)'
            PolicyRuleEnabled = '1'
            CCLRuleEnabled    = '1'
            ExceptionList     = @('Archive Files')
            UserList          = @('someuser')
            CCLList           = @('somelist')
        }
    }

    It 'Should override only the supplied field' {
        $result = $script:baseRule | New-SfosWebFilterPolicyRule -HTTPAction Allow

        $result.HTTPAction | Should -Be 'Allow'
        $result.HTTPSAction | Should -Be 'Deny'
        $result.FollowHTTPAction | Should -Be '1'
        $result.PolicyRuleEnabled | Should -Be '1'
        $result.CCLRuleEnabled | Should -Be '1'
    }

    It 'Should keep the schedule instead of falling back to the default' {
        # The default is 'All The Time'. Losing a business-hours schedule would widen the
        # rule to around the clock without any error.
        $result = $script:baseRule | New-SfosWebFilterPolicyRule -HTTPAction Allow

        $result.Schedule | Should -Be 'Work hours (5 Day week)'
    }

    It 'Should carry the categories and list fields across' {
        $result = $script:baseRule | New-SfosWebFilterPolicyRule -HTTPAction Allow

        @($result.CategoryList).Count | Should -Be 1
        $result.CategoryList[0].ID | Should -Be 'Extreme'
        @($result.ExceptionList) | Should -Be @('Archive Files')
        @($result.UserList) | Should -Be @('someuser')
        @($result.CCLList) | Should -Be @('somelist')
    }

    It 'Should still apply its defaults when no InputObject is supplied' {
        $category = New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory
        $result = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Warn

        $result.HTTPSAction | Should -Be 'Deny'
        $result.Schedule | Should -Be 'All The Time'
        $result.PolicyRuleEnabled | Should -Be '1'
    }

    It 'Should require -Category when there is no InputObject to take it from' {
        { New-SfosWebFilterPolicyRule -HTTPAction Deny } | Should -Throw '*needs -Category*'
    }
}

<#
    Everything below extends coverage to the remaining exported functions that the
    original suite above did not touch: every Get-* parsing shape, every write-cmdlet's
    generated XML, every Set-*'s read-modify-write preservation (including the five
    settings singletons), the module's own status-handling edge cases (217/222 warn,
    code-less "Transaction fail" throws), and the client-side error paths each cmdlet
    carries. See tools/coverage notes in the accompanying report for the full function
    list this closes.
#>

Describe 'Status Handling Edge Cases' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Undocumented code 217 (External WebFilterCategory create)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="217">Unable to get status message</Status></WebFilterCategory></Response>' }
            }
        }

        It 'Should not throw and should warn instead' {
            { New-SfosWebFilterCategory -Name 'ExtCat' -Classification Acceptable -QoSPolicy None -Url 'example.com/list.txt' @conn -Confirm:$false -WarningAction SilentlyContinue } | Should -Not -Throw

            $streams = New-SfosWebFilterCategory -Name 'ExtCat3' -Classification Acceptable -QoSPolicy None -Url 'example.com/list3.txt' @conn -Confirm:$false 3>&1
            $warnings = @($streams | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $warnings.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Undocumented code 222' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="222">Unable to get status message</Status></WebFilterCategory></Response>' }
            }
        }

        It 'Should not throw' {
            { New-SfosWebFilterCategory -Name 'ExtCat2' -Classification Acceptable -QoSPolicy None -Url 'example.com/list2.txt' @conn -Confirm:$false -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'Code 201 "Operation partially successful" (append-only URLList shrink attempt)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterCategory>
    <Name>ExternalCat</Name>
    <Classification>Acceptable</Classification>
    <QoSPolicy>None</QoSPolicy>
    <ConfigureCategory>External</ConfigureCategory>
    <URLList><URL>a.example.com</URL><URL>b.example.com</URL></URLList>
  </WebFilterCategory>
</Response>
'@
                    }
                }
                else {
                    # Live-observed: sending fewer URLs than currently stored answers 201 and
                    # removes nothing - the firewall's URLList is append-only on update.
                    [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="201">Operation partially successful.</Status></WebFilterCategory></Response>' }
                }
            }
        }

        It 'Should send only the reduced URL list the caller asked for' {
            Set-SfosWebFilterCategory -Name 'ExternalCat' -ConfigureCategory External -Url 'a.example.com' @conn -Confirm:$false -WarningAction SilentlyContinue

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<URL>a\.example\.com</URL>' -and
                $InnerXml -notmatch '<URL>b\.example\.com</URL>'
            }
        }

        It 'Should not throw even though the firewall silently kept both URLs (code 201 is a warning, not a failure)' {
            { Set-SfosWebFilterCategory -Name 'ExternalCat' -ConfigureCategory External -Url 'a.example.com' @conn -Confirm:$false -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'Code-less "Transaction fail" (ContentConditionList Name filter)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status>Transaction fail</Status></ContentConditionList></Response>' }
            }
        }

        It 'Should throw rather than reading it as an empty result' {
            { Get-SfosContentConditionList -KeyLike 'DoesNotMatter' @conn } | Should -Throw '*Transaction fail*'
        }
    }

    Context 'Code-less "No. of records Zero." (genuinely empty result)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status>No. of records Zero.</Status></ContentConditionList></Response>' }
            }
        }

        It 'Should return an empty array without throwing' {
            $result = @(Get-SfosContentConditionList @conn)
            $result.Count | Should -Be 0
        }
    }
}

Describe 'Get Parsing - FileType' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'A populated object' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FileType>
    <Name>Archives</Name>
    <Description>Common archives</Description>
    <FileExtensionList><FileExtension>zip</FileExtension><FileExtension>rar</FileExtension></FileExtensionList>
    <MIMEHeaderList><MIMEHeader>application/zip</MIMEHeader></MIMEHeaderList>
  </FileType>
</Response>
'@
                }
            }
        }

        It 'Should parse Name, Description, FileExtensionList and MIMEHeaderList' {
            $result = @(Get-SfosFileType @conn)[0]

            $result.Name | Should -Be 'Archives'
            $result.Description | Should -Be 'Common archives'
            @($result.FileExtensionList) | Should -Be @('zip', 'rar')
            @($result.MIMEHeaderList) | Should -Be @('application/zip')
        }

        It 'Should not expose a Template property' {
            $result = @(Get-SfosFileType @conn)[0]
            ($result.PSObject.Properties.Name -contains 'Template') | Should -Be $false
        }
    }

    Context 'An object with no extensions or headers' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><FileType><Name>Empty</Name></FileType></Response>' }
            }
        }

        It 'Should return empty arrays, not $null' {
            $result = @(Get-SfosFileType @conn)[0]
            @($result.FileExtensionList).Count | Should -Be 0
            @($result.MIMEHeaderList).Count | Should -Be 0
        }
    }
}

Describe 'Additional XML Generation - FileType/URLGroup members' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosFileType -Template' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><FileType><Status code="200">OK</Status></FileType></Response>' }
            }
        }

        It 'Should send the Template element when supplied' {
            New-SfosFileType -Name 'Templated' -Template 'Blank' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Template>Blank</Template>'
            }
        }
    }

    Context 'Remove-SfosFileType' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><FileType><Status code="200">OK</Status></FileType></Response>' }
            }
        }

        It 'Should send a Remove request naming the object' {
            Remove-SfosFileType -Name 'Archives' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Archives</Name>'
            }
        }
    }

    Context 'Remove-SfosWebFilterURLGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
            }
        }

        It 'Should send a Remove request naming the object' {
            Remove-SfosWebFilterURLGroup -Name 'AllowedNews' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>AllowedNews</Name>'
            }
        }
    }

    Context 'Add-SfosWebFilterURLGroupMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup>
    <Name>AllowedNews</Name>
    <Description>Approved sites</Description>
    <URLlist><URL>news.example.com</URL></URLlist>
  </WebFilterURLGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
                }
            }
        }

        It 'Should merge the new member with the existing one and preserve Description' {
            Add-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<URL>news\.example\.com</URL>' -and
                $InnerXml -match '<URL>news2\.example\.com</URL>' -and
                $InnerXml -match '<Description>Approved sites</Description>'
            }
        }
    }

    Context 'Remove-SfosWebFilterURLGroupMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterURLGroup>
    <Name>AllowedNews</Name>
    <Description>Approved sites</Description>
    <URLlist><URL>news.example.com</URL><URL>news2.example.com</URL></URLlist>
  </WebFilterURLGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">OK</Status></WebFilterURLGroup></Response>' }
                }
            }
        }

        It 'Should resend only the remaining member' {
            Remove-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<URL>news\.example\.com</URL>' -and
                $InnerXml -notmatch '<URL>news2\.example\.com</URL>'
            }
        }
    }

    Context 'Remove-SfosWebFilterURLGroupMember on a group with no members' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Name>Empty</Name></WebFilterURLGroup></Response>' }
            }
        }

        It 'Should return without calling the API again for the Set' {
            Remove-SfosWebFilterURLGroupMember -Name 'Empty' -Members 'x.example.com' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter { $InnerXml -match '<Get>' }
        }
    }
}

Describe 'Set-SfosFileType Read-Modify-Write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FileType>
    <Name>Archives</Name>
    <Description>Original description</Description>
    <FileExtensionList><FileExtension>zip</FileExtension><FileExtension>rar</FileExtension></FileExtensionList>
    <MIMEHeaderList><MIMEHeader>application/zip</MIMEHeader></MIMEHeaderList>
  </FileType>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FileType><Status code="200">OK</Status></FileType></Response>' }
            }
        }
    }

    It 'Should resend the existing extensions and MIME headers when only the description changes' {
        Set-SfosFileType -Name 'Archives' -Description 'Updated description' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Description>Updated description</Description>' -and
            $InnerXml -match '<FileExtension>zip</FileExtension>' -and
            $InnerXml -match '<FileExtension>rar</FileExtension>' -and
            $InnerXml -match '<MIMEHeader>application/zip</MIMEHeader>'
        }
    }

    It 'Should not expose a -Template parameter (the firewall never returns it, so it cannot be preserved)' {
        (Get-Command Set-SfosFileType).Parameters.ContainsKey('Template') | Should -Be $false
    }
}

Describe 'Get Parsing - WebFilterCategory' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterCategory>
    <Name>LocalCat</Name>
    <Classification>Productive</Classification>
    <ConfigureCategory>Local</ConfigureCategory>
    <QoSPolicy>None</QoSPolicy>
    <DomainList><Domain>example.com</Domain></DomainList>
  </WebFilterCategory>
  <WebFilterCategory>
    <Name>OtherCat</Name>
    <Classification>Unproductive</Classification>
    <ConfigureCategory>Local</ConfigureCategory>
    <QoSPolicy>None</QoSPolicy>
  </WebFilterCategory>
</Response>
'@
            }
        }
    }

    It 'Should parse Classification, ConfigureCategory, QoSPolicy and DomainList' {
        $result = @(Get-SfosWebFilterCategory @conn | Where-Object { $_.Name -eq 'LocalCat' })[0]

        $result.Classification | Should -Be 'Productive'
        $result.ConfigureCategory | Should -Be 'Local'
        $result.QoSPolicy | Should -Be 'None'
        @($result.DomainList) | Should -Be @('example.com')
    }

    It 'Should yield an empty array for absent KeywordList/URLList' {
        # An absent element ($node.KeywordList is $null) must come back as @(), not a
        # one-element array holding an empty string.
        $result = @(Get-SfosWebFilterCategory @conn | Where-Object { $_.Name -eq 'LocalCat' })[0]
        @($result.KeywordList).Count | Should -Be 0
        @($result.URLList).Count | Should -Be 0
    }

    It 'Should apply -ClassificationLike client-side' {
        $result = @(Get-SfosWebFilterCategory -ClassificationLike 'Unproductive' @conn)
        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'OtherCat'
    }
}

Describe 'New-SfosWebFilterCategory client-side validation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="200">OK</Status></WebFilterCategory></Response>' }
        }
    }

    It 'Should reject a Domain entry over 250 characters without calling the API' {
        $longDomain = 'a' * 251
        { New-SfosWebFilterCategory -Name 'TooLong' -Classification Productive -QoSPolicy None -Domain $longDomain @conn -Confirm:$false } | Should -Throw '*250 characters*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }

    It 'Should reject a URL that includes a scheme without calling the API' {
        { New-SfosWebFilterCategory -Name 'BadUrl' -Classification Productive -QoSPolicy None -Url 'https://example.com/list.txt' @conn -Confirm:$false } | Should -Throw '*scheme*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }
}

Describe 'Set-SfosWebFilterCategory Read-Modify-Write (Local)' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterCategory>
    <Name>LocalCat</Name>
    <Classification>Productive</Classification>
    <ConfigureCategory>Local</ConfigureCategory>
    <QoSPolicy>None</QoSPolicy>
    <Description>Original description</Description>
    <DomainList><Domain>example.com</Domain></DomainList>
  </WebFilterCategory>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="200">OK</Status></WebFilterCategory></Response>' }
            }
        }
    }

    It 'Should resend Classification, QoSPolicy and Domain when only the description changes' {
        Set-SfosWebFilterCategory -Name 'LocalCat' -ConfigureCategory Local -Description 'Updated description' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Classification>Productive</Classification>' -and
            $InnerXml -match '<QoSPolicy>None</QoSPolicy>' -and
            $InnerXml -match '<Domain>example\.com</Domain>' -and
            $InnerXml -match '<Description>Updated description</Description>'
        }
    }
}

Describe 'Remove-SfosWebFilterCategory' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterCategory><Status code="200">OK</Status></WebFilterCategory></Response>' }
        }
    }

    It 'Should send a Remove request naming the object' {
        Remove-SfosWebFilterCategory -Name 'LocalCat' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>LocalCat</Name>'
        }
    }
}

Describe 'Get Parsing - UserActivity' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>Search related</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
            }
        }
    }

    It 'Should map the lowercase <type> element to a Type property' {
        $result = @(Get-SfosUserActivity @conn)[0]

        $result.Desc | Should -Be 'Search related'
        $result.CategoryList[0].ID | Should -Be 'Search Engines'
        $result.CategoryList[0].Type | Should -Be 'web category'
    }
}

Describe 'New-SfosUserActivity' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
        }
    }

    It 'Should build CategoryList with a lowercase type element' {
        New-SfosUserActivity -Name 'Activity1' -CategoryList @([PSCustomObject]@{ ID = 'Search Engines'; Type = 'web category' }) @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -cmatch '<Category><ID>Search Engines</ID><type>web category</type></Category>' -and
            $InnerXml -match '<Set operation="add">'
        }
    }

    It 'Should reject a CategoryList entry missing ID or Type without calling the API' {
        { New-SfosUserActivity -Name 'Bad' -CategoryList @([PSCustomObject]@{ ID = 'Search Engines' }) @conn -Confirm:$false } | Should -Throw '*ID*Type*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }
}

Describe 'Set-SfosUserActivity CategoryList preservation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
            }
        }
    }

    It 'Should resend the existing CategoryList when only Desc changes' {
        Set-SfosUserActivity -Name 'Activity1' -Desc 'updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -cmatch '<Category><ID>Search Engines</ID><type>web category</type></Category>'
        }
    }
}

Describe 'Remove-SfosUserActivity' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
        }
    }

    It 'Should send a Remove request naming the object' {
        Remove-SfosUserActivity -Name 'Activity1' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Activity1</Name>'
        }
    }
}

Describe 'Add-SfosUserActivityMember merge behaviour' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
            }
        }
    }

    It 'Should keep the existing category and add the new one' {
        Add-SfosUserActivityMember -Name 'Activity1' -Members @([PSCustomObject]@{ ID = 'Image Search'; Type = 'web category' }) @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -cmatch '<Category><ID>Search Engines</ID><type>web category</type></Category>' -and
            $InnerXml -cmatch '<Category><ID>Image Search</ID><type>web category</type></Category>'
        }
    }
}

Describe 'Remove-SfosUserActivityMember error path' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # Only one category present - removing it would leave an empty list, which the
        # firewall rejects. The cmdlet must catch this client-side before calling the API.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserActivity>
    <Name>Activity1</Name>
    <Desc>original</Desc>
    <CategoryList><Category><ID>Search Engines</ID><type>web category</type></Category></CategoryList>
  </UserActivity>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><UserActivity><Status code="200">OK</Status></UserActivity></Response>' }
            }
        }
    }

    It 'Should throw rather than send an update with an empty CategoryList' {
        { Remove-SfosUserActivityMember -Name 'Activity1' -Members @([PSCustomObject]@{ ID = 'Search Engines'; Type = 'web category' }) @conn -Confirm:$false } |
            Should -Throw '*last CategoryList entry*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter { $InnerXml -match '<Get>' }
    }
}

Describe 'Get Parsing - WebFilterException' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterException>
    <Name>Sophos Services</Name>
    <Desc>Predefined</Desc>
    <Enabled>on</Enabled>
    <CertValidation>on</CertValidation>
    <EnableSrcIP>no</EnableSrcIP>
    <EnableDstIP>no</EnableDstIP>
    <EnableURLRegex>no</EnableURLRegex>
    <EnableWebCat>yes</EnableWebCat>
    <DomainList><WebCategory>Business</WebCategory></DomainList>
    <IsDefault>yes</IsDefault>
  </WebFilterException>
</Response>
'@
            }
        }
    }

    It 'Should flatten the DomainList wrapper into named properties and expose IsDefault' {
        $result = @(Get-SfosWebFilterException @conn)[0]

        @($result.WebCategory) | Should -Be @('Business')
        @($result.SourceIPAddress).Count | Should -Be 0
        $result.IsDefault | Should -Be 'yes'
        $result.EnableWebCat | Should -Be 'yes'
    }
}

Describe 'Set-SfosWebFilterException additional error paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'A regex rejected by the firewall (live-observed 501)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterException>
    <Name>ExampleException</Name>
    <Desc>Original</Desc>
    <Enabled>on</Enabled>
    <CertValidation>on</CertValidation>
    <EnableURLRegex>no</EnableURLRegex>
    <DomainList></DomainList>
  </WebFilterException>
</Response>
'@
                    }
                }
                else {
                    # Live-observed: '^https://...' style regexes are rejected with a
                    # diagnostic-free 501 - reproduced here as a mocked error path.
                    [PSCustomObject]@{ Content = '<Response><WebFilterException><Status code="501">Configuration parameters validation failed.</Status></WebFilterException></Response>' }
                }
            }
        }

        It 'Should throw and leave the object conceptually unmodified' {
            { Set-SfosWebFilterException -Name 'ExampleException' -URLRegex '^https://blocked\.example\.com' @conn -Confirm:$false } | Should -Throw
        }
    }

    Context 'Clearing every match criterion on update' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterException>
    <Name>ExampleException</Name>
    <Desc>Original</Desc>
    <Enabled>on</Enabled>
    <CertValidation>on</CertValidation>
    <EnableSrcIP>yes</EnableSrcIP>
    <DomainList><SrcIp>10.0.0.0/24</SrcIp></DomainList>
  </WebFilterException>
</Response>
'@
                }
            }
        }

        It 'Should throw client-side rather than send an object with no criteria' {
            { Set-SfosWebFilterException -Name 'ExampleException' -SourceIPAddress @() @conn -Confirm:$false } | Should -Throw '*match criterion*'
        }
    }
}

Describe 'Remove-SfosWebFilterException' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterException><Status code="200">OK</Status></WebFilterException></Response>' }
        }
    }

    It 'Should send a Remove request naming the object' {
        Remove-SfosWebFilterException -Name 'Example' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Example</Name>'
        }
    }
}

Describe 'Get Parsing - WebFilterPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'A policy with rules' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterPolicy>
    <Name>Restricted</Name>
    <DefaultAction>Allow</DefaultAction>
    <DownloadFileSizeRestriction>0</DownloadFileSizeRestriction>
    <RuleList>
      <Rule>
        <CategoryList><Category><ID>Weapons</ID><type>WebCategory</type></Category></CategoryList>
        <HTTPAction>Deny</HTTPAction>
        <HTTPSAction>Deny</HTTPSAction>
        <FollowHTTPAction>0</FollowHTTPAction>
        <Schedule>All The Time</Schedule>
        <PolicyRuleEnabled>1</PolicyRuleEnabled>
        <CCLRuleEnabled>0</CCLRuleEnabled>
        <ExceptionList><FileTypeCategory/></ExceptionList>
      </Rule>
    </RuleList>
  </WebFilterPolicy>
</Response>
'@
                }
            }
        }

        It 'Should parse the RuleList into rule objects with an empty ExceptionList (not @(""))' {
            $result = @(Get-SfosWebFilterPolicy @conn)[0]

            @($result.RuleList).Count | Should -Be 1
            $result.RuleList[0].HTTPAction | Should -Be 'Deny'
            $result.RuleList[0].CategoryList[0].ID | Should -Be 'Weapons'
            @($result.RuleList[0].ExceptionList).Count | Should -Be 0
        }
    }

    Context 'A policy with no rules (the phantom-rule trap)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Name>Empty-Policy</Name><DefaultAction>Allow</DefaultAction><DownloadFileSizeRestriction>0</DownloadFileSizeRestriction></WebFilterPolicy></Response>' }
            }
        }

        It 'Should return an empty RuleList, not a one-element array of blanks' {
            $result = @(Get-SfosWebFilterPolicy @conn)[0]
            @($result.RuleList).Count | Should -Be 0
        }
    }
}

Describe 'Remove-SfosWebFilterPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Status code="200">OK</Status></WebFilterPolicy></Response>' }
        }
    }

    It 'Should send a Remove request naming the object' {
        Remove-SfosWebFilterPolicy -Name 'Restricted' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Restricted</Name>'
        }
    }
}

Describe 'New-SfosWebFilterPolicyCategory' {

    It 'Should build a plain in-memory ID/Type object' {
        $result = New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory

        $result.ID | Should -Be 'Extreme'
        $result.Type | Should -Be 'WebCategory'
    }

    It 'Should reject a Type outside the documented set' {
        { New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type 'NotARealType' } | Should -Throw
    }
}

Describe 'New-SfosWebFilterPolicyRule rejects the undocumented-live-broken Log action' {

    It 'Should not accept Log for -HTTPAction' {
        { New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory) -HTTPAction Log } | Should -Throw
    }

    It 'Should not accept Log for -HTTPSAction' {
        { New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory) -HTTPSAction Log } | Should -Throw
    }
}

Describe 'Add-SfosWebFilterPolicyRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'An existing policy with one rule' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterPolicy>
    <Name>Basic-Policy</Name>
    <DefaultAction>Allow</DefaultAction>
    <DownloadFileSizeRestriction>0</DownloadFileSizeRestriction>
    <RuleList>
      <Rule>
        <CategoryList><Category><ID>Extreme</ID><type>WebCategory</type></Category></CategoryList>
        <HTTPAction>Deny</HTTPAction>
        <HTTPSAction>Deny</HTTPSAction>
        <FollowHTTPAction>0</FollowHTTPAction>
        <Schedule>All The Time</Schedule>
        <PolicyRuleEnabled>1</PolicyRuleEnabled>
        <CCLRuleEnabled>0</CCLRuleEnabled>
      </Rule>
    </RuleList>
  </WebFilterPolicy>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Status code="200">OK</Status></WebFilterPolicy></Response>' }
                }
            }
        }

        It 'Should keep the existing rule and append the new one' {
            $newRule = New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory) -HTTPAction Warn -HTTPSAction Warn
            Add-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Rule $newRule @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ID>Extreme</ID>' -and $InnerXml -match '<ID>Weapons</ID>' -and
                $InnerXml -match '<Set operation="update">'
            }
        }
    }

    Context 'A policy that does not exist' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Status>No. of records Zero.</Status></WebFilterPolicy></Response>' }
            }
        }

        It 'Should throw naming the object' {
            $rule = New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory) -HTTPAction Warn
            { Add-SfosWebFilterPolicyRule -Name 'DoesNotExist' -Rule $rule @conn -Confirm:$false } | Should -Throw '*DoesNotExist*'
        }
    }
}

Describe 'Remove-SfosWebFilterPolicyRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'A policy with two rules' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebFilterPolicy>
    <Name>Basic-Policy</Name>
    <DefaultAction>Allow</DefaultAction>
    <DownloadFileSizeRestriction>0</DownloadFileSizeRestriction>
    <RuleList>
      <Rule>
        <CategoryList><Category><ID>Extreme</ID><type>WebCategory</type></Category></CategoryList>
        <HTTPAction>Deny</HTTPAction><HTTPSAction>Deny</HTTPSAction><FollowHTTPAction>0</FollowHTTPAction>
        <Schedule>All The Time</Schedule><PolicyRuleEnabled>1</PolicyRuleEnabled><CCLRuleEnabled>0</CCLRuleEnabled>
      </Rule>
      <Rule>
        <CategoryList><Category><ID>Weapons</ID><type>WebCategory</type></Category></CategoryList>
        <HTTPAction>Warn</HTTPAction><HTTPSAction>Warn</HTTPSAction><FollowHTTPAction>0</FollowHTTPAction>
        <Schedule>All The Time</Schedule><PolicyRuleEnabled>1</PolicyRuleEnabled><CCLRuleEnabled>0</CCLRuleEnabled>
      </Rule>
    </RuleList>
  </WebFilterPolicy>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterPolicy><Status code="200">OK</Status></WebFilterPolicy></Response>' }
                }
            }
        }

        It 'Should keep only the rule that was not removed' {
            Remove-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Index 0 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ID>Weapons</ID>' -and $InnerXml -notmatch '<ID>Extreme</ID>'
            }
        }

        It 'Should throw for an out-of-range index' {
            { Remove-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Index 5 @conn -Confirm:$false } | Should -Throw '*out of range*'
        }
    }
}

Describe 'Get Parsing - SurfingQuotaPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SurfingQuotaPolicy>
    <Name>Daily-Quota</Name>
    <CycleType>Cyclic</CycleType>
    <CycleHours>2</CycleHours>
    <CycleMinutes>30</CycleMinutes>
    <PerDay>Days</PerDay>
  </SurfingQuotaPolicy>
  <SurfingQuotaPolicy>
    <Name>Monthly-Quota</Name>
    <CycleType>NonCyclic</CycleType>
    <Validity>30</Validity>
    <MaximumHours>100</MaximumHours>
  </SurfingQuotaPolicy>
</Response>
'@
            }
        }
    }

    It 'Should parse Cyclic type-specific fields' {
        $result = @(Get-SfosSurfingQuotaPolicy @conn | Where-Object { $_.Name -eq 'Daily-Quota' })[0]

        $result.CycleType | Should -Be 'Cyclic'
        $result.CycleHours | Should -Be '2'
        $result.PerDay | Should -Be 'Days'
    }

    It 'Should parse NonCyclic type-specific fields' {
        $result = @(Get-SfosSurfingQuotaPolicy @conn | Where-Object { $_.Name -eq 'Monthly-Quota' })[0]

        $result.CycleType | Should -Be 'NonCyclic'
        $result.Validity | Should -Be '30'
        $result.MaximumHours | Should -Be '100'
    }
}

Describe 'New-SfosSurfingQuotaPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><SurfingQuotaPolicy><Status code="200">OK</Status></SurfingQuotaPolicy></Response>' }
        }
    }

    It 'Should send CycleHours/CycleMinutes/PerDay for a Cyclic policy' {
        New-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -CycleHours 2 -CycleMinutes 30 -PerDay Days @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<CycleType>Cyclic</CycleType>' -and
            $InnerXml -match '<CycleHours>2</CycleHours>' -and
            $InnerXml -match '<CycleMinutes>30</CycleMinutes>' -and
            $InnerXml -match '<PerDay>Days</PerDay>' -and
            $InnerXml -notmatch '<Validity>'
        }
    }

    It 'Should send Validity/MaximumHours for a NonCyclic policy' {
        New-SfosSurfingQuotaPolicy -Name 'Monthly-Quota' -CycleType NonCyclic -Validity 30 -MaximumHours 100 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<CycleType>NonCyclic</CycleType>' -and
            $InnerXml -match '<Validity>30</Validity>' -and
            $InnerXml -match '<MaximumHours>100</MaximumHours>' -and
            $InnerXml -notmatch '<CycleHours>'
        }
    }

    It 'Should throw for Cyclic without the required fields, before calling the API' {
        { New-SfosSurfingQuotaPolicy -Name 'Bad' -CycleType Cyclic @conn -Confirm:$false } | Should -Throw '*requires*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }

    It 'Should throw for NonCyclic without the required fields, before calling the API' {
        { New-SfosSurfingQuotaPolicy -Name 'Bad' -CycleType NonCyclic @conn -Confirm:$false } | Should -Throw '*requires*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }

    It 'Should reject a non-numeric CycleHours' {
        { New-SfosSurfingQuotaPolicy -Name 'Bad' -CycleType Cyclic -CycleHours 'notanumber' -CycleMinutes 0 -PerDay Days @conn -Confirm:$false } | Should -Throw '*non-negative integer*'
    }
}

Describe 'Set-SfosSurfingQuotaPolicy Read-Modify-Write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SurfingQuotaPolicy>
    <Name>Daily-Quota</Name>
    <CycleType>Cyclic</CycleType>
    <CycleHours>2</CycleHours>
    <CycleMinutes>30</CycleMinutes>
    <PerDay>Days</PerDay>
    <Description>Original description</Description>
  </SurfingQuotaPolicy>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SurfingQuotaPolicy><Status code="200">OK</Status></SurfingQuotaPolicy></Response>' }
            }
        }
    }

    It 'Should resend CycleHours/CycleMinutes/PerDay when only the description changes' {
        Set-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -Description 'Updated description' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<CycleHours>2</CycleHours>' -and
            $InnerXml -match '<CycleMinutes>30</CycleMinutes>' -and
            $InnerXml -match '<PerDay>Days</PerDay>' -and
            $InnerXml -match '<Description>Updated description</Description>'
        }
    }
}

Describe 'Remove-SfosSurfingQuotaPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><SurfingQuotaPolicy><Status code="200">OK</Status></SurfingQuotaPolicy></Response>' }
        }
    }

    It 'Should send a Remove request naming the object' {
        Remove-SfosSurfingQuotaPolicy -Name 'Daily-Quota' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Daily-Quota</Name>'
        }
    }
}

Describe 'ContentConditionList (Key addressing)' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosContentConditionList' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <ContentConditionList>
    <Name>Sensitive-Terms</Name>
    <Key>SensitiveTerms_Custom</Key>
    <Description>Test list</Description>
    <ContentList><ContentString>foo</ContentString><ContentString>bar</ContentString></ContentList>
  </ContentConditionList>
</Response>
'@
                }
            }
        }

        It 'Should parse Key and ContentList and send only Key server-side' {
            Get-SfosContentConditionList -KeyLike 'SensitiveTerms' @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<key name="Key" criteria="like">SensitiveTerms</key>'
            }
        }

        It 'Should return the parsed object' {
            $result = @(Get-SfosContentConditionList @conn)[0]
            $result.Key | Should -Be 'SensitiveTerms_Custom'
            @($result.ContentList) | Should -Be @('foo', 'bar')
        }
    }

    Context 'New-SfosContentConditionList' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status code="200">OK</Status></ContentConditionList></Response>' }
            }
        }

        It 'Should not send a Key element - the firewall derives it from Name' {
            New-SfosContentConditionList -Name 'Sensitive-Terms' -ContentStrings @('foo', 'bar') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<Key>' -and
                $InnerXml -match '<ContentString>foo</ContentString>' -and
                $InnerXml -match '<ContentString>bar</ContentString>'
            }
        }
    }

    Context 'Set-SfosContentConditionList' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <ContentConditionList>
    <Name>Sensitive-Terms</Name>
    <Key>SensitiveTerms_Custom</Key>
    <Description>Original description</Description>
    <ContentList><ContentString>foo</ContentString><ContentString>bar</ContentString></ContentList>
  </ContentConditionList>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status code="200">OK</Status></ContentConditionList></Response>' }
                }
            }
        }

        It 'Should address the object by Key and resend the existing ContentList when only Description changes' {
            Set-SfosContentConditionList -Key 'SensitiveTerms_Custom' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Key>SensitiveTerms_Custom</Key>' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<ContentString>foo</ContentString>' -and
                $InnerXml -match '<ContentString>bar</ContentString>'
            }
        }
    }

    Context 'Remove-SfosContentConditionList' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status code="200">OK</Status></ContentConditionList></Response>' }
            }
        }

        It 'Should remove by Key, not by Name' {
            Remove-SfosContentConditionList -Key 'SensitiveTerms_Custom' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Key>SensitiveTerms_Custom</Key>'
            }
        }
    }

    Context 'Add-SfosContentConditionListMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <ContentConditionList>
    <Name>Sensitive-Terms</Name>
    <Key>SensitiveTerms_Custom</Key>
    <Description>Test list</Description>
    <ContentList><ContentString>foo</ContentString></ContentList>
  </ContentConditionList>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status code="200">OK</Status></ContentConditionList></Response>' }
                }
            }
        }

        It 'Should merge the new string with the existing one and preserve Name and Description' {
            Add-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'baz' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ContentString>foo</ContentString>' -and
                $InnerXml -match '<ContentString>baz</ContentString>' -and
                $InnerXml -match '<Name>Sensitive-Terms</Name>' -and
                $InnerXml -match '<Description>Test list</Description>'
            }
        }
    }

    Context 'Remove-SfosContentConditionListMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <ContentConditionList>
    <Name>Sensitive-Terms</Name>
    <Key>SensitiveTerms_Custom</Key>
    <Description>Test list</Description>
    <ContentList><ContentString>foo</ContentString><ContentString>baz</ContentString></ContentList>
  </ContentConditionList>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ContentConditionList><Status code="200">OK</Status></ContentConditionList></Response>' }
                }
            }
        }

        It 'Should resend only the remaining string' {
            Remove-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'baz' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ContentString>foo</ContentString>' -and
                $InnerXml -notmatch '<ContentString>baz</ContentString>'
            }
        }
    }
}

Describe 'Settings Singletons' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosMalwareProtection' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><MalwareProtection><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
            }
        }

        It 'Should parse PrimaryAntiVirusEngine' {
            (Get-SfosMalwareProtection @conn).PrimaryAntiVirusEngine | Should -Be 'Sophos'
        }
    }

    Context 'Set-SfosMalwareProtection Read-Modify-Write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><MalwareProtection><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><MalwareProtection><Status code="200">OK</Status></MalwareProtection></Response>' }
                }
            }
        }

        It 'Should resend the existing engine when no parameter is bound' {
            Set-SfosMalwareProtection @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine>'
            }
        }
    }

    Context 'Get-SfosWebFilterSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterSettings>
    <WebCaching>Disable</WebCaching>
    <Scanning>Single Anti-Virus (Maximum Performance)</Scanning>
    <BlockUnscannableContent>Block (Best Protection)</BlockUnscannableContent>
    <PharmingProtection>Enable</PharmingProtection>
    <DeniedMessageImage>Default</DeniedMessageImage>
  </WebFilterSettings>
</Response>
'@
                }
            }
        }

        It 'Should parse the fields and return an empty PUAWhitelist when absent' {
            $result = Get-SfosWebFilterSettings @conn
            $result.WebCaching | Should -Be 'Disable'
            $result.PharmingProtection | Should -Be 'Enable'
            @($result.PUAWhitelist).Count | Should -Be 0
        }
    }

    Context 'Set-SfosWebFilterSettings preserves PharmingProtection (documented worst-case)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterSettings>
    <WebCaching>Disable</WebCaching>
    <Scanning>Single Anti-Virus (Maximum Performance)</Scanning>
    <BlockUnscannableContent>Block (Best Protection)</BlockUnscannableContent>
    <PharmingProtection>Enable</PharmingProtection>
    <DeniedMessageImage>Default</DeniedMessageImage>
  </WebFilterSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterSettings><Status code="200">OK</Status></WebFilterSettings></Response>' }
                }
            }
        }

        It 'Should resend PharmingProtection unchanged when only WebCaching is toggled' {
            # On the sibling singleton WebFilterProtectionSettings, a field never mentioned in
            # the request was silently reset to Disable. Read-modify-write must prevent it here too.
            Set-SfosWebFilterSettings -WebCaching 'Enable' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<WebCaching>Enable</WebCaching>' -and
                $InnerXml -match '<PharmingProtection>Enable</PharmingProtection>' -and
                $InnerXml -match '<Scanning>Single Anti-Virus \(Maximum Performance\)</Scanning>'
            }
        }

        It 'sends no MultipartFile and no TopImageFile/BottomImageFile element when neither image parameter is passed' {
            Set-SfosWebFilterSettings -WebCaching 'Enable' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -notmatch '<TopImageFile>' -and
                $InnerXml -notmatch '<BottomImageFile>' -and
                (-not $MultipartFile -or $MultipartFile.Count -eq 0)
            }
        }

        It 'sends TopImageFile as the file base name with the matching MultipartFile field, without losing PharmingProtection' {
            $imgPath = Join-Path -Path 'TestDrive:\' -ChildPath 'top-image.jpg'
            Set-Content -Path $imgPath -Value 'placeholder jpg content'

            Set-SfosWebFilterSettings -TopImageFile $imgPath @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<TopImageFile>top-image\.jpg</TopImageFile>' -and
                $InnerXml -match '<PharmingProtection>Enable</PharmingProtection>' -and
                $InnerXml -match '<Scanning>Single Anti-Virus \(Maximum Performance\)</Scanning>' -and
                $MultipartFile.Count -eq 1 -and
                $MultipartFile['TopImageFile'] -eq $imgPath
            }
        }

        It 'sends BottomImageFile as the file base name with the matching MultipartFile field, without losing PharmingProtection' {
            $imgPath = Join-Path -Path 'TestDrive:\' -ChildPath 'bottom-image.jpg'
            Set-Content -Path $imgPath -Value 'placeholder jpg content'

            Set-SfosWebFilterSettings -BottomImageFile $imgPath @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<BottomImageFile>bottom-image\.jpg</BottomImageFile>' -and
                $InnerXml -match '<PharmingProtection>Enable</PharmingProtection>' -and
                $MultipartFile.Count -eq 1 -and
                $MultipartFile['BottomImageFile'] -eq $imgPath
            }
        }

        It 'throws client-side, without calling the API, when TopImageFile does not exist' {
            $missingPath = Join-Path -Path 'TestDrive:\' -ChildPath 'does-not-exist.jpg'

            { Set-SfosWebFilterSettings -TopImageFile $missingPath @conn -Confirm:$false } | Should -Throw '*not found*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
        }

        It 'throws client-side, without calling the API, when BottomImageFile does not exist' {
            $missingPath = Join-Path -Path 'TestDrive:\' -ChildPath 'does-not-exist-bottom.jpg'

            { Set-SfosWebFilterSettings -BottomImageFile $missingPath @conn -Confirm:$false } | Should -Throw '*not found*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
        }
    }

    Context 'Get-SfosWebFilterProtectionSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterProtectionSettings>
    <ScanMode>BatchMode</ScanMode>
    <FileSizeThreshold>30720</FileSizeThreshold>
    <FTPFileSizeThreshold>30720</FTPFileSizeThreshold>
    <PharmingProtection>Enable</PharmingProtection>
    <PUADetection>Disable</PUADetection>
  </WebFilterProtectionSettings>
</Response>
'@
                }
            }
        }

        It 'Should parse FileSizeThreshold as an int and PharmingProtection as a string' {
            $result = Get-SfosWebFilterProtectionSettings @conn
            $result.FileSizeThreshold | Should -Be 30720
            $result.PharmingProtection | Should -Be 'Enable'
        }
    }

    Context 'Set-SfosWebFilterProtectionSettings preserves PharmingProtection - the documented Ernstfall' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterProtectionSettings>
    <ScanMode>BatchMode</ScanMode>
    <FileSizeThreshold>30720</FileSizeThreshold>
    <FTPFileSizeThreshold>30720</FTPFileSizeThreshold>
    <AudioVideoFileScanning>Enable</AudioVideoFileScanning>
    <PharmingProtection>Enable</PharmingProtection>
    <PUADetection>Disable</PUADetection>
  </WebFilterProtectionSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterProtectionSettings><Status code="200">OK</Status></WebFilterProtectionSettings></Response>' }
                }
            }
        }

        It 'Should resend PharmingProtection=Enable when only FileSizeThreshold changes' {
            # A Set carrying only FileSizeThreshold, FTPFileSizeThreshold and
            # AudioVideoFileScanning reset PharmingProtection from Enable to Disable with a
            # code="200" success response.
            Set-SfosWebFilterProtectionSettings -FileSizeThreshold 30721 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<FileSizeThreshold>30721</FileSizeThreshold>' -and
                $InnerXml -match '<PharmingProtection>Enable</PharmingProtection>' -and
                $InnerXml -match '<AudioVideoFileScanning>Enable</AudioVideoFileScanning>'
            }
        }
    }

    Context 'Get-SfosWebFilterAdvancedSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterAdvancedSettings>
    <WebCaching>Disable</WebCaching>
    <WebProxyPort>3128</WebProxyPort>
    <WebProxyMinimumTLSVersion>TLS 1.1</WebProxyMinimumTLSVersion>
    <TrustedPorts><Port>21</Port><Port>1025-65535</Port></TrustedPorts>
  </WebFilterAdvancedSettings>
</Response>
'@
                }
            }
        }

        It 'Should parse TrustedPorts as strings, including a range' {
            $result = Get-SfosWebFilterAdvancedSettings @conn
            @($result.TrustedPorts) | Should -Be @('21', '1025-65535')
            $result.WebProxyPort | Should -Be 3128
        }
    }

    Context 'Set-SfosWebFilterAdvancedSettings preserves TrustedPorts' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterAdvancedSettings>
    <WebCaching>Disable</WebCaching>
    <WebProxyPort>3128</WebProxyPort>
    <WebProxyMinimumTLSVersion>TLS 1.1</WebProxyMinimumTLSVersion>
    <TrustedPorts><Port>21</Port><Port>1025-65535</Port></TrustedPorts>
  </WebFilterAdvancedSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterAdvancedSettings><Status code="200">OK</Status></WebFilterAdvancedSettings></Response>' }
                }
            }
        }

        It 'Should resend the existing TrustedPorts when only WebProxyPort changes' {
            Set-SfosWebFilterAdvancedSettings -WebProxyPort 8080 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<WebProxyPort>8080</WebProxyPort>' -and
                $InnerXml -match '<Port>21</Port>' -and
                $InnerXml -match '<Port>1025-65535</Port>' -and
                $InnerXml -match '<WebProxyMinimumTLSVersion>TLS 1\.1</WebProxyMinimumTLSVersion>'
            }
        }
    }

    Context 'Get-SfosDefaultWebFilterNotificationSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = '<Response><DefaultWebFilterNotificationSettings><Warning>Warning!</Warning><DownloadBlocked>Blocked</DownloadBlocked></DefaultWebFilterNotificationSettings></Response>' }
            }
        }

        It 'Should build a dynamic object from whatever fields the firewall returns' {
            $result = Get-SfosDefaultWebFilterNotificationSettings @conn
            $result.Warning | Should -Be 'Warning!'
            $result.DownloadBlocked | Should -Be 'Blocked'
        }
    }

    Context 'Set-SfosDefaultWebFilterNotificationSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><DefaultWebFilterNotificationSettings><Warning>Warning!</Warning><DownloadBlocked>Blocked</DownloadBlocked></DefaultWebFilterNotificationSettings></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DefaultWebFilterNotificationSettings><Status code="200">OK</Status></DefaultWebFilterNotificationSettings></Response>' }
                }
            }
        }

        It 'Should change only the requested field and resend the rest unchanged' {
            Set-SfosDefaultWebFilterNotificationSettings -Message @{ Warning = 'Achtung!' } @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Warning>Achtung!</Warning>' -and
                $InnerXml -match '<DownloadBlocked>Blocked</DownloadBlocked>'
            }
        }

        It 'Should throw on an unknown field name before sending any Set request' {
            { Set-SfosDefaultWebFilterNotificationSettings -Message @{ NotARealField = 'x' } @conn -Confirm:$false } | Should -Throw '*not a known*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter { $InnerXml -match '<Get>' }
        }
    }

    Context 'Get-SfosWebFilterNotificationSettings' {
        It 'Should exist and expose the connection and AsXml parameters' {
            $cmd = Get-Command Get-SfosWebFilterNotificationSettings
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Parameters.ContainsKey('Firewall') | Should -Be $true
            $cmd.Parameters.ContainsKey('Port') | Should -Be $true
            $cmd.Parameters.ContainsKey('Username') | Should -Be $true
            $cmd.Parameters.ContainsKey('Password') | Should -Be $true
            $cmd.Parameters.ContainsKey('SkipCertificateCheck') | Should -Be $true
            $cmd.Parameters.ContainsKey('Session') | Should -Be $true
            $cmd.Parameters.ContainsKey('AsXml') | Should -Be $true
        }

        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterNotificationSettings>
    <OverrideDefaultWarnedMessage>Disable</OverrideDefaultWarnedMessage>
    <OverrideDefaultDeniedMessage>Enable</OverrideDefaultDeniedMessage>
    <DeniedMessageImage>Default</DeniedMessageImage>
  </WebFilterNotificationSettings>
</Response>
'@
                }
            }
        }

        It 'Should parse the three fields into a PSCustomObject' {
            $result = Get-SfosWebFilterNotificationSettings @conn
            $result.OverrideDefaultWarnedMessage | Should -Be 'Disable'
            $result.OverrideDefaultDeniedMessage | Should -Be 'Enable'
            $result.DeniedMessageImage | Should -Be 'Default'
        }
    }

    Context 'Set-SfosWebFilterNotificationSettings' {
        It 'Should exist and expose the three functional and all connection parameters' {
            $cmd = Get-Command Set-SfosWebFilterNotificationSettings
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Parameters.ContainsKey('OverrideDefaultWarnedMessage') | Should -Be $true
            $cmd.Parameters.ContainsKey('OverrideDefaultDeniedMessage') | Should -Be $true
            $cmd.Parameters.ContainsKey('DeniedMessageImage') | Should -Be $true
            $cmd.Parameters.ContainsKey('Firewall') | Should -Be $true
            $cmd.Parameters.ContainsKey('Port') | Should -Be $true
            $cmd.Parameters.ContainsKey('Username') | Should -Be $true
            $cmd.Parameters.ContainsKey('Password') | Should -Be $true
            $cmd.Parameters.ContainsKey('SkipCertificateCheck') | Should -Be $true
            $cmd.Parameters.ContainsKey('Session') | Should -Be $true
            $cmd.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <WebFilterNotificationSettings>
    <OverrideDefaultWarnedMessage>Disable</OverrideDefaultWarnedMessage>
    <OverrideDefaultDeniedMessage>Enable</OverrideDefaultDeniedMessage>
    <DeniedMessageImage>Default</DeniedMessageImage>
  </WebFilterNotificationSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebFilterNotificationSettings><Status code="200">OK</Status></WebFilterNotificationSettings></Response>' }
                }
            }
        }

        It 'Should send the root element, operation="update" and all three fields' {
            Set-SfosWebFilterNotificationSettings -OverrideDefaultWarnedMessage 'Enable' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<WebFilterNotificationSettings>' -and
                $InnerXml -match '<OverrideDefaultWarnedMessage>Enable</OverrideDefaultWarnedMessage>' -and
                $InnerXml -match '<OverrideDefaultDeniedMessage>Enable</OverrideDefaultDeniedMessage>' -and
                $InnerXml -match '<DeniedMessageImage>Default</DeniedMessageImage>'
            }
        }

        It 'Should keep the other two fields from the read-back object when only one is passed' {
            Set-SfosWebFilterNotificationSettings -DeniedMessageImage 'Custom' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<DeniedMessageImage>Custom</DeniedMessageImage>' -and
                $InnerXml -match '<OverrideDefaultWarnedMessage>Disable</OverrideDefaultWarnedMessage>' -and
                $InnerXml -match '<OverrideDefaultDeniedMessage>Enable</OverrideDefaultDeniedMessage>'
            }
        }
    }
}

Describe 'Session parameter (multi-session support)' {

    BeforeAll {
        $cred1 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw1' -AsPlainText -Force))
        $cred2 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw2' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred1 -Name 'fw1' | Out-Null
        Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred2 -Name 'fw2' -NoDefault | Out-Null
    }

    AfterAll { Disconnect-SfosFirewall -All }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WebFilterURLGroup><Status>No. of records Zero.</Status></WebFilterURLGroup></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosWebFilterURLGroup -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosWebFilterURLGroup | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on a write cmdlet (New-SfosWebFilterURLGroup)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -MockWith {
            [PSCustomObject]@{ Content = '<Response><WebFilterURLGroup><Status code="200">Configuration applied successfully.</Status></WebFilterURLGroup></Response>' }
        }
        New-SfosWebFilterURLGroup -Name 'CrossFwGroup' -Members 'example.invalid' -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Name>CrossFwGroup</Name>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosWebFilterURLGroup -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Web -Times 0 -Exactly
    }
}