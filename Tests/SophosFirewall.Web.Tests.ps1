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

    It 'Should export exactly 52 functions' {
        (Get-Module SophosFirewall.Web).ExportedFunctions.Count | Should -Be 52
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
    # Live-verified defect: an update to UserActivity sent without <NewName> answers HTTP
    # 200 / status code 200, but renames the object to an EMPTY name - the object becomes an
    # unreachable orphan under its old name. Set-SfosUserActivity, Add-SfosUserActivityMember
    # and Remove-SfosUserActivityMember all update the object internally, so all three must
    # always send <NewName> - the caller's new name, or the object's current name when the
    # caller is not renaming. These tests exist to catch a regression that would silently
    # cause data loss on a live firewall while still reporting success.

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
    # has to leave everything else alone - same reasoning as the NetworkPolicy subtree in
    # SophosFirewall.Firewall (CLAUDE.md section 5).

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