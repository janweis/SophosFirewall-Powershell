#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Pester Tests for SophosFirewall.Core module
    
.DESCRIPTION
    Comprehensive test suite for core helper functions:
    - Connect-SfosFirewall / Disconnect-SfosFirewall
    - Invoke-SfosApi
    - Get-SfosApiStatus
    - Assert-SfosApiReturnSuccess
    - Resolve-SfosParameters
    - ConvertTo-SfosXmlEscaped
    
.NOTES
    Run with: Invoke-Pester -Path "SophosFirewall.Core.Tests.ps1" -Verbose
#>

BeforeAll {
    # Import the module - adjust path for both local and CI environments
    $modulePath = if (Test-Path "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1") {
        "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
    } else {
        "$PSScriptRoot\..\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
    }
    
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}

Describe 'SophosFirewall.Core Module' {
    
    Context 'Module Loading' {
        It 'Module should load without errors' {
            $modulePath = if (Test-Path "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1") {
                "$PSScriptRoot\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
            } else {
                "$PSScriptRoot\..\..\Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"
            }
            { Import-Module -Name $modulePath -Force -ErrorAction Stop } | Should -Not -Throw
        }
        
        It 'Should export required functions' {
            $module = Get-Module -Name 'SophosFirewall.Core'
            $requiredFunctions = @(
                'Connect-SfosFirewall',
                'Disconnect-SfosFirewall',
                'Get-SfosSession',
                'Invoke-SfosApi',
                'Get-SfosApiStatus',
                'Assert-SfosApiReturnSuccess',
                'Resolve-SfosParameters',
                'ConvertTo-SfosXmlEscaped'
            )
            
            foreach ($func in $requiredFunctions) {
                $module.ExportedFunctions.Keys | Should -Contain $func
            }
        }
    }
    
    Context 'ConvertTo-SfosXmlEscaped - XML Entity Escaping' {
        It 'Should escape ampersand (&)' {
            ConvertTo-SfosXmlEscaped 'Test & Test' | Should -Be 'Test &amp; Test'
        }
        
        It 'Should escape less-than (<)' {
            ConvertTo-SfosXmlEscaped 'A < B' | Should -Be 'A &lt; B'
        }
        
        It 'Should escape greater-than (>)' {
            ConvertTo-SfosXmlEscaped 'A > B' | Should -Be 'A &gt; B'
        }
        
        It 'Should escape double quote (")' {
            ConvertTo-SfosXmlEscaped 'Say "Hello"' | Should -Be 'Say &quot;Hello&quot;'
        }
        
        It "Should escape apostrophe (')" {
            ConvertTo-SfosXmlEscaped "It's" | Should -Be 'It&apos;s'
        }
        
        It 'Should handle multiple special characters' {
            ConvertTo-SfosXmlEscaped 'Test & <value> "quoted"' | `
                Should -Be 'Test &amp; &lt;value&gt; &quot;quoted&quot;'
        }
        
        It 'Should not modify plain text' {
            ConvertTo-SfosXmlEscaped 'PlainText' | Should -Be 'PlainText'
        }
        
        It 'Should handle empty string' {
            ConvertTo-SfosXmlEscaped '' | Should -Be ''
        }
    }
    
    Context 'Get-SfosApiStatus - XML Response Parsing' {
        It 'Should extract status code 200 from valid response' {
            $xmlResponse = @'
<Response><Status code="200"></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '200'
        }
        
        It 'Should extract status code 202 from valid response' {
            $xmlResponse = @'
<Response><Status code="202"></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '202'
        }
        
        It 'Should extract status code 502 from error response' {
            $xmlResponse = @'
<Response><Status code="502"><Msg>Authentication failed</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            $result = Get-SfosApiStatus -Xml $xml
            $result.Code | Should -Be '502'
        }
    }
    
    Context 'Assert-SfosApiReturnSuccess - Error Throwing' {
        It 'Should not throw on status 200' {
            $xmlResponse = @'
<Response><Status code="200"><Msg>Success</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml } | Should -Not -Throw
        }
        
        It 'Should not throw on status 216' {
            # 216 "Operation Successful" is a documented success code. 202 is not in the
            # table Sophos publishes at all and must not be accepted.
            $xmlResponse = @'
<Response><Status code="216"><Msg>Success</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml } | Should -Not -Throw
        }

        It 'Should throw on the undocumented status 202' {
            $xmlResponse = @'
<Response><Status code="202"><Msg>Accepted</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml } | Should -Throw
        }

        It 'Should warn but not throw on a partial-success code' {
            $xmlResponse = @'
<Response><Status code="201"><Msg>Operation partially successful.</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml -WarningAction SilentlyContinue } | Should -Not -Throw
        }
        
        It 'Should throw on status 502' {
            $xmlResponse = @'
<Response><Status code="502"><Msg>Authentication failed</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
        
        It 'Should throw on status 400' {
            $xmlResponse = @'
<Response><Status code="400"><Msg>Bad Request</Msg></Status></Response>
'@
            $xml = [xml]$xmlResponse
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
    }
    
    Context 'Resolve-SfosParameters - Parameter Merging' {
        AfterEach {
            # Tests must not leave session state behind for the next test
            Disconnect-SfosFirewall
        }

        It 'Should use provided parameters when supplied' {
            $params = @{
                BoundParameters = @{
                    Firewall = '192.168.1.1'
                    Port = 4444
                    Username = 'user'
                    Password = (ConvertTo-SecureString 'pass' -AsPlainText -Force)
                }
            }
            
            $result = Resolve-SfosParameters @params
            $result.Firewall | Should -Be '192.168.1.1'
            $result.Port | Should -Be 4444
        }
        
        It 'Should fall back to stored connection when parameters missing' {
            # This requires stored connection context
            # Mock scenario: if no parameters provided, should attempt to use stored context
            Connect-SfosFirewall -Firewall '192.168.1.1' -Port 4444 -Credential (New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString 'test' -AsPlainText -Force)))
            
            $result = Resolve-SfosParameters -BoundParameters @{}
            $result.Firewall | Should -Be '192.168.1.1'
            $result.Port | Should -Be 4444
        }
    }
    
    Context 'Connect-SfosFirewall / Disconnect-SfosFirewall - Session Management' {
        AfterEach {
            Disconnect-SfosFirewall
        }

        It 'Connect should store connection parameters' {
            # This would require actual firewall connection or mocking
            # Validate that function accepts parameters without error
            $cred = New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
            { Connect-SfosFirewall -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck } | Should -Not -Throw
        }
        
        It 'Disconnect should clear connection context' {
            { Disconnect-SfosFirewall } | Should -Not -Throw
        }
    }
    
    Context 'Error Handling' {
        It 'ConvertTo-SfosXmlEscaped should escape special characters' {
            $result = ConvertTo-SfosXmlEscaped 'Test & <special>'
            $result | Should -Be 'Test &amp; &lt;special&gt;'
        }
        
        It 'Get-SfosApiStatus should handle valid XML response' {
            $validXml = @'
<Response>
    <StatusCode>200</StatusCode>
    <Message>Success</Message>
</Response>
'@
            $xml = [xml]$validXml
            { $result = Get-SfosApiStatus -Xml $xml } | Should -Not -Throw
        }
    }
}

Describe 'Invoke-SfosApi - Request Building' {

    BeforeAll {
        $callArgs = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            [PSCustomObject]@{
                StatusCode = 200
                Content    = '<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>'
            }
        }
    }

    It 'Should URL-encode the request body' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -like 'reqxml=%3CRequest%3E%3CLogin%3E*'
        }
    }

    It 'Should not leave a raw ampersand in the body - it would truncate reqxml' {
        # 'A&B' becomes 'A&amp;B' through XML escaping; unencoded that ends the form field
        # and SFOS answers with code 529.
        $inner = '<Get><IPHost><Filter><key name="Name" criteria="like">A&amp;B</key></Filter></IPHost></Get>'
        Invoke-SfosApi @callArgs -InnerXml $inner | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Body -notmatch '&' -and $Body -match '%26amp%3B'
        }
    }

    It 'Should not send an APIVersion attribute unless asked to' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            [uri]::UnescapeDataString($Body) -like '*<Request><Login>*'
        }
    }

    It 'Should send the APIVersion attribute when supplied' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' -ApiVersion '2200.1' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            [uri]::UnescapeDataString($Body) -like '*<Request APIVersion="2200.1">*'
        }
    }

    It 'Should XML-escape credentials' {
        Invoke-SfosApi -Firewall 'fw.example.test' -Port 4444 -Username 'a<b' `
            -Password (ConvertTo-SecureString 'p&w' -AsPlainText -Force) -InnerXml '<Get/>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $decoded = [uri]::UnescapeDataString($Body)
            $decoded -like '*<Username>a&lt;b</Username>*' -and $decoded -like '*<Password>p&amp;w</Password>*'
        }
    }
}

Describe 'Assert-SfosApiReturnSuccess - Empty Results' {

    It 'Should not throw when SFOS reports an empty result without a status code' {
        # Real SFOS answer for a filter with no matches
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost transactionid=""><Status>No. of records Zero.</Status></IPHost>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'IPHost' -Action 'get' } | Should -Not -Throw
    }

    It 'Should still throw when a real error code is present' {
        $xml = [xml]'<Response><Status code="529">Input request file is Invalid</Status></Response>'
        { Assert-SfosApiReturnSuccess -Xml $xml -Action 'get' } | Should -Throw
    }

    It 'Should throw on a code-less status that is not the empty-result wording' {
        # Real SFOS answer to a filtered Get on ContentConditionList. It carries no code
        # either, so treating every code-less status as "no records" reported a populated
        # list as empty.
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <ContentConditionList transactionid=""><Status>Transaction fail</Status></ContentConditionList>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'ContentConditionList' -Action 'get' } |
            Should -Throw '*Transaction fail*'
    }
}

Describe 'Get-SfosApiStatus - Status field versus API status' {

    # A FirewallRule and a NATRule carry <Status>Enable</Status> as a data field. Matching
    # /Response/<Entity>/Status blindly picked those up, so a six-rule response looked like
    # six status nodes and every Get on the entity failed.

    It 'Should ignore a Status data field inside a named object' {
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule transactionid=""><Name>Allow-LAN</Name><Status>Enable</Status></FirewallRule>
  <FirewallRule transactionid=""><Name>Block-Guest</Name><Status>Disable</Status></FirewallRule>
</Response>
'@
        @(Get-SfosApiStatus -Xml $xml -ObjectName 'FirewallRule').Count | Should -Be 0
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'FirewallRule' -Action 'get' } | Should -Not -Throw
    }

    It 'Should still see a real status in a container without a name' {
        $xml = [xml]'<Response><Login><status>Authentication Successful</status></Login><FirewallRule transactionid=""><Status code="200">Configuration applied successfully.</Status></FirewallRule></Response>'

        @(Get-SfosApiStatus -Xml $xml -ObjectName 'FirewallRule').Code | Should -Be '200'
    }

    It 'Should still see a coded error that arrives next to a named object' {
        # The Name test alone would hide this one, so the code attribute wins regardless.
        $xml = [xml]'<Response><Login><status>Authentication Successful</status></Login><FirewallRule><Name>Allow-LAN</Name><Status code="502">Entity having same name already exists</Status></FirewallRule></Response>'

        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'FirewallRule' -Action 'create' -Target 'Allow-LAN' } |
            Should -Throw '*502*'
    }

    It 'Should still report the empty result for an entity that has a Status field' {
        $xml = [xml]'<Response><Login><status>Authentication Successful</status></Login><FirewallRule transactionid=""><Status>No. of records Zero.</Status></FirewallRule></Response>'

        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'FirewallRule' -Action 'get' } | Should -Not -Throw
    }
}

Describe 'Assert-SfosApiReturnSuccess - Login Failure' {

    It 'Should throw when the firewall reports an authentication failure' {
        # Real answer of a failed login: HTTP 200, no entity, no status code - only the
        # lowercase <status> under <Login>. Treating this as success made every write
        # report success while nothing happened on the firewall.
        $xml = [xml]'<Response APIVersion="2200.1"><Login><status>Authentication Failure</status></Login></Response>'

        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'IPHost' -Action 'create' -Target 'Web01' } |
            Should -Throw '*Authentication Failure*'
    }

    It 'Should not throw when the login succeeded and the entity status is 200' {
        $xml = [xml]'<Response><Login><status>Authentication Successful</status></Login><IPHost><Status code="200">OK</Status></IPHost></Response>'

        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'IPHost' -Action 'create' } | Should -Not -Throw
    }
}

Describe 'Get-SfosApiStatus - Multiple Status Nodes' {

    It 'Should return one object per status node instead of collapsing them' {
        # A bulk delete answers with one <Status> per object. Property access used to
        # collapse these into a single value whose code read "200 529".
        $xml = [xml]'<Response><FQDNHost><Status code="200">OK</Status><Status code="526">Record does not exist.</Status></FQDNHost></Response>'

        $result = @(Get-SfosApiStatus -Xml $xml -ObjectName 'FQDNHost')

        $result.Count | Should -Be 2
        $result[0].Code | Should -Be '200'
        $result[1].Code | Should -Be '526'
    }

    It 'Should throw on the failing node of a mixed bulk result' {
        $xml = [xml]'<Response><FQDNHost><Status code="200">OK</Status><Status code="526">Record does not exist.</Status></FQDNHost></Response>'

        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'FQDNHost' -Action 'remove' } |
            Should -Throw '*526*'
    }
}

Describe 'Resolve-SfosParameters - Explicit Values Win' {

    AfterEach {
        Disconnect-SfosFirewall
    }

    It 'Should let an explicit -SkipCertificateCheck:$false override the session' {
        $cred = New-Object System.Management.Automation.PSCredential('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw.example.test' -Credential $cred -SkipCertificateCheck | Out-Null

        $resolved = Resolve-SfosParameters -BoundParameters @{ SkipCertificateCheck = [switch]$false }
        $resolved.SkipCertificateCheck | Should -BeFalse
    }

    It 'Should inherit SkipCertificateCheck from the session when not specified' {
        $cred = New-Object System.Management.Automation.PSCredential('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw.example.test' -Credential $cred -SkipCertificateCheck | Out-Null

        $resolved = Resolve-SfosParameters -BoundParameters @{}
        $resolved.SkipCertificateCheck | Should -BeTrue
    }
}

Describe 'Assert-SfosApiReturnSuccess - Full status code table' {

    # Status table: 200/216 success, 201/203/211-215 warn, 204-210 fail, 217/222 warn
    # (measured, undocumented), the rest of 217-499 throws, 500-599 throws.
    # No 202 anywhere (covered separately above).

    Context 'Warn-but-succeed codes (201, 203, 211-215)' {
        # Pester's -ForEach on It, not a plain 'foreach' around the It block: the It body is
        # deferred to the Run phase, and a plain loop variable is shared by reference across
        # every iteration's closure, so every generated test ends up seeing the loop's final
        # value instead of its own. -ForEach binds $_ per test correctly.
        It 'Should warn but not throw on code <_>' -ForEach @(201, 203, 211, 212, 213, 214, 215) {
            $xml = [xml]("<Response><Status code=""{0}""><Msg>Operation partially successful.</Msg></Status></Response>" -f $_)
            { Assert-SfosApiReturnSuccess -Xml $xml -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Should emit a warning on code <_>' -ForEach @(201, 203, 211, 212, 213, 214, 215) {
            $xml = [xml]("<Response><Status code=""{0}""><Msg>Operation partially successful.</Msg></Status></Response>" -f $_)
            Assert-SfosApiReturnSuccess -Xml $xml -WarningVariable warnings -WarningAction SilentlyContinue
            $warnings.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Failing codes (204-210, "Operation partially failed")' {
        It 'Should throw on code <_>' -ForEach @(204, 205, 206, 207, 208, 209, 210) {
            $xml = [xml]("<Response><Status code=""{0}""><Msg>Operation partially failed.</Msg></Status></Response>" -f $_)
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Undocumented gap 217-499' {
        It 'Should warn but not throw on the measured code 217' {
            $xml = [xml]'<Response><Status code="217">Unable to get status message</Status></Response>'
            { Assert-SfosApiReturnSuccess -Xml $xml -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Should warn but not throw on the measured code 222' {
            $xml = [xml]'<Response><Status code="222">Unable to get status message</Status></Response>'
            { Assert-SfosApiReturnSuccess -Xml $xml -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Should throw on the unmeasured gap code <_> - waving it through would fail open' -ForEach @(220, 250, 300, 450, 499) {
            $xml = [xml]("<Response><Status code=""{0}""><Msg>Unrecognised</Msg></Status></Response>" -f $_)
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw
        }
    }

    Context '5xx failure codes' {
        It 'Should throw on code <_>' -ForEach @(500, 526, 528, 529, 530) {
            $code = $_
            $xml = [xml]("<Response><Status code=""{0}""><Msg>Failure</Msg></Status></Response>" -f $code)
            { Assert-SfosApiReturnSuccess -Xml $xml -ErrorAction Stop } | Should -Throw "*$code*"
        }
    }
}

Describe 'Resolve-SfosParameters - Precedence and Missing Values' {

    AfterEach {
        Disconnect-SfosFirewall
    }

    It 'Should let every explicit connection parameter override a stored session' {
        $sessionCred = New-Object System.Management.Automation.PSCredential('sessionuser', (ConvertTo-SecureString 'sessionpw' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'session.example.test' -Port 4444 -Credential $sessionCred | Out-Null

        $explicitPassword = ConvertTo-SecureString 'explicitpw' -AsPlainText -Force
        $resolved = Resolve-SfosParameters -BoundParameters @{
            Firewall = 'explicit.example.test'
            Port     = 8443
            Username = 'explicituser'
            Password = $explicitPassword
        }

        $resolved.Firewall | Should -Be 'explicit.example.test'
        $resolved.Port | Should -Be 8443
        $resolved.Username | Should -Be 'explicituser'
        $resolved.Password | Should -Be $explicitPassword
    }

    It 'Should throw when neither explicit parameters nor an active session are available' {
        { Resolve-SfosParameters -BoundParameters @{} } | Should -Throw '*No active Sophos Firewall connection*'
    }
}

Describe 'SophosFirewall.Core Integration Tests' {

    Context 'XML API Request Pattern Validation' {
        It 'Should correctly escape parameters in XML' {
            $name = 'Test & Special'
            $escaped = ConvertTo-SfosXmlEscaped $name
            $escaped | Should -Match '&amp;'
        }
    }

    Context 'Pipeline Support' {
        It 'ConvertTo-SfosXmlEscaped should support pipeline input' {
            'Test & Value' | ConvertTo-SfosXmlEscaped | Should -Be 'Test &amp; Value'
        }
    }
}

Describe 'Assert-SfosApiReturnSuccess - Fail-open guard for a status at an unexpected path' {

    # Measured against New-SfosL2TPConnection: its create/update status landed FLAT at
    # /Response/Configuration/Status while a wrong -ObjectName pointed at the nested
    # Get/Remove shape ('L2TPConnection/Configuration'). The lookup found nothing at either
    # the expected path or the plain /Response/Status fallback, and the function used to just
    # return - reporting success for a write that may have failed. These tests use the exact
    # mock shape and the deliberately wrong -ObjectName from that finding.

    It 'Should throw when an error status sits outside the expected -ObjectName path' {
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <Configuration><Status code="501">Invalid Request</Status></Configuration>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'L2TPConnection/Configuration' -Action 'create' -Target 'l2tpconn01' -ErrorAction Stop } |
            Should -Throw '*501*'
    }

    It 'Should name the path deviation in the thrown message, so -ObjectName can be corrected' {
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <Configuration><Status code="501">Invalid Request</Status></Configuration>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'L2TPConnection/Configuration' -Action 'create' -Target 'l2tpconn01' -ErrorAction Stop } |
            Should -Throw '*outside the expected path*'
    }

    It 'Should not throw when a success status sits outside the expected -ObjectName path, but should warn' {
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <Configuration><Status code="200">Configuration applied successfully.</Status></Configuration>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'L2TPConnection/Configuration' -Action 'create' -Target 'l2tpconn01' -WarningAction SilentlyContinue } |
            Should -Not -Throw
    }

    It 'Should emit a warning when a success status sits outside the expected -ObjectName path' {
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <Configuration><Status code="200">Configuration applied successfully.</Status></Configuration>
</Response>
'@
        Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'L2TPConnection/Configuration' -Action 'create' -Target 'l2tpconn01' -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings.Count | Should -BeGreaterThan 0
        [string]$warnings[0] | Should -Match 'outside the expected path'
    }

    It 'Should not fail open on a Status data field even when the fallback search runs' {
        # Same data-field exclusion as the primary lookup ('not(../Name)') has to hold for
        # the fallback search too, or a FirewallRule/NATRule's <Status>Enable</Status> would
        # be picked up as a fabricated success once a wrong -ObjectName forces the fallback.
        $xml = [xml]@'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule transactionid=""><Name>Allow-LAN</Name><Status>Enable</Status></FirewallRule>
</Response>
'@
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'SomeOtherEntity' -Action 'get' -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Should still behave exactly as before when there is no status anywhere in the response' {
        $xml = [xml]'<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>'
        { Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'IPHost' -Action 'create' -Target 'Web01' -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Should behave exactly as before when the status sits at the correct -ObjectName path' {
        # Backward-compatibility check: a correct path must not trigger the fallback warning.
        $xml = [xml]'<Response><Login><status>Authentication Successful</status></Login><IPHost><Status code="200">OK</Status></IPHost></Response>'
        Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'IPHost' -Action 'create' -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings.Count | Should -Be 0
    }
}

Describe 'Multi-Session Support' {

    AfterEach {
        # Every block below registers named sessions on top of whatever Connect-SfosFirewall
        # left behind - clear both the registry and the default session so tests cannot leak
        # into each other.
        Disconnect-SfosFirewall -All
    }

    Context 'Get-SfosSession - Registry CRUD' {
        It 'Should return nothing when no session is registered' {
            @(Get-SfosSession).Count | Should -Be 0
        }

        It 'Should list a session registered via Connect-SfosFirewall -Name' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Port 4444 -Credential $cred -Name 'fw1' | Out-Null

            $sessions = @(Get-SfosSession)
            $sessions.Count | Should -Be 1
            $sessions[0].Name | Should -Be 'fw1'
            $sessions[0].Firewall | Should -Be 'fw1.example.test'
            $sessions[0].Port | Should -Be 4444
            $sessions[0].Username | Should -Be 'u1'
        }

        It 'Should not expose a Password property in the session view' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null

            (Get-SfosSession -Name 'fw1').PSObject.Properties.Name | Should -Not -Contain 'Password'
        }

        It 'Should list several registered sessions' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            (Get-SfosSession).Name | Sort-Object | Should -Be @('fw1', 'fw2')
        }

        It 'Should throw for an unknown session name' {
            { Get-SfosSession -Name 'does-not-exist' } | Should -Throw '*does-not-exist*'
        }

        It 'Should look up a registered name case-insensitively' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'FW1' | Out-Null

            { Get-SfosSession -Name 'fw1' } | Should -Not -Throw
            (Get-SfosSession -Name 'fw1').Firewall | Should -Be 'fw1.example.test'
        }
    }

    Context 'Connect-SfosFirewall -NoDefault' {
        It 'Should not replace the default session when -Name and -NoDefault are both given' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            (Get-SfosSession -Name 'fw1').IsDefault | Should -BeTrue
            (Get-SfosSession -Name 'fw2').IsDefault | Should -BeFalse

            # The bare (no -Session) resolution path still has to see fw1 - the default
            # session is unaffected by registering fw2 on top of it.
            $resolved = Resolve-SfosParameters -BoundParameters @{}
            $resolved.Firewall | Should -Be 'fw1.example.test'
        }

        It 'Should still become the default session when -NoDefault is given without -Name' {
            # -NoDefault alone (no -Name) would strand the connection with no way to reach it
            # again, so it is documented and tested as a no-op in that case.
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -NoDefault | Out-Null

            $resolved = Resolve-SfosParameters -BoundParameters @{}
            $resolved.Firewall | Should -Be 'fw1.example.test'
        }
    }

    Context 'Resolve-SfosParameters - Session base selection' {
        It 'Should resolve a session by registered name' {
            $cred1 = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            $cred2 = New-Object System.Management.Automation.PSCredential('u2', (ConvertTo-SecureString 'p2' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred1 -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Port 8443 -Credential $cred2 -Name 'fw2' -NoDefault | Out-Null

            $resolved = Resolve-SfosParameters -BoundParameters @{ Session = 'fw2' }
            $resolved.Firewall | Should -Be 'fw2.example.test'
            $resolved.Port | Should -Be 8443
            $resolved.Username | Should -Be 'u2'
        }

        It 'Should resolve a session passed as the object returned by Connect-SfosFirewall identically to passing its name' {
            $cred = New-Object System.Management.Automation.PSCredential('u2', (ConvertTo-SecureString 'p2' -AsPlainText -Force))
            $fw2 = Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault

            $byName = Resolve-SfosParameters -BoundParameters @{ Session = 'fw2' }
            $byObject = Resolve-SfosParameters -BoundParameters @{ Session = $fw2 }

            $byObject.Firewall | Should -Be $byName.Firewall
            $byObject.Port | Should -Be $byName.Port
            $byObject.Username | Should -Be $byName.Username
        }

        It 'Should let an explicit connection parameter still win over the chosen -Session base' {
            $cred = New-Object System.Management.Automation.PSCredential('u2', (ConvertTo-SecureString 'p2' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Port 4444 -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            $resolved = Resolve-SfosParameters -BoundParameters @{ Session = 'fw2'; Port = 9999 }
            $resolved.Firewall | Should -Be 'fw2.example.test'
            $resolved.Port | Should -Be 9999
        }

        It 'Should throw for an unregistered session name' {
            { Resolve-SfosParameters -BoundParameters @{ Session = 'no-such-session' } } | Should -Throw '*no-such-session*'
        }

        It 'Should throw for an explicit -Session $null even while a default session is active' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred | Out-Null

            # ContainsKey is true here even though the value is $null - this is the case the
            # ContainsKey philosophy exists for: an explicit -Session $null disables the
            # default-session fallback rather than being read as "not supplied".
            { Resolve-SfosParameters -BoundParameters @{ Session = $null } } | Should -Throw '*No active Sophos Firewall connection*'
        }

        It 'Should throw for a duck-typing object with no Firewall property' {
            { Resolve-SfosParameters -BoundParameters @{ Session = [PSCustomObject]@{ NotFirewall = 'x' } } } | Should -Throw
        }

        It 'Should accept a duck-typed object that has a Firewall property' {
            $duckSession = [PSCustomObject]@{
                Firewall             = 'duck.example.test'
                Port                 = 4444
                Username             = 'duckuser'
                Password             = (ConvertTo-SecureString 'duckpw' -AsPlainText -Force)
                SkipCertificateCheck = $false
            }

            $resolved = Resolve-SfosParameters -BoundParameters @{ Session = $duckSession }
            $resolved.Firewall | Should -Be 'duck.example.test'
        }

        It 'Should behave exactly as before when the calling cmdlet has no -Session parameter at all' {
            # Connect (no -Name) -> Resolve (no Session key in BoundParameters) -> Disconnect,
            # the call shape used by every cmdlet without a -Session parameter.
            $cred = New-Object System.Management.Automation.PSCredential('bareuser', (ConvertTo-SecureString 'barepw' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'bare.example.test' -Port 4444 -Credential $cred -SkipCertificateCheck | Out-Null

            $resolved = Resolve-SfosParameters -BoundParameters @{}
            $resolved.Firewall | Should -Be 'bare.example.test'
            $resolved.Port | Should -Be 4444
            $resolved.Username | Should -Be 'bareuser'
            $resolved.SkipCertificateCheck | Should -BeTrue

            Disconnect-SfosFirewall
            { Resolve-SfosParameters -BoundParameters @{} } | Should -Throw '*No active Sophos Firewall connection*'
        }
    }

    Context 'Disconnect-SfosFirewall - Name, Session and All' {
        It 'Should remove only the named session with -Name, leaving others intact' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            Disconnect-SfosFirewall -Name 'fw2'

            (Get-SfosSession).Name | Should -Be @('fw1')
            { Resolve-SfosParameters -BoundParameters @{ Session = 'fw2' } } | Should -Throw '*fw2*'
        }

        It 'Should also clear the default session when the removed name is the current default' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null

            Disconnect-SfosFirewall -Name 'fw1'

            { Resolve-SfosParameters -BoundParameters @{} } | Should -Throw '*No active Sophos Firewall connection*'
        }

        It 'Should throw when -Name does not match a registered session' {
            { Disconnect-SfosFirewall -Name 'does-not-exist' } | Should -Throw '*does-not-exist*'
        }

        It 'Should accept a session object via -Session, including from the pipeline' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            $fw1 = Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1'

            $fw1 | Disconnect-SfosFirewall

            @(Get-SfosSession).Count | Should -Be 0
        }

        It 'Should actually remove the registered session when piped the Get-SfosSession view, not silently do nothing' {
            # Get-SfosSession's view is a different object (no Password, no PSTypeName tag)
            # than what is stored in the registry, so a naive reference match would find
            # nothing here and this would be a silent no-op.
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            Get-SfosSession -Name 'fw2' | Disconnect-SfosFirewall

            (Get-SfosSession).Name | Should -Be @('fw1')
        }

        It 'Should remove the matching session when a bare registered name is piped in' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null

            'fw1' | Disconnect-SfosFirewall

            @(Get-SfosSession).Count | Should -Be 0
        }

        It 'Should remove every registered session and the default session with -All' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1' | Out-Null
            Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault | Out-Null

            Disconnect-SfosFirewall -All

            @(Get-SfosSession).Count | Should -Be 0
            { Resolve-SfosParameters -BoundParameters @{} } | Should -Throw '*No active Sophos Firewall connection*'
        }

        It 'Should still clear the default session with no parameters, exactly as before' {
            $cred = New-Object System.Management.Automation.PSCredential('u1', (ConvertTo-SecureString 'p1' -AsPlainText -Force))
            Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred | Out-Null

            { Disconnect-SfosFirewall } | Should -Not -Throw
            { Resolve-SfosParameters -BoundParameters @{} } | Should -Throw '*No active Sophos Firewall connection*'
        }
    }
}

Describe 'Invoke-SfosApi - Session Parameter Set' {

    BeforeEach {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            [PSCustomObject]@{
                StatusCode = 200
                Content    = '<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>'
            }
        }
    }

    AfterEach {
        Disconnect-SfosFirewall -All
    }

    It 'Should send the same request as the explicit parameter set when resolved via a registered session name' {
        $cred = New-Object System.Management.Automation.PSCredential('sessuser', (ConvertTo-SecureString 'sesspw' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw2.example.test' -Port 4444 -Credential $cred -Name 'fw2' -NoDefault | Out-Null

        Invoke-SfosApi -Session 'fw2' -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $decoded = [uri]::UnescapeDataString($Body)
            $Uri -eq 'https://fw2.example.test:4444/webconsole/APIController' -and
            $decoded -like '*<Username>sessuser</Username>*' -and
            $decoded -like '*<Password>sesspw</Password>*' -and
            $decoded -like '*<Get><IPHost/></Get>*'
        }
    }

    It 'Should resolve a session passed as an object the same way as by name' {
        $cred = New-Object System.Management.Automation.PSCredential('sessuser', (ConvertTo-SecureString 'sesspw' -AsPlainText -Force))
        $fw2 = Connect-SfosFirewall -Firewall 'fw2.example.test' -Port 4444 -Credential $cred -Name 'fw2' -NoDefault

        Invoke-SfosApi -Session $fw2 -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://fw2.example.test:4444/webconsole/APIController'
        }
    }

    It 'Should throw for an unregistered session name and never call Invoke-WebRequest' {
        { Invoke-SfosApi -Session 'no-such-session' -InnerXml '<Get/>' } | Should -Throw '*no-such-session*'

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 0 -Exactly
    }

    It 'Should still support the explicit parameter set unchanged when -Session is not used' {
        Invoke-SfosApi -Firewall 'fw.example.test' -Port 4444 -Username 'apiuser' `
            -Password (ConvertTo-SecureString 'pw' -AsPlainText -Force) -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://fw.example.test:4444/webconsole/APIController'
        }
    }
}

Describe 'Invoke-SfosApi - TimeoutSec' {

    BeforeAll {
        $callArgs = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -MockWith {
            [PSCustomObject]@{
                StatusCode = 200
                Content    = '<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>'
            }
        }
    }

    It 'Should default TimeoutSec to 30 when not specified' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $TimeoutSec -eq 30
        }
    }

    It 'Should pass an explicit TimeoutSec through to Invoke-WebRequest' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' -TimeoutSec 5 | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $TimeoutSec -eq 5
        }
    }

    It 'Should omit TimeoutSec entirely when 0 is passed' {
        Invoke-SfosApi @callArgs -InnerXml '<Get><IPHost/></Get>' -TimeoutSec 0 | Out-Null

        Should -Invoke -CommandName Invoke-WebRequest -ModuleName SophosFirewall.Core -Times 1 -Exactly -ParameterFilter {
            $null -eq $TimeoutSec
        }
    }
}
