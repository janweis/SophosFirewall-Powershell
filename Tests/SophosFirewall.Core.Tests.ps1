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

    # CLAUDE.md SS5 status table: 200/216 success, 201/203/211-215 warn, 204-210 fail,
    # 217/222 warn (measured, undocumented), the rest of 217-499 throws, 500-599 throws.
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
