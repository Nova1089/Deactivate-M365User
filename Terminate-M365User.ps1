# functions
function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:warningColor = "Yellow"
    $script:failColor = "Red"    
}

function Show-Introduction
{
    Write-Host ("This script terminates a user in Microsoft 365 by performing the following: `n" +
                "- Signs them out of all sessions. `n" +
                "- Blocks them from signing in. `n" +
                "- Resets their password to a random, undocumented password. `n" +
                "- Hides them from the Global Address List (GAL). `n" +
                "- Converts their email to a shared mailbox. `n" +
                "- Removes all their licenses. `n" +
                "- Removes their membership to the `"Blue Raven Corporate`" group."
    ) -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function Use-Module($moduleName)
{    
    $keepGoing = -not(Test-ModuleInstalled $moduleName)
    while ($keepGoing)
    {
        Prompt-InstallModule $moduleName
        Test-SessionPrivileges
        Install-Module $moduleName

        if ((Test-ModuleInstalled $moduleName) -eq $true)
        {
            Write-Host "Importing module..." -ForegroundColor $infoColor
            Import-Module $moduleName
            $keepGoing = $false
        }
    }
}

function Test-ModuleInstalled($moduleName)
{    
    $module = Get-Module -Name $moduleName -ListAvailable
    return ($null -ne $module)
}

function Prompt-InstallModule($moduleName)
{
    do 
    {
        Write-Host "$moduleName module is required." -ForegroundColor $infoColor
        $confirmInstall = Read-Host -Prompt "Would you like to install the module? (y/n)"
    }
    while ($confirmInstall -inotmatch "^\s*y\s*$") # regex matches a y but allows spaces
}

function Test-SessionPrivileges
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentSessionIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($currentSessionIsAdmin -ne $true)
    {
        Write-Host ("Please run script with admin privileges.`n" +
            "1. Open Powershell as admin.`n" +
            "2. CD into script directory.`n" +
            "3. Run .\scriptname`n") -ForegroundColor $failColor
        Read-Host "Press Enter to exit"
        exit
    }
}

function TryConnect-AzureAD
{
    $connected = Test-ConnectedToAzureAD

    while(-not($connected))
    {
        Write-Host "Connecting to Azure AD..." -ForegroundColor $infoColor
        Connect-AzureAD -ErrorAction SilentlyContinue

        $connected = Test-ConnectedToAzureAD
        if(-not($connected))
        {
            Write-Warning "Failed to connect to Azure AD."
            Read-Host "Press Enter to try again"
        }
    }
}

function Test-ConnectedToAzureAD
{
    try
    {
        Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
    }
    catch
    {
        return $false
    }
    return $true
}

function TryConnect-ExchangeOnline
{
    $connectionStatus = Get-ConnectionInformation -ErrorAction SilentlyContinue

    while ($null -eq $connectionStatus)
    {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor $infoColor
        Connect-ExchangeOnline -ErrorAction SilentlyContinue

        $connectionStatus = Get-ConnectionInformation
        if ($null -eq $connectionStatus)
        {
            Write-Warning "Failed to connect to Exchange Online."
            Read-Host "Press Enter to try again"
        }
    }
}

function PromptFor-User
{
    $keepGoing = $true

    while ($keepGoing)
    {
        $searchString = Read-Host "Enter full name or UPN of the user to terminate"

        if ($searchString -eq "")
        {
            $keepGoing = $true
            continue
        }

        $user = Get-AzureAdUser -SearchString $searchString

        if ($null -eq $user)
        {
            Write-Warning "User was not found. Please try again."
            $keepGoing = $true
            continue
        }

        if ($user.Count -gt 1)
        {
            Write-Warning "More than one user was found. Please use the UPN to uniquely identify the user."
            $keepGoing = $true
            continue
        }

        Write-Host "Found user: $($user.UserPrincipalName)" -ForegroundColor $successColor
        $correct = Prompt-YesOrNo "Are you sure you want to terminate this user?"

        if ($correct)
        {
            $keepGoing = $false
        }
        else
        {
            $keepGoing = $true
        }
    }
    return $user
}

function Prompt-YesOrNo($question)
{
    Write-Host "$question`n[Y] Yes  [N] No"

    do
    {
        $response = Read-Host
        $validResponse = $response -imatch '^\s*[yn]\s*$' # regex matches y or n but allows spaces
        if (-not($validResponse)) 
        {
            Write-Warning "Please enter y or n."
        }
    }
    while (-not($validResponse))

    if ($response.Trim() -ieq "y")
    {
        return $true
    }
    return $false
}

function SignOut-AllSessions($objectId)
{
    try
    {
        Revoke-AzureADUserAllRefreshToken -ObjectId $objectId
        Write-Host "User signed out of all sessions." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when signing user out of their sessions:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    } 
}

function Block-SignIn($objectId)
{
    try
    {
        Set-AzureAdUser -ObjectId $objectId -AccountEnabled $false
        Write-Host "User sign-in blocked." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when blocking ability to sign-in:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }
}

function Change-Password($objectId)
{
    try
    {
        $randomPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
        $passwordAsSecureString = ConvertTo-SecureString -String $randomPassword -AsPlainText -Force
        Set-AzureADUserPassword -ObjectId $objectId -Password $passwordAsSecureString
        Write-Host "User password changed." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when changing password:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }
}

function HideFrom-GlobalAddressList($upn)
{
    try
    {
        Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true
        Write-Host "User hidden from the GAL." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when hiding the user from the GAL:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }
}

function ConvertTo-SharedMailbox($upn)
{
    try
    {
        Set-Mailbox -Identity $upn -Type "Shared"
        Write-Host "Converted to shared mailbox." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when converting to shared mailbox:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }
}

function Remove-AllLicenses($azureUser)
{    
    try
    {
        $skuIds = New-Object -TypeName System.Collections.Generic.List[string]
        foreach ($license in $azureUser.AssignedLicenses)
        {
            $skuIds.Add($license.SkuId)
        }

        $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
        $licenses.RemoveLicenses = $skuIds

        Set-AzureADUserLicense -ObjectId $azureUser.ObjectId -AssignedLicenses $licenses
        Write-Host "Removed all licenses." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when removing licenses:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }

    $updatedUser = Get-AzureADUser -ObjectId $azureUser.ObjectId
    if ($updatedUser.AssignedLicenses.Count -gt 0)
    {
        Write-Host "There was an issue removing all the user's licenses. They'll need to be removed manually." -ForegroundColor $warningColor
    }
}

function Remove-GroupMembership($userId, $groupId)
{
    # Both userId and groupId can be a name, alias, email address, or GUID.
    try
    {
        Remove-UnifiedGroupLinks -Links $userId -Identity $groupId -LinkType "Members" -Confirm:$false
        Write-Host "Removed group membership to $groupId." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when removing membership to $groupId`:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
    }
}

# main
Initialize-ColorScheme
Show-Introduction
Use-Module "AzureAD"
Use-Module "ExchangeOnlineManagement"
TryConnect-AzureAD
TryConnect-ExchangeOnline
$user = PromptFor-User
Write-Host "Processing..." -ForegroundColor $infoColor
SignOut-AllSessions -ObjectId $user.ObjectId
Block-SignIn -ObjectId $user.ObjectId
Change-Password -ObjectId $user.ObjectId
HideFrom-GlobalAddressList -UPN $user.UserPrincipalName
ConvertTo-SharedMailbox -UPN $user.UserPrincipalName
Remove-AllLicenses -AzureUser $user
Remove-GroupMembership -UserId $user.UserPrincipalName -GroupId "corporate@blueravensolar.com"
Read-Host "Press Enter to exit"
