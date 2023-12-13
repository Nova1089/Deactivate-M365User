# Version 1.5

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
    Write-Host ("This script deactivates a user in Microsoft 365 by performing the following: `n" +
                "- Signs them out of all sessions. `n" +
                "- Blocks them from signing in. `n" +
                "- Resets their password to a random, undocumented password. `n" +
                "- Hides them from the Global Address List (GAL). `n" +
                "- Converts their email to a shared mailbox. `n" +
                "- Removes all their licenses. `n" +
                "- Removes their membership to the `"Blue Raven Corporate`" group. `n" +
                "- Removes all admin roles. `n" +
                "- Checks for litigation hold, and if so, assigns the Exchange Online Plan 2 license. `n" +
                "- If needed, forwards their emails to the mailbox of your choice. `n"
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
        Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null

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
        Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue | Out-Null
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
        $upn = Read-Host "Enter the UPN of the user to deactivate"

        if ($upn -eq "")
        {
            $keepGoing = $true
            continue
        }

        try
        {
            $user = Get-AzureAdUser -ObjectId $upn -ErrorAction "SilentlyContinue"
        }
        catch
        {
            # Try catch is just here to suppress unneeded error messages.
        }        

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

        Write-Host "Found user:" -ForegroundColor $successColor
        $user | Select-Object UserPrincipalName, JobTitle, Department | Format-Table | Out-Host

        $ready = Prompt-YesOrNo "Are you sure you want to deactivate this user?"
        if ($ready)
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

function Show-TimeStamp
{
    $timeStamp = Get-Date -Format yyyy-MM-dd-hh-mmtt
    Write-Host $timestamp -ForegroundColor $infoColor
}

function SignOut-AllSessions($azureUser)
{
    try
    {
        $azureUser | Revoke-AzureADUserAllRefreshToken
        Write-Host "User signed out of all sessions." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when signing user out of their sessions:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    } 
}

function Block-SignIn($azureUser)
{
    if (-not($azureUser.AccountEnabled))
    {
        Write-Host "User sign-in is already blocked." -ForegroundColor $successColor
        return
    }

    try
    {
        $azureUser | Set-AzureAdUser -AccountEnabled $false
        Write-Host "User sign-in blocked." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when blocking ability to sign-in:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    }
}

function Set-RandomPassword($azureUser)
{
    try
    {
        $randomPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
        $passwordAsSecureString = ConvertTo-SecureString -String $randomPassword -AsPlainText -Force
        $azureUser | Set-AzureADUserPassword -Password $passwordAsSecureString
        Write-Host "User password set to something random." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when setting random password:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    }
}

function HideFrom-GlobalAddressList($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    if ($mailbox.HiddenFromAddressListsEnabled)
    {
        Write-Host "Mailbox is already hidden from the GAL." -ForegroundColor $successColor
        return
    }
    
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
        return
    }
}

function ConvertTo-SharedMailbox($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    if ($mailbox.RecipientTypeDetails -eq "SharedMailbox")
    {
        Write-Host "Mailbox is already a 'Shared Mailbox'." -ForegroundColor $successColor
        return
    }
    
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
        return
    }
}

function Remove-AllLicenses($azureUser)
{    
    if ($azureUser.AssignedLicenses.Count -eq 0)
    {
        Write-Host "User has no licenses to remove." -ForegroundColor $successColor
        return
    }
    
    try
    {
        $skuIds = New-Object -TypeName System.Collections.Generic.List[string]
        foreach ($license in $azureUser.AssignedLicenses)
        {
            $skuIds.Add($license.SkuId)
        }

        $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
        $licenses.RemoveLicenses = $skuIds

        $azureUser | Set-AzureADUserLicense -AssignedLicenses $licenses
        Write-Host "Removed all licenses." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when removing licenses:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    }

}

function Remove-GroupMembership($azureUser, $groupUpn)
{
    $isGroupMember = Test-IsMemberOfGroup -AzureUser $azureUser -GroupUpn $groupUpn
    if (-not($isGroupMember))
    {
        Write-Host "User is not a member of $groupUpn." -ForegroundColor $successColor
        return
    }
    
    try
    {
        Remove-UnifiedGroupLinks -Links $azureUser.UserPrincipalName -Identity $groupUpn -LinkType "Members" -Confirm:$false
        Write-Host "Removed group membership to $groupUpn." -ForegroundColor $successColor
    }
    catch
    {
        Write-Host "An error occurred when removing membership to $groupUpn`:" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    }
}

function Test-IsMemberOfGroup($azureUser, $groupUpn)
{
    $userMemberships = $azureUser | Get-AzureADUserMembership
    foreach ($group in $userMemberships)
    {
        if ($group.Mail -ieq $groupUpn)
        {
            return $true
        }
    }
    return $false
}

function Remove-AllAdminRoles($azureUser)
{
    $allRoles = Get-AzureADDirectoryRole
    $removedRoles = New-Object -TypeName System.Collections.Generic.List[object]

    $success = $true
    foreach ($role in $allRoles)
    {
        try
        {
            if (Test-HasAdminRole -Role $role -AzureUser $azureUser)
            {
                Remove-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -MemberId $azureUser.ObjectId
                $removedRoles.Add($role)
            } 
        }
        catch
        {
            $success = $false
            Write-Host "An error occurred when removing role:" -ForegroundColor $warningColor
            $role | Out-Host
            Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
            Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        }        
    }

    if ($removedRoles.Count -gt 0)
    {
        Write-Host "Removed the following admin roles:" -ForegroundColor $successColor
        $removedRoles | Select-Object DisplayName, Description | Out-Host
    }
    elseif ($success)
    {
        Write-Host "User has no admin roles to remove." -ForegroundColor $successColor
    }
}

function Test-HasAdminRole($role, $azureUser)
{
    return $null -ne ($role | Get-AzureADDirectoryRoleMember | Where-Object { $_.ObjectId -eq $azureUser.ObjectId })
}

function Assign-LicenseForLitigationHold($upn)
{   
    try
    {
        Assign-License -UPN $upn -LicenseSkuId "19ec0d23-8335-4cbd-94ac-6050e30712fa" # SKU ID for Exchange Online Plan 2 license.
    }
    catch
    {
        if ($_.Exception.Message -ilike "*does not have any available licenses*")
        {
            Write-Warning "Tried assigning Exchange Online Plan 2 license (needed for litigation hold), but there were none available."
        }
        else
        {
            Write-Warning "Tried assigning Exchange Online Plan 2 license (needed for litigation hold), but there was an error:"
            Write-Host $_.Exception.Message -ForegroundColor $warningColor
        }
        return
    }
    
    Write-Host "Assigned Exchange Online Plan 2 license. (Needed for litigation hold.)" -ForegroundColor $successColor   
}

function Test-LitigationHoldEnabled($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    if ($mailbox.LitigationHoldEnabled)
    {
        Write-Host "Mailbox is currently on litigation hold." -ForegroundColor $infoColor
    }
    else
    {
        Write-Host "Mailbox is NOT on litigation hold. (No license needs to be assigned.)" -ForegroundColor $infoColor
    }
    return $mailbox.LitigationHoldEnabled
}

function Assign-License($upn, $licenseSkuId)
{
    # For a list of license SKU IDs, see: https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference

    $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $license.SkuId = $licenseSkuId
    $licensesToAssign = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
    $licensesToAssign.AddLicenses = $license

    try
    {
        Set-AzureADUserLicense -ObjectId $upn -AssignedLicenses $licensesToAssign -ErrorAction Stop
    }
    catch
    {
        throw
    }
}

function Prompt-ForwardingRecipientMailbox
{
    do
    {
        $recipientEmail = Read-Host "Enter the email address to forward to"
        $recipientEmail = $recipientEmail.Trim()
        $recipientMb = Get-Mailbox -Identity $recipientEmail
        if ($null -eq $recipientMb)
        {
            Write-Warning "Mailbox not found. Please try again."
            $foundRecipientMailbox = $false
            continue
        }
        else
        {
            $foundRecipientMailbox = $true
        }
    }
    while (-not($foundRecipientMailbox))

    return $recipientMb
}

function Forward-Emails($upn, $recipientMailbox)
{
    $sourceMailbox = Get-Mailbox -Identity $upn
    if ($sourceMailbox.ForwardingSmtpAddress -ieq "smtp:$($recipientMailbox.UserPrincipalName)")
    {
        Write-Host "Mailbox is already being forwarded to $($recipientMailbox.UserPrincipalName)." -ForegroundColor $successColor
        return
    }
    
    try
    {
        Set-Mailbox -Identity $upn -ForwardingSmtpAddress $recipientMailbox.UserPrincipalName -DeliverToMailboxAndForward $true
    }
    catch
    {
        Write-Host "An error occurred when forwarding the mailbox." -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        Write-Host "This will need to be done manually." -ForegroundColor $warningColor
        return
    }
    Write-Host "Mailbox was forwarded to $($recipientMailbox.UserPrincipalName)." -ForegroundColor $successColor
}

function Test-SignInBlocked($azureuser)
{
    $updatedUser = Get-AzureAdUser -ObjectId $azureUser.ObjectId
    if ($updatedUser.AccountEnabled)
    {
        Write-Warning "There was an issue blocking sign-in. This will need to be done manually."
    }
}

function Test-HiddenFromGlobalAddressList($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    if (-not($mailbox.HiddenFromAddressListsEnabled))
    {
        Write-Warning "There was an issue hiding the user from the GAL. This will need to be done manually."
        return $false
    }
    return $true
}

function Test-ConvertedToSharedMailbox($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    if ($mailbox.RecipientTypeDetails -ne "SharedMailbox")
    {
        Write-Warning "There was an issue converting to shared mailbox. This will need to be done manually."
        return $false
    }
    return $true
}

function Test-AllLicensesRemoved($azureUser, [string[]]$excludedLicenseSkuIds)
{
    $updatedUser = Get-AzureADUser -ObjectId $azureUser.ObjectId

    if ($updatedUser.AssignedLicenses.Count -eq 0) { return $true } 

    if ($null -eq $excludedLicenseSkuIds) 
    { 
        Write-Warning "There was an issue removing all the user's licenses. They'll need to be removed manually."
        return $false 
    }

    if ($updatedUser.AssignedLicenses.Count -gt $excludedLicenseSkuIds.Count)
    {
        Write-Warning "There was an issue removing all the user's licenses. They'll need to be removed manually."
        return $false 
    }

    # Making sure the only licenses they have are ones specified by $excludedLicenseSkuIds.
    foreach ($skuId in $excludedLicenseSkuIds)
    {        
        $hasLicense = Test-UserHasLicense -AzureUser $updatedUser -LicenseSkuId $skuId
        if (-not($hasLicense))
        {
            Write-Warning "There was an issue removing all the user's licenses. They'll need to be removed manually."
            return $false 
        }
    }

    return $true
}

function Test-MembershipRemoved($azureUser, $groupUpn)
{
    $isGroupMember = Test-IsMemberOfGroup -AzureUser $azureUser -GroupUpn $groupUpn
    if ($isGroupMember)
    {
        Write-Warning "There was an issue removing the user from group: $groupUpn. This will need to be done manually."
        return $false
    }
    return $true
}

function Test-AllAdminRolesRemoved($azureUser)
{
    $allRoles = Get-AzureADDirectoryRole

    $foundAdminRole = $false
    foreach ($role in $allRoles)
    {
        if (Test-HasAdminRole -Role $role -AzureUser $azureUser)
        {
            Write-Warning "There was an issue removing the role from the user: $($role.DisplayName). This will need to be done manually."
            $foundAdminRole = $true
        }
    }
    return -not($foundAdminRole)
}

function Test-LitigationHoldHandled($upn)
{
    $mailbox = Get-Mailbox -Identity $upn
    $azureUser = Get-AzureADUser -ObjectId $upn

    if ($mailbox.LitigationHoldEnabled)
    {
        $hasLicense = Test-UserHasLicense -AzureUser $azureUser -LicenseSkuId "19ec0d23-8335-4cbd-94ac-6050e30712fa"
        if (-not($hasLicense))
        {
            Write-Warning "There was an issue assigning Exchange Online Plan 2 license (needed for litigation hold). This will need to be done manually."
            return $false
        }
    }
    return $true
}

function Test-UserHasLicense($azureUser, $licenseSkuId)
{
    # For a list of license SKU IDs, see: https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference

    foreach ($license in $azureUser.AssignedLicenses)
    {
        if ($license.SkuId -ieq $licenseSkuId)
        {
            return $true
        }
    }
    return $false
}

function Test-EmailsForwarded($upn, $recipientMailbox)
{
    $sourceMailbox = Get-Mailbox -Identity $upn
    if ($sourceMailbox.ForwardingSmtpAddress -ine "smtp:$($recipientMailbox.UserPrincipalName)")
    {
        Write-Warning "There was an issue forwarding the mailbox."
        Write-Host "Expected ForwardingSmtpAddress: smtp:$($recipientMailbox.UserPrincipalName)" -ForegroundColor $warningColor
        Write-Host "Actual ForwardingSmtpAddress: $($sourceMailbox.ForwardingSmtpAddress)" -ForegroundColor $warningColor
        return $false
    }
    return $true
}

# main
Initialize-ColorScheme
Show-Introduction
$azureADPreviewInstalled = Test-ModuleInstalled "AzureADPreview"
if (-not($azureADPreviewInstalled))
{
    Use-Module "AzureAD"
}
Use-Module "ExchangeOnlineManagement"
TryConnect-AzureAD
TryConnect-ExchangeOnline
$user = PromptFor-User
Show-TimeStamp
Write-Host "Processing..." -ForegroundColor $infoColor
SignOut-AllSessions -AzureUser $user
Block-SignIn -AzureUser $user
Set-RandomPassword -AzureUser $user
HideFrom-GlobalAddressList -UPN $user.UserPrincipalName
ConvertTo-SharedMailbox -UPN $user.UserPrincipalName
Remove-AllLicenses -AzureUser $user
Remove-GroupMembership -AzureUser $user -GroupUpn "corporate@blueravensolar.com"
Remove-AllAdminRoles -AzureUser $user

$litigationHoldEnabled = Test-LitigationHoldEnabled -UPN $user.UserPrincipalName
if ($litigationHoldEnabled)
{
    Assign-LicenseForLitigationHold -UPN $user.UserPrincipalName
}

$shouldForward = Prompt-YesOrNo "Do their emails need to be forwarded?"
if ($shouldForward)
{
    $recipientMailbox = Prompt-ForwardingRecipientMailbox
    Forward-Emails -UPN $user.UserPrincipalName -RecipientMailbox $recipientMailbox
}

# testing
$secondsToWait = 10
Write-Host "Waiting $secondsToWait seconds to check that all was successful..." -ForegroundColor $infoColor
Start-Sleep -Seconds $secondsToWait
Write-Host "Checking..." -ForegroundColor $infoColor

$allGood = $true
if ($false -eq (Test-SignInBlocked $user)) {$allGood = $false}
if ($false -eq (Test-HiddenFromGlobalAddressList $user.UserPrincipalName)) { $allGood = $false }
if ($false -eq (Test-ConvertedToSharedMailbox $user.UserPrincipalName)) { $allGood = $false }
if ($litigationHoldEnabled)
{
    # SKU ID for Exchange Online Plan 2 license
    if ($false -eq (Test-AllLicensesRemoved -AzureUser $user -ExcludedLicenseSkuIds "19ec0d23-8335-4cbd-94ac-6050e30712fa")) { $allGood = $false }
}
else
{
    if ($false -eq (Test-AllLicensesRemoved -AzureUser $user)) { $allGood = $false }
}
if ($false -eq (Test-MembershipRemoved -AzureUser $user -GroupUpn "corporate@blueravensolar.com")) { $allGood = $false }
if ($false -eq (Test-AllAdminRolesRemoved $user)) { $allGood = $false }
if ($false -eq (Test-LitigationHoldHandled $user.UserPrincipalName)) { $allGood = $false }
if ($shouldForward -and $false -eq (Test-EmailsForwarded -UPN $user.UserPrincipalName -RecipientMailbox $recipientMailbox)) { $allGood = $false }
if ($allGood) { Write-Host "Everything was a success!" -ForegroundColor $successColor }

Read-Host "Press Enter to exit"