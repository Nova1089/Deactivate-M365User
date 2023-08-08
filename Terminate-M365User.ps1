<#
Sign out of all sessions
Block sign-in
Reset password
Hide from GAL
Convert to shared mailbox
Release all office licenses
Remove user from corporate members
#>

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
    Write-Host "This script terminates a user in Microsoft 365." -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function PromptFor-User
{
    $keepGoing = $true

    while ($keepGoing)
    {
        $searchString = Read-Host "Enter full name or UPN of the user to disable."
        $user = Get-AzureAdUser -SearchString $searchString

        if ($null -eq $user)
        {
            Write-Warning "User was not found, please try again."
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
        $correct = Prompt-YesOrNo "Is this the user you want to terminate?"

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
        $success = $true
    }
    catch
    {
        $success = $false
        Write-Host "An error occurred when signing user out of their sessions: `n" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
    }
    
    if ($success)
    {
        Write-Host "User signed out of all sessions." -ForegroundColor $successColor
    }    
}

function Block-SignIn($objectId)
{
    try
    {
        Set-AzureAdUser -ObjectId $objectId -AccountEnabled $false
    }
    catch
    {
        Write-Host "An error occurred when blocking ability to sign-in: `n" -ForegroundColor $failColor
        throw $_ # $_ represents the ErrorRecord object
    }
    
    Write-Host "User sign-in blocked."
}

function Change-Password($objectId)
{
    try
    {
        $randomPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
        $passwordAsSecureString = ConvertTo-SecureString -String $randomPassword -AsPlainText -Force
        Set-AzureADUserPassword -ObjectId $objectId -Password $passwordAsSecureString
        $success = $true
    }
    catch
    {
        Write-Host "An error occurred when changing password: `n" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        $success = $false
    }

    if ($success)
    {
        Write-Host "User password changed." -ForegroundColor $successColor
    }
}

function HideFrom-GlobalAddressList($upn)
{
    try
    {
        Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true
        $success = $true
    }
    catch
    {
        Write-Host "An error occurred when hiding the user from the GAL: `n" -ForegroundColor $warningColor
        Write-Host $_.Exception.Message -ForegroundColor $warningColor # $_ represents the ErrorRecord object
        $success = $false
    }

    if ($success)
    {
        Write-Host "User hidden from the GAL." -ForegroundColor $successColor
    }
}

function ConvertTo-SharedMailbox($upn)
{
    Set-Mailbox -Identity $upn -Type "Shared"
    Write-Host "Converted to shared mailbox." -ForegroundColor $successColor
}

function Remove-AllLicenses($azureUser)
{    
    $skuIds = New-Object -TypeName System.Collections.Generic.List[string]

    foreach ($license in $azureUser.AssignedLicenses)
    {
        $skuIds.Add($license.SkuId)
    }

    $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
    $licenses.RemoveLicenses = $skuIds

    Set-AzureADUserLicense -ObjectId $azureUser.ObjectId -AssignedLicenses $licenses

    $updatedUser = Get-AzureADUser -ObjectId $azureUser.ObjectId

    if ($updatedUser.AssignedLicenses.Count -gt 0)
    {
        Write-Host "There was an issue removing the user's licenses. They'll need to be removed manually." -ForegroundColor $warningColor
    }
}

# main
Initialize-ColorScheme
Show-Introduction
$user = PromptFor-User
SignOut-AllSessions -ObjectId $user.ObjectId
Block-SignIn -ObjectId $user.ObjectId
Change-Password -ObjectId $user.ObjectId
HideFrom-GlobalAddressList -UPN $user.UserPrincipalName
ConvertTo-SharedMailbox -UPN $user.UserPrincipalName
Remove-AllLicenses -AzureUser $user







