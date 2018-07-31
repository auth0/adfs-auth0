#####################################################################
# Script: configureAdfs.ps1
# Descrption: Add and remove a relying party to ADFS with rules
######################################################################

function AddRelyingParty
(
[string]$realm = $(throw "Realm for the application is required. E.g.: http://whatever.com or urn:whatever"),
[string]$webAppEndpoint = $(throw "Endpoint where the token will be POSTed is required")
)
{
  # In ADFS 3.0, management Cmdlets are moved into 'ADFS' module which gets auto-loaded. No more explicit snapin loading required.
  # [Fix]: Only attempt snapin loading if ADFS commands are not available
  if ( (Get-Command Set-ADFSRelyingPartyTrust -ErrorAction SilentlyContinue) -eq $null)
  {
    # check if SP snapin exists in the machine
    if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null )
    {
        Write-Error "This PowerShell script requires the Microsoft.Adfs.Powershell Snap-In. Try executing it from an ADFS server"
        return;
    }

    # check if SP snapin is already loaded, if not load it
    if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue) -eq $null )
    {
        Write-Verbose "Adding Microsoft.Adfs.Powershell Snapin"
        Add-PSSnapin Microsoft.Adfs.Powershell
    }

  # check if running as Admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) 
    {
      Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
      return;
    }
  }
  
  # remove if exists
  $rp = Get-ADFSRelyingPartyTrust -Name $realm
  if ($rp) 
  {
    Write-Verbose "Removing Relying Party Trust: $realm"
    Remove-ADFSRelyingPartyTrust -TargetName $realm
  }

  Write-Verbose "Adding Relying Party Trust: $realm"
  Write-Verbose "Add-ADFSRelyingPartyTrust -Name $realm -Identifier $realm -WSFedEndpoint $webAppEndpoint"
  Add-ADFSRelyingPartyTrust -Name $realm -Identifier $realm -WSFedEndpoint $webAppEndpoint

  # get the RP to add Transform and Authz rules.
  $rp = Get-ADFSRelyingPartyTrust -Name $realm

  # transform Rules
  $rules = @'
  @RuleName = "Store: ActiveDirectory -> Mail (ldap attribute: mail), Name (ldap attribute: userPrincipalName), GivenName (ldap attribute: givenName), Surname (ldap attribute: sn)" 
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
   => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 
   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", 
   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", 
   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", 
   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), query = ";mail,displayName,userPrincipalName,givenName,sn;{0}", param = c.Value);
'@
  
  Write-Verbose "Adding Claim Rules"
  Set-ADFSRelyingPartyTrust –TargetName $realm -IssuanceTransformRules $rules

  # Authorization Rules
  $authRules = '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
  Write-Verbose "Adding Issuance Authorization Rules: $authRules"
  $rSet = New-ADFSClaimRuleSet –ClaimRule $authRules
  Set-ADFSRelyingPartyTrust –TargetName $realm –IssuanceAuthorizationRules $rSet.ClaimRulesString

  Remove-PSSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue

  Write-Host "Relying Party Trust '$realm' added succesfully."

}


function RemoveRelyingParty
(
[string]$realm = $(throw "Realm for the application is required. E.g.: http://whatever.com or urn:whatever")
)
{

  if ( (Get-Command Set-ADFSRelyingPartyTrust -ErrorAction SilentlyContinue) -eq $null)
  {
    # check if ADFS snapin exists in the machine
    if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null )
    {
        Write-Error "This PowerShell script requires the Microsoft.Adfs.Powershell Snap-In. Try executing it from an ADFS server"
        return;
    }

    # check if ADFSP snapin is already loaded, if not load it
    if ( (Get-PSSnapin -Name Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue) -eq $null )
    {
        Write-Verbose "Adding Microsoft.Adfs.Powershell Snapin"
        Add-PSSnapin Microsoft.Adfs.Powershell
    }

    # check if running as Admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) 
    {
        Write-Error "This PowerShell script requires Administrator privilieges. Try executing by doing right click -> 'Run as Administrator'"
        return;
    }
  }

  # remove if exists
  $rp = Get-ADFSRelyingPartyTrust -Name $realm
  if ($rp) 
  {
    Write-Verbose "Removing Relying Party Trust: $realm"
    Remove-ADFSRelyingPartyTrust -TargetName $realm
    Write-Host "Relying Party Trust '$realm' removed succesfully."
  }

  Remove-PSSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue

}
