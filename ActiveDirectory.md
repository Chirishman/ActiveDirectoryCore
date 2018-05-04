
# ActiveDirectory Module
-----


```PowerShell
Import-Module PSCoreWindowsCompat,WindowsPSModulePath; Add-WindowsPSModulePath

Get-Module ActiveDirectory -ListAvailable | select ModuleType,Version,Name,@{N='ExportedCommands';e={$_.ExportedCommands.keys | fl | out-string}} | tee -Variable Commands | fl
```




    ModuleType       : Manifest
    Version          : 1.0.0.0
    Name             : ActiveDirectory
    ExportedCommands : Add-ADCentralAccessPolicyMember
                       Add-ADComputerServiceAccount
                       Add-ADDomainControllerPasswordReplicationPolicy
                       Add-ADFineGrainedPasswordPolicySubject
                       Add-ADGroupMember
                       Add-ADPrincipalGroupMembership
                       Add-ADResourcePropertyListMember
                       Clear-ADAccountExpiration
                       Clear-ADClaimTransformLink
                       Disable-ADAccount
                       Disable-ADOptionalFeature
                       Enable-ADAccount
                       Enable-ADOptionalFeature
                       Get-ADAccountAuthorizationGroup
                       Get-ADAccountResultantPasswordReplicationPolicy
                       Get-ADAuthenticationPolicy
                       Get-ADAuthenticationPolicySilo
                       Get-ADCentralAccessPolicy
                       Get-ADCentralAccessRule
                       Get-ADClaimTransformPolicy
                       Get-ADClaimType
                       Get-ADComputer
                       Get-ADComputerServiceAccount
                       Get-ADDCCloningExcludedApplicationList
                       Get-ADDefaultDomainPasswordPolicy
                       Get-ADDomain
                       Get-ADDomainController
                       Get-ADDomainControllerPasswordReplicationPolicy
                       Get-ADDomainControllerPasswordReplicationPolicyUsage
                       Get-ADFineGrainedPasswordPolicy
                       Get-ADFineGrainedPasswordPolicySubject
                       Get-ADForest
                       Get-ADGroup
                       Get-ADGroupMember
                       Get-ADObject
                       Get-ADOptionalFeature
                       Get-ADOrganizationalUnit
                       Get-ADPrincipalGroupMembership
                       Get-ADReplicationAttributeMetadata
                       Get-ADReplicationConnection
                       Get-ADReplicationFailure
                       Get-ADReplicationPartnerMetadata
                       Get-ADReplicationQueueOperation
                       Get-ADReplicationSite
                       Get-ADReplicationSiteLink
                       Get-ADReplicationSiteLinkBridge
                       Get-ADReplicationSubnet
                       Get-ADReplicationUpToDatenessVectorTable
                       Get-ADResourceProperty
                       Get-ADResourcePropertyList
                       Get-ADResourcePropertyValueType
                       Get-ADRootDSE
                       Get-ADServiceAccount
                       Get-ADTrust
                       Get-ADUser
                       Get-ADUserResultantPasswordPolicy
                       Grant-ADAuthenticationPolicySiloAccess
                       Install-ADServiceAccount
                       Move-ADDirectoryServer
                       Move-ADDirectoryServerOperationMasterRole
                       Move-ADObject
                       New-ADAuthenticationPolicy
                       New-ADAuthenticationPolicySilo
                       New-ADCentralAccessPolicy
                       New-ADCentralAccessRule
                       New-ADClaimTransformPolicy
                       New-ADClaimType
                       New-ADComputer
                       New-ADDCCloneConfigFile
                       New-ADFineGrainedPasswordPolicy
                       New-ADGroup
                       New-ADObject
                       New-ADOrganizationalUnit
                       New-ADReplicationSite
                       New-ADReplicationSiteLink
                       New-ADReplicationSiteLinkBridge
                       New-ADReplicationSubnet
                       New-ADResourceProperty
                       New-ADResourcePropertyList
                       New-ADServiceAccount
                       New-ADUser
                       Remove-ADAuthenticationPolicy
                       Remove-ADAuthenticationPolicySilo
                       Remove-ADCentralAccessPolicy
                       Remove-ADCentralAccessPolicyMember
                       Remove-ADCentralAccessRule
                       Remove-ADClaimTransformPolicy
                       Remove-ADClaimType
                       Remove-ADComputer
                       Remove-ADComputerServiceAccount
                       Remove-ADDomainControllerPasswordReplicationPolicy
                       Remove-ADFineGrainedPasswordPolicy
                       Remove-ADFineGrainedPasswordPolicySubject
                       Remove-ADGroup
                       Remove-ADGroupMember
                       Remove-ADObject
                       Remove-ADOrganizationalUnit
                       Remove-ADPrincipalGroupMembership
                       Remove-ADReplicationSite
                       Remove-ADReplicationSiteLink
                       Remove-ADReplicationSiteLinkBridge
                       Remove-ADReplicationSubnet
                       Remove-ADResourceProperty
                       Remove-ADResourcePropertyList
                       Remove-ADResourcePropertyListMember
                       Remove-ADServiceAccount
                       Remove-ADUser
                       Rename-ADObject
                       Revoke-ADAuthenticationPolicySiloAccess
                       Reset-ADServiceAccountPassword
                       Restore-ADObject
                       Search-ADAccount
                       Set-ADAccountAuthenticationPolicySilo
                       Set-ADAccountControl
                       Set-ADAccountExpiration
                       Set-ADAccountPassword
                       Set-ADAuthenticationPolicy
                       Set-ADAuthenticationPolicySilo
                       Set-ADCentralAccessPolicy
                       Set-ADCentralAccessRule
                       Set-ADClaimTransformLink
                       Set-ADClaimTransformPolicy
                       Set-ADClaimType
                       Set-ADComputer
                       Set-ADDefaultDomainPasswordPolicy
                       Set-ADDomain
                       Set-ADDomainMode
                       Set-ADFineGrainedPasswordPolicy
                       Set-ADForest
                       Set-ADForestMode
                       Set-ADGroup
                       Set-ADObject
                       Set-ADOrganizationalUnit
                       Set-ADReplicationConnection
                       Set-ADReplicationSite
                       Set-ADReplicationSiteLink
                       Set-ADReplicationSiteLinkBridge
                       Set-ADReplicationSubnet
                       Set-ADResourceProperty
                       Set-ADResourcePropertyList
                       Set-ADServiceAccount
                       Set-ADUser
                       Show-ADAuthenticationPolicyExpression
                       Sync-ADObject
                       Test-ADServiceAccount
                       Uninstall-ADServiceAccount
                       Unlock-ADAccount



## Commands
-----


```PowerShell
$Commands.ExportedCommands.Split("`r`n") | ?{$_} | %{
    powershell -NonInteractive -NoProfile -Command "Get-Help $_"
}
```




    NAME
        Add-ADCentralAccessPolicyMember
        
    SYNOPSIS
        Adds central access rules to a central access policy in Active Directory.
        
        
    SYNTAX
        Add-ADCentralAccessPolicyMember [-Identity] <ADCentralAccessPolicy> [-Members] <ADCentralAccessRule[]> [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADCentralAccessPolicyMember cmdlet adds central access rules to a central access policy in Active 
        Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291002
    
    REMARKS
        To see the examples, type: "get-help Add-ADCentralAccessPolicyMember -examples".
        For more information, type: "get-help Add-ADCentralAccessPolicyMember -detailed".
        For technical information, type: "get-help Add-ADCentralAccessPolicyMember -full".
        For online help, type: "get-help Add-ADCentralAccessPolicyMember -online"
    
    
    
    NAME
        Add-ADComputerServiceAccount
        
    SYNOPSIS
        Adds one or more service accounts to an Active Directory computer.
        
        
    SYNTAX
        Add-ADComputerServiceAccount [-Identity] <ADComputer> [-ServiceAccount] <ADServiceAccount[]> [-AuthType {Negotiate 
        | Basic}] [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADComputerServiceAccount cmdlet adds one or more computer service accounts to an Active Directory computer.
        
        The Computer parameter specifies the Active Directory computer that will host the new service accounts. You can 
        identify a computer by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager 
        (SAM) account name. You can also set the Computer parameter to a computer object variable, such as 
        $<localComputerobject>, or pass a computer object through the pipeline to the Computer parameter. For example, you 
        can use the Get-ADComputer cmdlet to retrieve a computer object and then pass the object through the pipeline to 
        the Add-ADComputerServiceAccount cmdlet.
        
        The ServiceAccount parameter specifies the service accounts to add. You can identify a service account by its 
        distinguished name (DN), GUID, Security Identifier (SID) or Security Accounts Manager (SAM) account name. You can 
        also specify service account object variables, such as $<localServiceAccountObject>. If you are specifying more 
        than one account, use a comma-separated list.
        
        Note: Adding a service account is a different operation than installing the service account locally.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291003
        Get-ADComputer 
        Get-ADComputerServiceAccount 
        Remove-ADComputerServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Add-ADComputerServiceAccount -examples".
        For more information, type: "get-help Add-ADComputerServiceAccount -detailed".
        For technical information, type: "get-help Add-ADComputerServiceAccount -full".
        For online help, type: "get-help Add-ADComputerServiceAccount -online"
    
    
    
    NAME
        Add-ADDomainControllerPasswordReplicationPolicy
        
    SYNOPSIS
        Adds users, computers, and groups to the allowed or denied list of a read-only domain controller password 
        replication policy.
        
        
    SYNTAX
        Add-ADDomainControllerPasswordReplicationPolicy [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADDomainControllerPasswordReplicationPolicy cmdlet adds one or more users, computers, and groups to the 
        allowed or denied list of a read-only domain controller (RODC) password replication policy.
        
        The Identity parameter specifies the RODC that uses the allowed and denied lists to apply the password replication 
        policy. You can identify a domain controller by its GUID, IPV4Address, global IPV6Address, or DNS host name. You 
        can also identify a domain controller by the name of the server object that represents the domain controller, the 
        Distinguished Name (DN) of the NTDS settings object of the server object, the GUID of the NTDS settings object of 
        the server object under the configuration partition, or the DN of the computer object that represents the domain 
        controller. You can also set the Identity parameter to a domain controller object variable, such as 
        $<localDomainControllerobject>, or pass a domain controller object through the pipeline to the Identity parameter. 
        For example, you can use the Get-ADDomainController cmdlet to get a domain controller object and then pass the 
        object through the pipeline to the Add-ADDomainControllerPasswordReplicationPolicy cmdlet. You must specify a 
        read-only domain controller. If you specify a writeable domain controller for this parameter, the cmdlet returns a 
        non-terminating error.
        
        The AllowedList parameter specifies the users, computers, and groups to add to the allowed list. Similarly, the 
        DeniedList parameter specifies the users, computers, and groups to add to the denied list. You must specify either 
        one or both of the AllowedList and DeniedList parameters. You can identify a user, computer, or group by 
        distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can 
        also specify user, computer, or group variables, such as $<localUserObject>. If you are specifying more than one 
        item, use a comma-separated list. If a specified user, computer, or group is not on the allowed or denied list, 
        the cmdlet does not return an error.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291004
        Get-ADDomainController 
        Get-ADDomainControllerPasswordReplicationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Add-ADDomainControllerPasswordReplicationPolicy -examples".
        For more information, type: "get-help Add-ADDomainControllerPasswordReplicationPolicy -detailed".
        For technical information, type: "get-help Add-ADDomainControllerPasswordReplicationPolicy -full".
        For online help, type: "get-help Add-ADDomainControllerPasswordReplicationPolicy -online"
    
    
    
    NAME
        Add-ADFineGrainedPasswordPolicySubject
        
    SYNOPSIS
        Applies a fine-grained password policy to one more users and groups.
        
        
    SYNTAX
        Add-ADFineGrainedPasswordPolicySubject [-Identity] <ADFineGrainedPasswordPolicy> [-Subjects] <ADPrincipal[]> 
        [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADFineGrainedPasswordPolicySubject cmdlet applies a fine-grained password policy to one or more global 
        security groups and users.
        
        The Identity parameter specifies the fine-grained password policy to apply. You can identify a fine-grained 
        password policy by its distinguished name, GUID or name. You can also set the Identity parameter to a fine-grained 
        password policy object variable, such as $<localPasswordPolicyObject>, or pass a fine-grained password policy 
        object through the pipeline to the Identity parameter. For example, you can use the 
        Get-ADFineGrainedPasswordPolicy cmdlet to get a fine-grained password policy object and then pass the object 
        through the pipeline to the Add-ADFineGrainedPasswordPolicySubject cmdlet.
        
        The Subjects parameter specifies the users and global security groups. You can identify a user or global security 
        group by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account 
        name. You can also specify user and global security group object variables, such as $<localUserObject>. If you are 
        specifying more than one user or group, use a comma-separated list. To pass user and global security group objects 
        through the pipeline to the Subjects parameter, use the Get-ADUser or the Get-ADGroup cmdlets to retrieve the user 
        or group objects, and then pass these objects through the pipeline to the Add-ADFineGrainedPasswordPolicySubject 
        cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291005
        Get-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Add-ADFineGrainedPasswordPolicySubject -examples".
        For more information, type: "get-help Add-ADFineGrainedPasswordPolicySubject -detailed".
        For technical information, type: "get-help Add-ADFineGrainedPasswordPolicySubject -full".
        For online help, type: "get-help Add-ADFineGrainedPasswordPolicySubject -online"
    
    
    
    NAME
        Add-ADGroupMember
        
    SYNOPSIS
        Adds one or more members to an Active Directory group.
        
        
    SYNTAX
        Add-ADGroupMember [-Identity] <ADGroup> [-Members] <ADPrincipal[]> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADGroupMember cmdlet adds one or more users, groups, service accounts, or computers as new members of an 
        Active Directory group.
        
        The Identity parameter specifies the Active Directory group that receives the new members. You can identify a 
        group by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account 
        name. You can also specify group object variable, such as $<localGroupObject>, or pass a group object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADGroup cmdlet to get a group object and then 
        pass the object through the pipeline to the Add-ADGroupMember cmdlet.
        
        The Members parameter specifies the new members to add to a group. You can identify a new member by its 
        distinguished name (DN), GUID, security identifier (SID) or SAM account name. You can also specify user, computer, 
        and group object variables, such as $<localUserObject>. If you are specifying more than one new member, use a 
        comma-separated list. You cannot pass user, computer, or group objects through the pipeline to this cmdlet. To add 
        user, computer, or group objects to a group by using the pipeline, use the Add-ADPrincipalGroupMembership cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291006
        Add-ADPrincipalGroupMembership 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADPrincipalGroupMembership 
        Remove-ADGroupMember 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Add-ADGroupMember -examples".
        For more information, type: "get-help Add-ADGroupMember -detailed".
        For technical information, type: "get-help Add-ADGroupMember -full".
        For online help, type: "get-help Add-ADGroupMember -online"
    
    
    
    NAME
        Add-ADPrincipalGroupMembership
        
    SYNOPSIS
        Adds a member to one or more Active Directory groups.
        
        
    SYNTAX
        Add-ADPrincipalGroupMembership [-Identity] <ADPrincipal> [-MemberOf] <ADGroup[]> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADPrincipalGroupMembership cmdlet adds a user, group, service account, or computer as a new member to one 
        or more Active Directory groups.
        
        The Identity parameter specifies the new user, computer, or group to add. You can identify the user, group, or 
        computer by its distinguished name (DN), GUID, security identifier (SID), or SAM account name. You can also 
        specify a user, group, or computer object variable, such as $<localGroupObject>, or pass an object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADGroup cmdlet to get a group object and then 
        pass the object through the pipeline to the Add-ADPrincipalGroupMembership cmdlet. Similarly, you can use 
        Get-ADUser or Get-ADComputer to get user and computer objects to pass through the pipeline.
        
        This cmdlet collects all of the user, computer and group objects from the pipeline, and then adds these objects to 
        the specified group by using one Active Directory operation.
        
        The MemberOf parameter specifies the groups that receive the new member. You can identify a group by its 
        distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can 
        also specify group object variable, such as $<localGroupObject>. To specify more than one group, use a 
        comma-separated list. You cannot pass group objects through the pipeline to the MemberOf parameter. To add to a 
        group by passing the group through the pipeline, use the Add-ADGroupMember cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291007
        Add-ADGroupMember 
        Get-ADComputer 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADPrincipalGroupMembership 
        Get-ADUser 
        Remove-ADGroupMember 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Add-ADPrincipalGroupMembership -examples".
        For more information, type: "get-help Add-ADPrincipalGroupMembership -detailed".
        For technical information, type: "get-help Add-ADPrincipalGroupMembership -full".
        For online help, type: "get-help Add-ADPrincipalGroupMembership -online"
    
    
    
    NAME
        Add-ADResourcePropertyListMember
        
    SYNOPSIS
        Adds one or more resource properties to a resource property list in Active Directory.
        
        
    SYNTAX
        Add-ADResourcePropertyListMember [-Identity] <ADResourcePropertyList> [-Members] <ADResourceProperty[]> [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Add-ADResourcePropertyListMember adds one or more resource properties to a resource property list in Active 
        Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291008
    
    REMARKS
        To see the examples, type: "get-help Add-ADResourcePropertyListMember -examples".
        For more information, type: "get-help Add-ADResourcePropertyListMember -detailed".
        For technical information, type: "get-help Add-ADResourcePropertyListMember -full".
        For online help, type: "get-help Add-ADResourcePropertyListMember -online"
    
    
    
    NAME
        Clear-ADAccountExpiration
        
    SYNOPSIS
        Clears the expiration date for an Active Directory account.
        
        
    SYNTAX
        Clear-ADAccountExpiration [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Clear-ADAccountExpiration cmdlet clears the expiration date for an Active Directory user or computer account. 
        When you clear the expiration date for an account, the account does not expire.
        
        The Identity parameter specifies the user or computer account to modify. You can identify a user or group by its 
        distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can 
        also set the Identity parameter to a user or computer object variable, such as $<localUserObject>, or pass a user 
        or computer object through the pipeline to the Identity parameter. For example, you can use the Get-ADUser, 
        Get-ADComputer or Search-ADAccount cmdlet to retrieve an object and then pass the object through the pipeline to 
        the Clear-ADAccountExpiration cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291009
        Search-ADAccount 
        Set-ADAccountExpiration 
        Get-ADUser Get-ADComputer 
    
    REMARKS
        To see the examples, type: "get-help Clear-ADAccountExpiration -examples".
        For more information, type: "get-help Clear-ADAccountExpiration -detailed".
        For technical information, type: "get-help Clear-ADAccountExpiration -full".
        For online help, type: "get-help Clear-ADAccountExpiration -online"
    
    
    
    NAME
        Clear-ADClaimTransformLink
        
    SYNOPSIS
        Removes a claims transformation from being applied to one or more cross-forest trust relationships in Active 
        Directory.
        
        
    SYNTAX
        Clear-ADClaimTransformLink [-Identity] <ADTrust> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-PassThru] [-Policy <ADClaimTransformPolicy>] [-Server <String>] [-TrustRole {Trusted | Trusting}] [-Confirm] 
        [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Clear-ADClaimTransformLink cmdlet removes a claims transformation from being applied to one or more 
        cross-forest trust relationships in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291010
    
    REMARKS
        To see the examples, type: "get-help Clear-ADClaimTransformLink -examples".
        For more information, type: "get-help Clear-ADClaimTransformLink -detailed".
        For technical information, type: "get-help Clear-ADClaimTransformLink -full".
        For online help, type: "get-help Clear-ADClaimTransformLink -online"
    
    
    
    NAME
        Disable-ADAccount
        
    SYNOPSIS
        Disables an Active Directory account.
        
        
    SYNTAX
        Disable-ADAccount [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Disable-ADAccount cmdlet disables an Active Directory user, computer, or service account.
        
        The Identity parameter specifies the Active Directory user, computer service account, or other service account 
        that you want to disable. You can identify an account by its distinguished name (DN), GUID, security identifier 
        (SID), or Security Accounts Manager (SAM) account name. You can also set the Identity parameter to an object 
        variable such as $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity 
        parameter. For example, you can use the Get-ADUser cmdlet to retrieve a user account object and then pass the 
        object through the pipeline to the Disable-Account cmdlet. Similarly, you can use Get-ADComputer and 
        Search-ADAccount to retrieve account objects.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291011
        Clear-ADAccountExpiration 
        Enable-ADAccount 
        Get-ADAccountAuthorizationGroup 
        Search-ADAccount 
        Set-ADAccountControl 
        Set-ADAccountExpiration 
        Set-ADAccountPassword 
        Unlock-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Disable-ADAccount -examples".
        For more information, type: "get-help Disable-ADAccount -detailed".
        For technical information, type: "get-help Disable-ADAccount -full".
        For online help, type: "get-help Disable-ADAccount -online"
    
    
    
    NAME
        Disable-ADOptionalFeature
        
    SYNOPSIS
        Disables an Active Directory optional feature.
        
        
    SYNTAX
        Disable-ADOptionalFeature [-Identity] <ADOptionalFeature> [-Scope] {Unknown | ForestOrConfigurationSet | Domain} 
        [-Target] <ADEntity> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Disable-ADOptionalFeature disables an Active Directory optional feature that is associated with a particular 
        Domain Mode or Forest Mode.
        
        The Identity parameter specifies the Active Directory optional feature that you want to disable. You can identify 
        an optional feature by its distinguished name (DN), feature GUID, or object GUID. You can also set the parameter 
        to an optional feature object variable, such as $<localOptionalFeatureObject> or you can pass an optional feature 
        object through the pipeline to the Identity parameter. For example, you can use the Get-ADOptionalFeature cmdlet 
        to retrieve an optional feature object and then pass the object through the pipeline to the 
        Disable-ADOptionalFeature cmdlet.
        
        The Scope parameter specifies the scope at which the optional feature is disabled. Possible values for this 
        parameter are Domain and Forest.
        
        The Target parameter specifies the domain or forest on which the optional feature is disabled. You can identify 
        the domain or forest by its fully-qualified domain name (FQDN), NetBIOS name, or the distinguished name (DN) of 
        the domain naming context (domain NC).
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291012
        Enable-ADOptionalFeature 
        Get-ADOptionalFeature 
    
    REMARKS
        To see the examples, type: "get-help Disable-ADOptionalFeature -examples".
        For more information, type: "get-help Disable-ADOptionalFeature -detailed".
        For technical information, type: "get-help Disable-ADOptionalFeature -full".
        For online help, type: "get-help Disable-ADOptionalFeature -online"
    
    
    
    NAME
        Enable-ADAccount
        
    SYNOPSIS
        Enables an Active Directory account.
        
        
    SYNTAX
        Enable-ADAccount [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Enable-ADAccount cmdlet enables an Active Directory user, computer or service account.
        
        The Identity parameter specifies the Active Directory user, computer or service account that you want to enable. 
        You can identify an account by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts 
        Manager (SAM) account name. You can also set the Identity parameter to an object variable such as 
        $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity parameter. For 
        example, you can use the Get-ADUser cmdlet to retrieve an account object and then pass the object through the 
        pipeline to the Enable-ADAccount cmdlet. Similarly, you can use Get-ADComputer and Search-ADAccount to retrieve 
        account objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291013
        Clear-ADAccountExpiration 
        Disable-ADAccount 
        Get-ADAccountAuthorizationGroup 
        Search-ADAccount 
        Set-ADAccountControl 
        Set-ADAccountExpiration 
        Set-ADAccountPassword 
        Unlock-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Enable-ADAccount -examples".
        For more information, type: "get-help Enable-ADAccount -detailed".
        For technical information, type: "get-help Enable-ADAccount -full".
        For online help, type: "get-help Enable-ADAccount -online"
    
    
    
    NAME
        Enable-ADOptionalFeature
        
    SYNOPSIS
        Enables an Active Directory optional feature.
        
        
    SYNTAX
        Enable-ADOptionalFeature [-Identity] <ADOptionalFeature> [-Scope] {Unknown | ForestOrConfigurationSet | Domain} 
        [-Target] <ADEntity> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Enable-ADOptionalFeature enables an Active Directory optional feature that is associated with a particular 
        Domain mode or Forest mode. Active Directory optional features that depend on a specified domain mode or Forest 
        mode must be explicitly enabled after the domain mode or forest mode is set.
        
        The Identity parameter specifies the Active Directory optional feature that you want to enable. You can identify 
        an optional feature by its distinguished name (DN), feature GUID, or object GUID. You can also set the parameter 
        to an optional feature object variable, such as $<localOptionalFeatureObject> or you can pass an optional feature 
        object through the pipeline to the Identity parameter. For example, you can use the Get-ADOptionalFeature cmdlet 
        to retrieve an optional feature object and then pass the object through the pipeline to the 
        Enable-ADOptionalFeature cmdlet.
        
        The Scope parameter specifies the scope at which the optional feature will be enabled. Possible values for this 
        parameter are Domain and Forest.
        
        The Target parameter specifies the domain or forest on which the optional feature will be enabled. You can 
        identify the domain or forest by its fully-qualified domain name (FQDN), NetBIOS name, or distinguished name (DN) 
        of the domain naming context (domain NC).
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291014
        Disable-ADOptionalFeature 
        Get-ADOptionalFeature 
    
    REMARKS
        To see the examples, type: "get-help Enable-ADOptionalFeature -examples".
        For more information, type: "get-help Enable-ADOptionalFeature -detailed".
        For technical information, type: "get-help Enable-ADOptionalFeature -full".
        For online help, type: "get-help Enable-ADOptionalFeature -online"
    
    
    
    NAME
        Get-ADAccountAuthorizationGroup
        
    SYNOPSIS
        Gets the accounts token group information.
        
        
    SYNTAX
        Get-ADAccountAuthorizationGroup [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADAuthorizationGroup cmdlet gets the security groups from the specified user, computer or service accounts 
        token. This cmdlet requires a global catalog to perform the group search. If the forest that contains the account 
        does not have a global catalog, the cmdlet returns a non-terminating error.
        
        The Identity parameter specifies the user, computer, or service account. You can identify a user, computer, or 
        service account object by its distinguished name (DN), GUID, security identifier (SID), Security Account Manager 
        (SAM) account name or user principal name. You can also set the Identity parameter to an account object variable, 
        such as $<localAccountobject>, or pass an account object through the pipeline to the Identity parameter. For 
        example, you can use the Get-ADUser, Get-ADComputer, Get-ADServiceAccount or Search-ADAccount cmdlets to retrieve 
        an account object and then pass the object through the pipeline to the Get-ADAccountAuthorizationGroup cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291015
        Get-ADComputer 
        Get-ADServiceAccount 
        Get-ADUser 
        Search-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Get-ADAccountAuthorizationGroup -examples".
        For more information, type: "get-help Get-ADAccountAuthorizationGroup -detailed".
        For technical information, type: "get-help Get-ADAccountAuthorizationGroup -full".
        For online help, type: "get-help Get-ADAccountAuthorizationGroup -online"
    
    
    
    NAME
        Get-ADAccountResultantPasswordReplicationPolicy
        
    SYNOPSIS
        Gets the resultant password replication policy for an Active Directory account.
        
        
    SYNTAX
        Get-ADAccountResultantPasswordReplicationPolicy [-Identity] <ADAccount> [-DomainController] <ADDomainController> 
        [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition <String>] [-Server <String>] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADAccountResultantPasswordReplicationPolicy gets the resultant password replication policy for a user, 
        computer or service account on the specified read-only domain controller.
        
        The policy will be one of the following values:
        
        Allow or 1
        
        DenyExplicit or 0
        
        DenyImplicit or 2
        
        Unknown or -1
        
        The Identity parameter specifies the account. You can identify a user, computer, or service account object by its 
        distinguished name (DN), GUID, security identifier (SID) or Security Account Manager (SAM) account name. You can 
        also set the Identity parameter to an account object variable, such as $<localAccountobject>, or pass an account 
        object through the pipeline to the Identity parameter. For example, you can use the Get-ADUser, Get-ADComputer, 
        Get-ADServiceAccount or Search-ADAccount cmdlets to retrieve an account object and then pass the object through 
        the pipeline to the Get-ADAccountResultantPasswordReplicationPolicy cmdlet.
        
        The DomainController parameter specifies the read-only domain controller. You can identify a domain controller by 
        its IPV4Address, global IPV6Address, or DNS host name. You can also identify a domain controller by the 
        Distinguished Name (DN) of the NTDS settings object or the server object, the GUID of the NTDS settings object or 
        the server object under the configuration partition, or the DN, SamAccountName, GUID, SID of the computer object 
        that represents the domain controller. You can also set the DomainController parameter to a domain controller 
        object variable, such as $<localDomainControllerObject>.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291016
        Get-ADComputer 
        Get-ADServiceAccount 
        Get-ADUser 
        Search-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Get-ADAccountResultantPasswordReplicationPolicy -examples".
        For more information, type: "get-help Get-ADAccountResultantPasswordReplicationPolicy -detailed".
        For technical information, type: "get-help Get-ADAccountResultantPasswordReplicationPolicy -full".
        For online help, type: "get-help Get-ADAccountResultantPasswordReplicationPolicy -online"
    
    
    
    NAME
        Get-ADAuthenticationPolicy
        
    SYNOPSIS
        Gets one or more Active Directory Domain Services authentication policies.
        
        
    SYNTAX
        Get-ADAuthenticationPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADAuthenticationPolicy [-Identity] <ADAuthenticationPolicy> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADAuthenticationPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADAuthenticationPolicy cmdlet gets an authentication policy or performs a search to get authentication 
        policies.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy to get. You can 
        identify an authentication policy by its distinguished name (DN), GUID or name. You can also use the Identity 
        parameter to specify a variable that contains an authentication policy object, or you can use the pipeline 
        operator to pass an authentication policy object to the Identity parameter.
        
        You can search for and use multiple authentication policies by specifying the Filter parameter or the LDAPFilter 
        parameter. The Filter parameter uses the Windows PowerShellr expression language to write query strings for Active 
        Directory Domain Services. Windows PowerShell expression language syntax provides rich type conversion support for 
        value types received by the Filter parameter. For more information about the Filter parameter syntax, see 
        about_ActiveDirectory_Filter. If you have existing LDAP query strings, you can use the LDAPFilter parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=288129
        New-ADAuthenticationPolicy 
        Remove-ADAuthenticationPolicy 
        Set-ADAuthenticationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Get-ADAuthenticationPolicy -examples".
        For more information, type: "get-help Get-ADAuthenticationPolicy -detailed".
        For technical information, type: "get-help Get-ADAuthenticationPolicy -full".
        For online help, type: "get-help Get-ADAuthenticationPolicy -online"
    
    
    
    NAME
        Get-ADAuthenticationPolicySilo
        
    SYNOPSIS
        Gets one or more Active Directory Domain Services authentication policy silos.
        
        
    SYNTAX
        Get-ADAuthenticationPolicySilo [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> 
        [<CommonParameters>]
        
        Get-ADAuthenticationPolicySilo [-Identity] <ADAuthenticationPolicySilo> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADAuthenticationPolicySilo [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADAuthenticationPolicySilo cmdlet gets an authentication policy silo or performs a search to get 
        authentication policy silos.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy silo to get. You can 
        identify an authentication policy silo by its distinguished name (DN), GUID or name. You can also use the Identity 
        parameter to specify a variable that contains an authentication policy silo object, or you can use the pipeline 
        operator to pass an authentication policy silo object to the Identity parameter.
        
        You can search for and use multiple authentication policies by specifying the Filter parameter or the LDAPFilter 
        parameter. The Filter parameter uses the Windows PowerShellr expression language to write query strings for Active 
        Directory Domain Services. Windows PowerShell expression language syntax provides rich type conversion support for 
        value types received by the Filter parameter. For more information about the Filter parameter syntax, see 
        about_ActiveDirectory_Filter. If you have existing LDAP query strings, you can use the LDAPFilter parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=288159
        New-ADAuthenticationPolicySilo 
        Remove-ADAuthenticationPolicySilo 
        Set-ADAuthenticationPolicySilo 
    
    REMARKS
        To see the examples, type: "get-help Get-ADAuthenticationPolicySilo -examples".
        For more information, type: "get-help Get-ADAuthenticationPolicySilo -detailed".
        For technical information, type: "get-help Get-ADAuthenticationPolicySilo -full".
        For online help, type: "get-help Get-ADAuthenticationPolicySilo -online"
    
    
    
    NAME
        Get-ADCentralAccessPolicy
        
    SYNOPSIS
        Retrieves central access policies from Active Directory.
        
        
    SYNTAX
        Get-ADCentralAccessPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADCentralAccessPolicy [-Identity] <ADCentralAccessPolicy> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADCentralAccessPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADCentralAccessPolicy cmdlet retrieves central access policies from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291017
    
    REMARKS
        To see the examples, type: "get-help Get-ADCentralAccessPolicy -examples".
        For more information, type: "get-help Get-ADCentralAccessPolicy -detailed".
        For technical information, type: "get-help Get-ADCentralAccessPolicy -full".
        For online help, type: "get-help Get-ADCentralAccessPolicy -online"
    
    
    
    NAME
        Get-ADCentralAccessRule
        
    SYNOPSIS
        Retrieves central access rules from Active Directory.
        
        
    SYNTAX
        Get-ADCentralAccessRule [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADCentralAccessRule [-Identity] <ADCentralAccessRule> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADCentralAccessRule [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADCentralAccessRule cmdlet retrieves central access rules from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291018
    
    REMARKS
        To see the examples, type: "get-help Get-ADCentralAccessRule -examples".
        For more information, type: "get-help Get-ADCentralAccessRule -detailed".
        For technical information, type: "get-help Get-ADCentralAccessRule -full".
        For online help, type: "get-help Get-ADCentralAccessRule -online"
    
    
    
    NAME
        Get-ADClaimTransformPolicy
        
    SYNOPSIS
        Returns one or more Active Directory claim transform objects based on a specified filter.
        
        
    SYNTAX
        Get-ADClaimTransformPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADClaimTransformPolicy [[-Identity] <ADClaimTransformPolicy>] [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADClaimTransformPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADClaimTransformPolicy cmdlet returns one or more Active Directory claim transform objects based on a 
        specified filter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291019
    
    REMARKS
        To see the examples, type: "get-help Get-ADClaimTransformPolicy -examples".
        For more information, type: "get-help Get-ADClaimTransformPolicy -detailed".
        For technical information, type: "get-help Get-ADClaimTransformPolicy -full".
        For online help, type: "get-help Get-ADClaimTransformPolicy -online"
    
    
    
    NAME
        Get-ADClaimType
        
    SYNOPSIS
        Returns a claim type from Active Directory.
        
        
    SYNTAX
        Get-ADClaimType [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADClaimType [-Identity] <ADClaimType> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADClaimType [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADClaimType cmdlet returns a claim type defined in Active Drectory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291020
    
    REMARKS
        To see the examples, type: "get-help Get-ADClaimType -examples".
        For more information, type: "get-help Get-ADClaimType -detailed".
        For technical information, type: "get-help Get-ADClaimType -full".
        For online help, type: "get-help Get-ADClaimType -online"
    
    
    
    NAME
        Get-ADComputer
        
    SYNOPSIS
        Gets one or more Active Directory computers.
        
        
    SYNTAX
        Get-ADComputer [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADComputer [-Identity] <ADComputer> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADComputer [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADComputer cmdlet gets a computer or performs a search to retrieve multiple computers.
        
        The Identity parameter specifies the Active Directory computer to retrieve. You can identify a computer by its 
        distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can 
        also set the parameter to a computer object variable, such as $<localComputerObject> or pass a computer object 
        through the pipeline to the Identity parameter.
        
        To search for and retrieve more than one computer, use the Filter or LDAPFilter parameters. The Filter parameter 
        uses the PowerShell Expression Language to write query strings for Active Directory. PowerShell Expression 
        Language syntax provides rich type conversion support for value types received by the Filter parameter. For more 
        information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing LDAP query 
        strings, you can use the LDAPFilter parameter.
        
        This cmdlet retrieves a default set of computer object properties. To retrieve additional properties use the 
        Properties parameter. For more information about the how to determine the properties for computer objects, see the 
        Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291021
        Add-ADComputerServiceAccount 
        Get-ADComputerServiceAccount 
        New-ADComputer 
        Remove-ADComputer 
        Remove-ADComputerServiceAccount 
        Set-ADComputer 
    
    REMARKS
        To see the examples, type: "get-help Get-ADComputer -examples".
        For more information, type: "get-help Get-ADComputer -detailed".
        For technical information, type: "get-help Get-ADComputer -full".
        For online help, type: "get-help Get-ADComputer -online"
    
    
    
    NAME
        Get-ADComputerServiceAccount
        
    SYNOPSIS
        Gets the service accounts hosted by a computer.
        
        
    SYNTAX
        Get-ADComputerServiceAccount [-Identity] <ADComputer> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Partition <String>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADComputerServiceAccount cmdlet gets all of the service accounts that are hosted by the specified computer.
        
        The Computer parameter specifies the Active Directory computer that hosts the service accounts. You can identify a 
        computer by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) 
        account name. You can also set the Computer parameter to a computer object variable, such as 
        $<localComputerobject>, or pass a computer object through the pipeline to the Computer parameter. For example, you 
        can use the Get-ADComputer cmdlet to retrieve a computer object and then pass the object through the pipeline to 
        the Get-ADComputerServiceAccount cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291022
        Add-ADComputerServiceAccount 
        Get-ADComputer 
        Remove-ADComputerServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Get-ADComputerServiceAccount -examples".
        For more information, type: "get-help Get-ADComputerServiceAccount -detailed".
        For technical information, type: "get-help Get-ADComputerServiceAccount -full".
        For online help, type: "get-help Get-ADComputerServiceAccount -online"
    
    
    
    NAME
        Get-ADDCCloningExcludedApplicationList
        
    SYNOPSIS
        Returns the list of installed programs and services present on this domain controller that are not in the default 
        or user defined inclusion list.
        
        
    SYNTAX
        Get-ADDCCloningExcludedApplicationList [-Force] [-Path <String>] -GenerateXml [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDCCloningExcludedApplicationList cmdlet searches the local domain controller for programs and services 
        in the installed programs database, the services control manager that are not specified in the default and user 
        defined inclusion list. The applications in the resulting list can be added to the user defined exclusion list if 
        they are determined to support cloning. If the applications are not cloneable, they should be removed from the 
        source domain controller before the clone media is created. Any application that appears in cmdlet output and is 
        not included in the user defined inclusion list will force cloning to fail.
        
        Once you have granted a source virtualized DC permissions to be cloned, the Get-ADDCCloningExcludedApplicationList 
        cmdlet should be run a first time with no additional parameters on the source virtualized domain controller to 
        identify all programs or services that are to be evaluated for cloning. Next, vet the returned list with your 
        software vendors and remove any applications from the list that cannot be safely cloned. Finally, you can run the 
        Get-ADDCCloningExcludedApplicationList cmdlet again using the -GenerateXml parameter set to create the 
        CustomDCCloneAllowList.xml file.
        
        The Get-ADDCCloningExcludedApplicationList cmdlet needs to be run before the New-ADDCCloneConfigFile cmdlet is 
        used because if the New-ADDCCloneConfigFile cmdlet detects an excluded application, it will not create a 
        DCCloneConfig.xml file. For more information on virtual domain controller cloning, see the guidance on ADDS 
        virtualization at http://go.microsoft.com/fwlink/?LinkId=208030.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291023
    
    REMARKS
        To see the examples, type: "get-help Get-ADDCCloningExcludedApplicationList -examples".
        For more information, type: "get-help Get-ADDCCloningExcludedApplicationList -detailed".
        For technical information, type: "get-help Get-ADDCCloningExcludedApplicationList -full".
        For online help, type: "get-help Get-ADDCCloningExcludedApplicationList -online"
    
    
    
    NAME
        Get-ADDefaultDomainPasswordPolicy
        
    SYNOPSIS
        Gets the default password policy for an Active Directory domain.
        
        
    SYNTAX
        Get-ADDefaultDomainPasswordPolicy [[-Current] {LocalComputer | LoggedOnUser}] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [<CommonParameters>]
        
        Get-ADDefaultDomainPasswordPolicy [-Identity] <ADDefaultDomainPasswordPolicy> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDefaultDomainPasswordPolicy cmdlet gets the default password policy for a domain.
        
        The Identity parameter specifies the Active Directory domain. You can identify a domain by its Distinguished Name 
        (DN), GUID, Security Identifier (SID), DNS domain name, or NETBIOS name. You can also set the parameter to a 
        domain object variable, such as $<localDomainObject> or pass a domain object through the pipeline to the Identity 
        parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291024
        Get-ADDomain 
    
    REMARKS
        To see the examples, type: "get-help Get-ADDefaultDomainPasswordPolicy -examples".
        For more information, type: "get-help Get-ADDefaultDomainPasswordPolicy -detailed".
        For technical information, type: "get-help Get-ADDefaultDomainPasswordPolicy -full".
        For online help, type: "get-help Get-ADDefaultDomainPasswordPolicy -online"
    
    
    
    NAME
        Get-ADDomain
        
    SYNOPSIS
        Gets an Active Directory domain.
        
        
    SYNTAX
        Get-ADDomain [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Current {LocalComputer | 
        LoggedOnUser}] [-Server <String>] [<CommonParameters>]
        
        Get-ADDomain [-Identity] <ADDomain> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Server 
        <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDomain cmdlet gets the Active Directory domain specified by the parameters. You can specify the domain 
        by setting the Identity or Current parameters.
        
        The Identity parameter specifies the Active Directory domain to get. You can identify the domain object to get by 
        its Distinguished Name (DN), GUID, Security Identifier (SID), DNS domain name, or NetBIOS name. You can also set 
        the parameter to a domain object variable, such as $<localDomainObject> or pass a domain object through the 
        pipeline to the Identity parameter.
        
        To get the domain of the local computer or current logged on user (CLU) set the Current parameter to LocalComputer 
        or LoggedOnUser.  When you set the Current parameter, you do not need to set the Identity parameter.
        
        When the Current parameter is set to LocalComputer or LogedOnUser, the cmdlet uses the Server and Credential 
        parameters according to the following rules.
        
        -If both the Server and Credential parameters are not specified:
        
        --The domain is set to the domain of the LocalComputer or LoggedOnUser and a server is located in this domain. The 
        credentials of the current logged on user are used to get the domain.
        
        -If the Server parameter is specified and the Credential parameter is not specified:
        
        --The domain is set to the domain of the specified server and the cmdlet checks to make sure that the server is in 
        the domain of the LocalComputer or LoggedOnUser. Then the credentials of the current logged on user are used to 
        get the domain. An error is returned when the server is not in the domain of the LocalComputer or LoggedOnUser.
        
        -If the Server parameter is not specified and the Credential parameter is specified:
        
        --The domain is set to the domain of the LocalComputer or LoggedOnUser and a server is located in this domain. 
        Then the credentials specified by the Credential parameter are used to get the domain.
        
        If the Server and Credential parameters are specified:
        
        The domain is set to the domain of the specified server and the cmdlet checks to make sure that the server is in 
        the domain of the LocalComputer or LoggedOnUser. Then the credentials specified by the Credential parameter are 
        used to get the domain. An error is returned when the server is not in the domain of the LocalComputer or 
        LoggedOnUser.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291025
        Set-ADDomain 
        Set-ADDomainMode 
    
    REMARKS
        To see the examples, type: "get-help Get-ADDomain -examples".
        For more information, type: "get-help Get-ADDomain -detailed".
        For technical information, type: "get-help Get-ADDomain -full".
        For online help, type: "get-help Get-ADDomain -online"
    
    
    
    NAME
        Get-ADDomainController
        
    SYNOPSIS
        Gets one or more Active Directory domain controllers based on discoverable services criteria, search parameters or 
        by providing a domain controller identifier, such as the NetBIOS name.
        
        
    SYNTAX
        Get-ADDomainController [[-Identity] <ADDomainController>] [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [<CommonParameters>]
        
        Get-ADDomainController [-AuthType {Negotiate | Basic}] [-AvoidSelf] [-DomainName <String>] [-ForceDiscover] 
        [-MinimumDirectoryServiceVersion {Windows2000 | Windows2008 | Windows2012 | Windows2012R2}] [-NextClosestSite] 
        [-Service {ADWS | GlobalCatalog | KDC | PrimaryDC | ReliableTimeService | TimeService}] [-SiteName <String>] 
        [-Writable] -Discover [<CommonParameters>]
        
        Get-ADDomainController [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Server <String>] -Filter 
        <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDomainController cmdlet gets the domain controllers specified by the parameters. You can get domain 
        controllers by setting the Identity, Filter or Discover parameters.
        
        The Identity parameter specifies the domain controller to get. You can identify a domain controller by its GUID, 
        IPV4Address, global IPV6Address, or DNS host name. You can also identify a domain controller by the name of the 
        server object that represents the domain controller, the Distinguished Name (DN) of the NTDS settings object or 
        the server object, the GUID of the NTDS settings object or the server object under the configuration partition, or 
        the DN of the computer object that represents the domain controller.  You can also set the Identity parameter to a 
        domain controller object variable, such as $<localDomainControllerObject>, or pass a domain controller object 
        through the pipeline to the Identity parameter.
        
        To search for and retrieve more than one domain controller, use the Filter parameter. The Filter parameter uses 
        the PowerShell Expression Language to write query strings for Active Directory. PowerShell Expression Language 
        syntax provides rich type conversion support for value types received by the Filter parameter. For more 
        information about the Filter parameter syntax, see about_ActiveDirectory_Filter. You cannot use an LDAP query 
        string with this cmdlet.
        
        To get a domain controller by using the discovery mechanism of DCLocator, use the Discover parameter. You can 
        provide search criteria by setting parameters such as Service, SiteName, DomainName, NextClosestSite, AvoidSelf, 
        and ForceDiscover.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291026
        Add-ADDomainControllerPasswordReplicationPolicy 
        Get-ADDomainControllerPasswordReplicationPolicy 
        Remove-ADDomainControllerPasswordReplicationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Get-ADDomainController -examples".
        For more information, type: "get-help Get-ADDomainController -detailed".
        For technical information, type: "get-help Get-ADDomainController -full".
        For online help, type: "get-help Get-ADDomainController -online"
    
    
    
    NAME
        Get-ADDomainControllerPasswordReplicationPolicy
        
    SYNOPSIS
        Gets the members of the allowed list or denied list of a read-only domain controller's password replication policy.
        
        
    SYNTAX
        Get-ADDomainControllerPasswordReplicationPolicy [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDomainControllerPasswordReplicationPolicy gets the users, computers, service accounts and groups that 
        are members of the applied list or denied list for a read-only domain controller's (RODC) password replication 
        policy. To get the members of the applied list, specify the AppliedList parameter. To get the members of the 
        denied list, specify the DeniedList parameter.
        
        The Identity parameter specifies the RODC that uses the allowed and denied lists to apply the password replication 
        policy. You can identify a domain controller by its GUID, IPV4Address, IPV6Address, or DNS host name. You can also 
        identify a domain controller by the name of the server object that represents the domain controller, the 
        Distinguished Name (DN) of the NTDS settings object or the server object, the GUID of the NTDS settings object or 
        the server object under the configuration partition, or the DN of the computer object that represents the domain 
        controller.
        
        You can also set the Identity parameter to a domain controller object variable, such as 
        $<localDomainControllerobject>, or pass a domain controller object through the pipeline to the Identity parameter. 
        For example, you can use the Get-ADDomainController cmdlet to retrieve a domain controller object and then pass 
        the object through the pipeline to the Get-ADDomainControllerPasswordReplicationPolicy cmdlet.
        
        If you specify a writeable domain controller for this cmdlet, the cmdlet returns a non-terminating error.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291027
        Add-ADDomainControllerPasswordReplicationPolicy 
        Remove-ADDomainControllerPasswordReplicationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Get-ADDomainControllerPasswordReplicationPolicy -examples".
        For more information, type: "get-help Get-ADDomainControllerPasswordReplicationPolicy -detailed".
        For technical information, type: "get-help Get-ADDomainControllerPasswordReplicationPolicy -full".
        For online help, type: "get-help Get-ADDomainControllerPasswordReplicationPolicy -online"
    
    
    
    NAME
        Get-ADDomainControllerPasswordReplicationPolicyUsage
        
    SYNOPSIS
        Gets the Active Directory accounts that are authenticated by a read-only domain controller or that are in the 
        revealed list of the domain controller.
        
        
    SYNTAX
        Get-ADDomainControllerPasswordReplicationPolicyUsage [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADDomainControllerPasswordReplicationPolicyUsage cmdlet gets the user or computer accounts that are 
        authenticated by a read-only domain controller (RODC) or that have passwords that are stored on that RODC. The 
        list of accounts that are stored on a RODC is known as the revealed list.
        
        To get accounts that are authenticated by the RODC, use the AuthenticatedAccounts parameter. To get the accounts 
        that have passwords stored on the RODC, use the RevealedAccounts parameter.
        
        The Identity parameter specifies the RODC. You can identify a domain controller by its GUID, IPV4Address, global 
        IPV6Address, or DNS host name. You can also identify a domain controller by the name of the server object that 
        represents the domain controller, the Distinguished Name (DN) of the NTDS settings object of the server object, 
        the GUID of the NTDS settings object of the server object under the configuration partition, or the DN of the 
        computer object that represents the domain controller. You can also set the Identity parameter to a domain 
        controller object variable, such as $<localDomainControllerobject>, or pass a domain controller object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADDomainController cmdlet to retrieve a 
        domain controller object and then pass the object through the pipeline to the 
        Get-ADDomainControllerPasswordReplicationPolicyUsage cmdlet. If you specify a writeable domain controller for this 
        cmdlet, the cmdlet returns a non-terminating error.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291028
        Get-ADDomainController 
    
    REMARKS
        To see the examples, type: "get-help Get-ADDomainControllerPasswordReplicationPolicyUsage -examples".
        For more information, type: "get-help Get-ADDomainControllerPasswordReplicationPolicyUsage -detailed".
        For technical information, type: "get-help Get-ADDomainControllerPasswordReplicationPolicyUsage -full".
        For online help, type: "get-help Get-ADDomainControllerPasswordReplicationPolicyUsage -online"
    
    
    
    NAME
        Get-ADFineGrainedPasswordPolicy
        
    SYNOPSIS
        Gets one or more Active Directory fine grained password policies.
        
        
    SYNTAX
        Get-ADFineGrainedPasswordPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | 
        OneLevel | Subtree}] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADFineGrainedPasswordPolicy [-Identity] <ADFineGrainedPasswordPolicy> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADFineGrainedPasswordPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | 
        OneLevel | Subtree}] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADFineGrainedPasswordPolicy cmdlet gets a fine grained password policy or performs a search to retrieve 
        multiple fine grained password policies.
        
        The Identity parameter specifies the Active Directory fine grained password policy to get. You can identify a fine 
        grained password policy by its distinguished name (DN), GUID or name. You can also set the parameter to a fine 
        grained password policy object variable, such as $<localFineGrainedPasswordPolicyObject> or pass a fine grained 
        password policy object through the pipeline to the Identity parameter.
        
        To search for and retrieve more than one fine grained password policies, use the Filter or LDAPFilter parameters. 
        The Filter parameter uses the PowerShell Expression Language to write query strings for Active Directory. 
        PowerShell Expression Language syntax provides rich type conversion support for value types received by the Filter 
        parameter. For more information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have 
        existing LDAP query strings, you can use the LDAPFilter parameter.
        
        This cmdlet retrieves a default set of fine grained password policy object properties. To retrieve additional 
        properties use the Properties parameter. For more information about the how to determine the properties for 
        FineGrainedPasswordPolicy objects, see the Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291029
        Add-ADFineGrainedPasswordPolicySubject 
        New-ADFineGrainedPasswordPolicy 
        Remove-ADFineGrainedPasswordPolicy 
        Remove-ADFineGrainedPasswordPolicySubject 
        Set-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Get-ADFineGrainedPasswordPolicy -examples".
        For more information, type: "get-help Get-ADFineGrainedPasswordPolicy -detailed".
        For technical information, type: "get-help Get-ADFineGrainedPasswordPolicy -full".
        For online help, type: "get-help Get-ADFineGrainedPasswordPolicy -online"
    
    
    
    NAME
        Get-ADFineGrainedPasswordPolicySubject
        
    SYNOPSIS
        Gets the users and groups to which a fine grained password policy is applied.
        
        
    SYNTAX
        Get-ADFineGrainedPasswordPolicySubject [-Identity] <ADFineGrainedPasswordPolicy> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get- ADFineGrainedPasswordPolicySubject cmdlet gets users and groups that are subject to a fine grained 
        password policy.
        
        The Identity parameter specifies the fine grained password policy. You can identify a fine grained password policy 
        by its distinguished name, GUID or name. You can also set the Identity parameter to a fine grained password policy 
        object variable, such as $<localPasswordPolicyObject>, or pass a fine grained password policy object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADFineGrainedPasswordPolicy cmdlet to 
        retrieve a fine grained password policy object and then pass the object through the pipeline to the Get- 
        ADFineGrainedPasswordPolicySubject cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291030
        Get-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Get-ADFineGrainedPasswordPolicySubject -examples".
        For more information, type: "get-help Get-ADFineGrainedPasswordPolicySubject -detailed".
        For technical information, type: "get-help Get-ADFineGrainedPasswordPolicySubject -full".
        For online help, type: "get-help Get-ADFineGrainedPasswordPolicySubject -online"
    
    
    
    NAME
        Get-ADForest
        
    SYNOPSIS
        Gets an Active Directory forest.
        
        
    SYNTAX
        Get-ADForest [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Current {LocalComputer | 
        LoggedOnUser}] [-Server <String>] [<CommonParameters>]
        
        Get-ADForest [-Identity] <ADForest> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Server 
        <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADForest cmdlet gets the Active Directory forest specified by the parameters. You can specify the forest 
        by setting the Identity or Current parameters.
        
        The Identity parameter specifies the Active Directory forest to get. You can identify a forest by its fully 
        qualified domain name (FQDN), DNS host name, or NetBIOS name. You can also set the parameter to a forest object 
        variable, such as $<localForestObject> or you can pass a forest object through the pipeline to the Identity 
        parameter.
        
        To retrieve the forest of the local computer or current logged on user (CLU) set the Current parameter to 
        LocalComputer or LoggedOnUser.  When you set the Current parameter, you do not need to set the Identity parameter.
        
        When the Current parameter is set to LocalComputer or LoggedOnUser, the cmdlet uses the Server and Credential 
        parameter values to determine the domain and the credentials to use to identify the domain of the forest according 
        to the following rules.
        
        -If both the Server and Credential parameters are not specified:
        
        --The domain is set to the domain of the LocalComputer or LoggedOnUser and a server is located in this domain. The 
        credentials of the current logged on user are used to get the domain.
        
        -If the Server parameter is specified and the Credential parameter is not specified:
        
        --The domain is set to the domain of the specified server and the cmdlet checks to make sure that the server is in 
        the domain of the LocalComputer or LoggedOnUser. Then the credentials of the current logged on user are used to 
        get the domain. An error is returned when the server is not in the domain of the LocalComputer or LoggedOnUser.
        
        -If the Server parameter is not specified and the Credential parameter is specified:
        
        --The domain is set to the domain of the LocalComputer or LoggedOnUser and a server is located in this domain. 
        Then the credentials specified by the Credential parameter are used to get the domain.
        
        If the Server and Credential parameters are specified:
        
        The domain is set to the domain of the specified server and the cmdlet checks to make sure that the server is in 
        the domain of the LocalComputer or LoggedOnUser. Then the credentials specified by the Credential parameter are 
        used to get the domain. An error is returned when the server is not in the domain of the LocalComputer or 
        LoggedOnUser.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291031
        Set-ADForest 
        Set-ADForestMode 
    
    REMARKS
        To see the examples, type: "get-help Get-ADForest -examples".
        For more information, type: "get-help Get-ADForest -detailed".
        For technical information, type: "get-help Get-ADForest -full".
        For online help, type: "get-help Get-ADForest -online"
    
    
    
    NAME
        Get-ADGroup
        
    SYNOPSIS
        Gets one or more Active Directory groups.
        
        
    SYNTAX
        Get-ADGroup [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-ResultPageSize 
        <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | Subtree}] [-Server 
        <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADGroup [-Identity] <ADGroup> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADGroup [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-ResultPageSize 
        <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | Subtree}] [-Server 
        <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADGroup cmdlet gets a group or performs a search to retrieve multiple groups from an Active Directory.
        
        The Identity parameter specifies the Active Directory group to get. You can identify a group by its distinguished 
        name (DN), GUID, security identifier (SID), Security Accounts Manager (SAM) account name, or canonical name. You 
        can also specify group object variable, such as $<localGroupObject>.
        
        To search for and retrieve more than one group, use the Filter or LDAPFilter parameters. The Filter parameter uses 
        the PowerShell Expression Language to write query strings for Active Directory. PowerShell Expression Language 
        syntax provides rich type conversion support for value types received by the Filter parameter. For more 
        information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing LDAP query 
        strings, you can use the LDAPFilter parameter.
        
        This cmdlet gets a default set of group object properties. To get additional properties use the Properties 
        parameter. For more information about the how to determine the properties for group objects, see the Properties 
        parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291032
        New-ADGroup 
        Remove-ADGroup 
        Set-ADGroup 
    
    REMARKS
        To see the examples, type: "get-help Get-ADGroup -examples".
        For more information, type: "get-help Get-ADGroup -detailed".
        For technical information, type: "get-help Get-ADGroup -full".
        For online help, type: "get-help Get-ADGroup -online"
    
    
    
    NAME
        Get-ADGroupMember
        
    SYNOPSIS
        Gets the members of an Active Directory group.
        
        
    SYNTAX
        Get-ADGroupMember [-Identity] <ADGroup> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-Recursive] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADGroupMember cmdlet gets the members of an Active Directory group. Members can be users, groups, and 
        computers.
        
        The Identity parameter specifies the Active Directory group to access. You can identify a group by its 
        distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can 
        also specify the group by passing a group object through the pipeline. For example, you can use the Get-ADGroup 
        cmdlet to retrieve a group object and then pass the object through the pipeline to the Get-ADGroupMember cmdlet.
        
        If the Recursive parameter is specified, the cmdlet gets all members in the hierarchy of the group that do not 
        contain child objects. For example, if the group SaraDavisReports contains the user KarenToh and the group 
        JohnSmithReports, and JohnSmithReports contains the user JoshPollock, then the cmdlet returns KarenToh and 
        JoshPollock.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291033
        Add-ADGroupMember 
        Add-ADPrincipalGroupMembership 
        Get-ADGroup 
        Get-ADPrincipalGroupMembership 
        Remove-ADGroupMember 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Get-ADGroupMember -examples".
        For more information, type: "get-help Get-ADGroupMember -detailed".
        For technical information, type: "get-help Get-ADGroupMember -full".
        For online help, type: "get-help Get-ADGroupMember -online"
    
    
    
    NAME
        Get-ADObject
        
    SYNOPSIS
        PSCX Cmdlet: Search for objects in the Active Directory/Global Catalog.
        
        
    SYNTAX
        Get-ADObject [-Class <ObjectClass[]>] [-Credential <PSCredential>] [-DistinguishedName <String>] [-Domain 
        <String>] [-Filter <String>] [-GlobalCatalog] [-PageSize <Int32>] [-Scope <SearchScope>] [-Server <String>] 
        [-SizeLimit <Int32>] [-Value <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        Search for objects in the Active Directory/Global Catalog.
        
    
    RELATED LINKS
    
    REMARKS
        To see the examples, type: "get-help Get-ADObject -examples".
        For more information, type: "get-help Get-ADObject -detailed".
        For technical information, type: "get-help Get-ADObject -full".
    
    
    
    
    NAME
        Get-ADOptionalFeature
        
    SYNOPSIS
        Gets one or more Active Directory optional features.
        
        
    SYNTAX
        Get-ADOptionalFeature [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADOptionalFeature [-Identity] <ADOptionalFeature> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADOptionalFeature [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADOptionalFeature cmdlet gets an optional feature or performs a search to retrieve multiple optional 
        features from an Active Directory.
        
        The Identity parameter specifies the Active Directory optional feature that you want to get. You can identify an 
        optional feature by its distinguished name (DN), feature GUID, or object GUID. You can also set the parameter to 
        an optional feature object variable, such as $<localOptionalFeatureObject> or you can pass an optional feature 
        object through the pipeline to the Identity parameter.
        
        To search for and retrieve more than one optional feature, use the Filter or LDAPFilter parameters. The Filter 
        parameter uses the PowerShell Expression Language to write query strings for Active Directory. PowerShell 
        Expression Language syntax provides rich type conversion support for value types received by the Filter parameter. 
        For more information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing 
        LDAP query strings, you can use the LDAPFilter parameter.
        
        This cmdlet retrieves a default set of optional feature object properties. To retrieve additional properties use 
        the Properties parameter. For more information about the how to determine the properties for computer objects, see 
        the Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291035
        Disable-ADOptionalFeature 
        Enable-ADOptionalFeature 
    
    REMARKS
        To see the examples, type: "get-help Get-ADOptionalFeature -examples".
        For more information, type: "get-help Get-ADOptionalFeature -detailed".
        For technical information, type: "get-help Get-ADOptionalFeature -full".
        For online help, type: "get-help Get-ADOptionalFeature -online"
    
    
    
    NAME
        Get-ADOrganizationalUnit
        
    SYNOPSIS
        Gets one or more Active Directory organizational units.
        
        
    SYNTAX
        Get-ADOrganizationalUnit [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADOrganizationalUnit [-Identity] <ADOrganizationalUnit> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADOrganizationalUnit [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADOrganizational unit cmdlet gets an organizational unit object or performs a search to retrieve multiple 
        organizational units.
        
        The Identity parameter specifies the Active Directory organizational unit to retrieve. You can identify an 
        organizational unit by its distinguished name (DN) or GUID. You can also set the parameter to an organizational 
        unit object variable, such as $<localOrganizationalunitObject> or pass an organizational unit object through the 
        pipeline to the Identity parameter.
        
        To search for and retrieve more than one organizational unit, use the Filter or LDAPFilter parameters. The Filter 
        parameter uses the PowerShell Expression Language to write query strings for Active Directory. PowerShell 
        Expression Language syntax provides rich type conversion support for value types received by the Filter parameter. 
        For more information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing 
        LDAP query strings, you can use the LDAPFilter parameter.
        
        This cmdlet retrieves a default set of organizational unit object properties. To retrieve additional properties 
        use the Properties parameter. For more information about the how to determine the properties for computer objects, 
        see the Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291036
        New-ADOrganizational unit 
        Set-ADOrganizational unit 
        Remove-ADOrganizational unit 
    
    REMARKS
        To see the examples, type: "get-help Get-ADOrganizationalUnit -examples".
        For more information, type: "get-help Get-ADOrganizationalUnit -detailed".
        For technical information, type: "get-help Get-ADOrganizationalUnit -full".
        For online help, type: "get-help Get-ADOrganizationalUnit -online"
    
    
    
    NAME
        Get-ADPrincipalGroupMembership
        
    SYNOPSIS
        Gets the Active Directory groups that have a specified user, computer, group, or service account.
        
        
    SYNTAX
        Get-ADPrincipalGroupMembership [-Identity] <ADPrincipal> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-ResourceContextPartition <String>] [-ResourceContextServer <String>] 
        [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADPrincipalGroupMembership cmdlet gets the Active Directory groups that have a specified user, computer, 
        group, or service account as a member. This cmdlet requires a global catalog to perform the group search. If the 
        forest that contains the user, computer or group does not have a global catalog, the cmdlet returns a 
        non-terminating error. If you want to search for local groups in another domain, use the ResourceContextServer 
        parameter to specify the alternate server in the other domain.
        
        The Identity parameter specifies the user, computer, or group object that you want to determine group membership 
        for. You can identify a user, computer, or group object by its distinguished name (DN), GUID, security identifier 
        (SID) or SAM account name. You can also specify a user, group, or computer object variable, such as 
        $<localGroupObject>, or pass an object through the pipeline to the Identity parameter. For example, you can use 
        the Get-ADGroup cmdlet to retrieve a group object and then pass the object through the pipeline to the 
        Get-ADPrincipalGroupMembership cmdlet. Similarly, you can use Get-ADUser or Get-ADComputer to get user and 
        computer objects to pass through the pipeline.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291037
        Add-ADGroupMember 
        Add-ADPrincipalGroupMembership 
        Get-ADComputer 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADUser 
        Remove-ADGroupMember 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Get-ADPrincipalGroupMembership -examples".
        For more information, type: "get-help Get-ADPrincipalGroupMembership -detailed".
        For technical information, type: "get-help Get-ADPrincipalGroupMembership -full".
        For online help, type: "get-help Get-ADPrincipalGroupMembership -online"
    
    
    
    NAME
        Get-ADReplicationAttributeMetadata
        
    SYNOPSIS
        Returns the replication metadata for one or more Active Directory replication partners.
        
        
    SYNTAX
        Get-ADReplicationAttributeMetadata [-Object] <ADObject> [-Server] <String> [[-Properties] <String[]>] [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-Filter <String>] [-IncludeDeletedObjects] 
        [-ShowAllLinkedValues] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationAttributeMetadata cmdlet returns the replication metadata for one or more attributes on a 
        given object. The metadata is contained in the following two directory objects:
        
        single-value attribute: msDS-ReplAttributeMetaData
        
        multi-value attribute: msDS-ReplValueMetaData
        
        The cmdlet parses the byte array(s) and returns the data in a readable format.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291038
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationAttributeMetadata -examples".
        For more information, type: "get-help Get-ADReplicationAttributeMetadata -detailed".
        For technical information, type: "get-help Get-ADReplicationAttributeMetadata -full".
        For online help, type: "get-help Get-ADReplicationAttributeMetadata -online"
    
    
    
    NAME
        Get-ADReplicationConnection
        
    SYNOPSIS
        Returns a specific Active Directory replication connection or a set of AD replication connection objects based on 
        a specified filter.
        
        
    SYNTAX
        Get-ADReplicationConnection [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Filter <String>] 
        [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADReplicationConnection [-Identity] <ADReplicationConnection> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationConnection cmdlet returns a specific Active Directory replication connection or a set of AD 
        replication connection objects based on a specified filter.  Connections are used to enable domain controllers to 
        replicate with each other. A connection defines a one-way, inbound route from one domain controller, the source, 
        to another domain controller, the destination. The Kerberos consistency checker (KCC) reuses existing connections 
        where it can, deletes unused connections, and creates new connections if none exist that meet the current need.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291039
        Set-ADReplicationConnection 
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationConnection -examples".
        For more information, type: "get-help Get-ADReplicationConnection -detailed".
        For technical information, type: "get-help Get-ADReplicationConnection -full".
        For online help, type: "get-help Get-ADReplicationConnection -online"
    
    
    
    NAME
        Get-ADReplicationFailure
        
    SYNOPSIS
        Returns a collection of data describing an Active Directory replication failure.
        
        
    SYNTAX
        Get-ADReplicationFailure [-Target] <Object[]> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-EnumeratingServer <String>] [-Filter <String>] [<CommonParameters>]
        
        Get-ADReplicationFailure [[-Target] <Object[]>] [-Scope] {Domain | Forest | Server | Site} [-AuthType {Negotiate | 
        Basic}] [-Credential <PSCredential>] [-EnumeratingServer <String>] [-Filter <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationFailure cmdlet returns all failures currently associated with a given domain controller or 
        Active Directory Lightweight Directory Services (AD LDS) instance. The return object is of type 
        ADReplicationFailure. This cmdlet returns the list of failures in the ADReplicationSummary object for a specific 
        server.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291040
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationFailure -examples".
        For more information, type: "get-help Get-ADReplicationFailure -detailed".
        For technical information, type: "get-help Get-ADReplicationFailure -full".
        For online help, type: "get-help Get-ADReplicationFailure -online"
    
    
    
    NAME
        Get-ADReplicationPartnerMetadata
        
    SYNOPSIS
        Returns the replication metadata for a set of one or more replication partners.
        
        
    SYNTAX
        Get-ADReplicationPartnerMetadata [-Target] <Object[]> [[-Partition] <String[]>] [[-PartnerType] {Both | Inbound | 
        Outbound}] [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-EnumerationServer <String>] [-Filter 
        <String>] [<CommonParameters>]
        
        Get-ADReplicationPartnerMetadata [[-Target] <Object[]>] [-Scope] {Domain | Forest | Server | Site} [[-Partition] 
        <String[]>] [[-PartnerType] {Both | Inbound | Outbound}] [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-EnumerationServer <String>] [-Filter <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationPartnerMetadata cmdlet returns an Active Directory replication partner metadata object for 
        each of its replication partners which contains all of the relevant replication data for the partners involved. 
        This includes attributes such as LastReplicationSuccess or LastReplicationAttempt and other data specific to each 
        pairing of replication partners. If the results are too verbose for your needs, you can use the Partition 
        parameter to specify a partition to narrow down the results. Optionally, you can use the Filter parameter to 
        narrow down results as well. If no partition or filter are specified for the results, the default naming context 
        is used and metadata for all replication partners is returned.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291041
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationPartnerMetadata -examples".
        For more information, type: "get-help Get-ADReplicationPartnerMetadata -detailed".
        For technical information, type: "get-help Get-ADReplicationPartnerMetadata -full".
        For online help, type: "get-help Get-ADReplicationPartnerMetadata -online"
    
    
    
    NAME
        Get-ADReplicationQueueOperation
        
    SYNOPSIS
        Returns the contents of the replication queue for a specified server.
        
        
    SYNTAX
        Get-ADReplicationQueueOperation [-Server] <String> [[-Partition] <String[]>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Filter <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationQueueOperation cmdlet returns all of the pending operations in the replication queue. While 
        replication operations are pending, this cmdlet can be useful for determining the status of queued operations.
        
        The Get-ADReplicationQueueOperation cmdlet can be called from script to watch and observe when operations get 
        moved out of the queue as they are replicated. It also allows for filtering on any of the properties on the 
        ADReplicationOperation object.
        
        The replication queue operates in the following manner: suppose a domain controller has five inbound replication 
        connections. As the domain controller formulates change requests, either by a schedule being reached or from a 
        notification, it adds a work item for each request to the end of the queue of pending synchronization requests. 
        Each pending synchronization request represents one <source domain controller, directory partition> pair, such as 
        "synchronize the schema directory partition from DC1," or "delete the ApplicationX directory partition."
        
        When a work item has been received into the queue, notification and polling intervals do not apply. Instead, the 
        domain controller processes the item (begins synchronizing from its source) as soon as the work item reaches the 
        front of the replication queue. This process continues until either the destination is fully synchronized with the 
        source domain controller, an error occurs, or the synchronization is pre-empted by a higher-priority operation.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291042
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationQueueOperation -examples".
        For more information, type: "get-help Get-ADReplicationQueueOperation -detailed".
        For technical information, type: "get-help Get-ADReplicationQueueOperation -full".
        For online help, type: "get-help Get-ADReplicationQueueOperation -online"
    
    
    
    NAME
        Get-ADReplicationSite
        
    SYNOPSIS
        Returns a specific Active Directory replication site or a set of replication site objects based on a specified 
        filter.
        
        
    SYNTAX
        Get-ADReplicationSite [[-Identity] <ADReplicationSite>] [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADReplicationSite [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-Server <String>] -Filter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationSite cmdlet returns a specific Active Directory replication site or a set of replication site 
        objects based on a specified filter. Sites are used in Active Directory to either enable clients to discover 
        network resources (published shares, domain controllers) close to the physical location of a client computer or to 
        reduce network traffic over wide area network (WAN) links. Sites can also be used to optimize replication between 
        domain controllers.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291043
        New-ADReplicationSite 
        Remove-ADReplicationSite 
        Set-ADReplicationSite 
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationSite -examples".
        For more information, type: "get-help Get-ADReplicationSite -detailed".
        For technical information, type: "get-help Get-ADReplicationSite -full".
        For online help, type: "get-help Get-ADReplicationSite -online"
    
    
    
    NAME
        Get-ADReplicationSiteLink
        
    SYNOPSIS
        Returns a specific Active Directory site link or a set of site links based on a specified filter.
        
        
    SYNTAX
        Get-ADReplicationSiteLink [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADReplicationSiteLink [-Identity] <ADReplicationSiteLink> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationSiteLink cmdlet can be used to return a specific Active Directory site link or a set of site 
        links based on a specified filter.  A site link connects two or more sites. Site links reflect the administrative 
        policy for how sites are to be interconnected and the methods used to transfer replication traffic. You must 
        connect sites with site links so that domain controllers at each site can replicate Active Directory changes.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291044
        New-ADReplicationSiteLink 
        Remove-ADReplicationSiteLink 
        Set-ADReplicationSiteLink 
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationSiteLink -examples".
        For more information, type: "get-help Get-ADReplicationSiteLink -detailed".
        For technical information, type: "get-help Get-ADReplicationSiteLink -full".
        For online help, type: "get-help Get-ADReplicationSiteLink -online"
    
    
    
    NAME
        Get-ADReplicationSiteLinkBridge
        
    SYNOPSIS
        Returns a specific Active Directory site link bridge or a set of site link bridge objects based on a specified 
        filter.
        
        
    SYNTAX
        Get-ADReplicationSiteLinkBridge [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADReplicationSiteLinkBridge [-Identity] <ADReplicationSiteLinkBridge> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationSiteLinkBridge cmdlet returns a specific Active Directory site link bridge or a set of site 
        link bridge objects based on a specified filter. A site link bridge connects two or more site links and enables 
        transitivity between site links. Each site link in a bridge must have a site in common with another site link in 
        the bridge.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291045
        New-ADReplicationSiteLinkBridge 
        Remove-ADReplicationSiteLinkBridge 
        Set-ADReplicationSiteLinkBridge 
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationSiteLinkBridge -examples".
        For more information, type: "get-help Get-ADReplicationSiteLinkBridge -detailed".
        For technical information, type: "get-help Get-ADReplicationSiteLinkBridge -full".
        For online help, type: "get-help Get-ADReplicationSiteLinkBridge -online"
    
    
    
    NAME
        Get-ADReplicationSubnet
        
    SYNOPSIS
        Returns a specific Active Directory subnet or a set of AD subnets based on a specified filter.
        
        
    SYNTAX
        Get-ADReplicationSubnet [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADReplicationSubnet [-Identity] <ADReplicationSubnet> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADReplicationSubnet cmdlet returns a specific Active Directory subnet or a set of AD subnets based on a 
        specified filter. Subnet objects (class subnet) define network subnets in Active Directory. A network subnet is a 
        segment of a TCP/IP network to which a set of logical IP addresses is assigned. Subnets group computers in a way 
        that identifies their physical proximity on the network. Subnet objects in Active Directory are used to map 
        computers to sites.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291046
        New-ADReplicationSubnet 
        Remove-ADReplicationSubnet 
        Set-ADReplicationSubnet 
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationSubnet -examples".
        For more information, type: "get-help Get-ADReplicationSubnet -detailed".
        For technical information, type: "get-help Get-ADReplicationSubnet -full".
        For online help, type: "get-help Get-ADReplicationSubnet -online"
    
    
    
    NAME
        Get-ADReplicationUpToDatenessVectorTable
        
    SYNOPSIS
        Displays the highest Update Sequence Number (USN) for the specified domain controller.
        
        
    SYNTAX
        Get-ADReplicationUpToDatenessVectorTable [-Target] <Object[]> [[-Partition] <String[]>] [-AuthType {Negotiate | 
        Basic}] [-Credential <PSCredential>] [-EnumerationServer <String>] [-Filter <String>] [<CommonParameters>]
        
        Get-ADReplicationUpToDatenessVectorTable [[-Target] <Object[]>] [-Scope] {Domain | Forest | Server | Site} 
        [[-Partition] <String[]>] [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-EnumerationServer 
        <String>] [-Filter <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        Displays the highest Update Sequence Number (USN) for the specified domain controller(s). This information shows 
        how up-to-date a replica is with its replication partners.  During replication, each object that is replicated has 
        USN and if the object is modified, the USN is incremented. The value of the USN for a given object is local to 
        each domain controller where it has replicated are number is different on each domain controller.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291047
    
    REMARKS
        To see the examples, type: "get-help Get-ADReplicationUpToDatenessVectorTable -examples".
        For more information, type: "get-help Get-ADReplicationUpToDatenessVectorTable -detailed".
        For technical information, type: "get-help Get-ADReplicationUpToDatenessVectorTable -full".
        For online help, type: "get-help Get-ADReplicationUpToDatenessVectorTable -online"
    
    
    
    NAME
        Get-ADResourceProperty
        
    SYNOPSIS
        Gets one or more resource properties.
        
        
    SYNTAX
        Get-ADResourceProperty [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADResourceProperty [-Identity] <ADResourceProperty> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADResourceProperty [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADResourceProperty cmdlet gets one or more resource properties.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291048
    
    REMARKS
        To see the examples, type: "get-help Get-ADResourceProperty -examples".
        For more information, type: "get-help Get-ADResourceProperty -detailed".
        For technical information, type: "get-help Get-ADResourceProperty -full".
        For online help, type: "get-help Get-ADResourceProperty -online"
    
    
    
    NAME
        Get-ADResourcePropertyList
        
    SYNOPSIS
        Retrieves resource property lists from Active Directory.
        
        
    SYNTAX
        Get-ADResourcePropertyList [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADResourcePropertyList [-Identity] <ADResourcePropertyList> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADResourcePropertyList [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADResourcePropertyList cmdlet retrieves resource property lists from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291049
    
    REMARKS
        To see the examples, type: "get-help Get-ADResourcePropertyList -examples".
        For more information, type: "get-help Get-ADResourcePropertyList -detailed".
        For technical information, type: "get-help Get-ADResourcePropertyList -full".
        For online help, type: "get-help Get-ADResourcePropertyList -online"
    
    
    
    NAME
        Get-ADResourcePropertyValueType
        
    SYNOPSIS
        Retrieves a resource property value type from Active Directory.
        
        
    SYNTAX
        Get-ADResourcePropertyValueType [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADResourcePropertyValueType [-Identity] <ADResourcePropertyValueType> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADResourcePropertyValueType [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADResourcePropertyValueType cmdlet retrieves a resource property value type from Active Directory. The 
        resource property value type supports the following Active Directory primitives (ValueType, IsSingleValued, 
        RestrictValues) and a Boolean indicating whether SuggestedValues are allowed.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291050
    
    REMARKS
        To see the examples, type: "get-help Get-ADResourcePropertyValueType -examples".
        For more information, type: "get-help Get-ADResourcePropertyValueType -detailed".
        For technical information, type: "get-help Get-ADResourcePropertyValueType -full".
        For online help, type: "get-help Get-ADResourcePropertyValueType -online"
    
    
    
    NAME
        Get-ADRootDSE
        
    SYNOPSIS
        Gets the root of a Directory Server information tree.
        
        
    SYNTAX
        Get-ADRootDSE [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-Server 
        <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADRootDSE cmdlet gets the conceptual object representing the root of the directory information tree of a 
        directory server. This tree provides information about the configuration and capabilities of the directory server, 
        such as the distinguished name for the configuration container, the current time on the directory server, and the 
        functional levels of the directory server and the domain.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291051
    
    REMARKS
        To see the examples, type: "get-help Get-ADRootDSE -examples".
        For more information, type: "get-help Get-ADRootDSE -detailed".
        For technical information, type: "get-help Get-ADRootDSE -full".
        For online help, type: "get-help Get-ADRootDSE -online"
    
    
    
    NAME
        Get-ADServiceAccount
        
    SYNOPSIS
        Gets one or more Active Directory managed service accounts or group managed service accounts.
        
        
    SYNTAX
        Get-ADServiceAccount [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADServiceAccount [-Identity] <ADServiceAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Partition <String>] [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADServiceAccount [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] 
        [-ResultPageSize <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | 
        Subtree}] [-Server <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADServiceAccount cmdlet gets a managed service account (MSA) or performs a search to retrieve MSAs.
        
        The Identity parameter specifies the Active Directory MSA to get. You can identify a MSA by its distinguished name 
        Members (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can also set 
        the parameter to a MSA object variable, such as $<localServiceaccountObject> or pass a MSA object through the 
        pipeline to the Identity parameter.
        
        To search for and retrieve more than one MSA, use the Filter or LDAPFilter parameters. The Filter parameter uses 
        the PowerShell Expression Language to write query strings for Active Directory. PowerShell Expression Language 
        syntax provides rich type conversion support for value types received by the Filter parameter. For more 
        information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing LDAP query 
        strings, you can use the LDAPFilter parameter.
        
        This cmdlet gets a default set of MSA object properties. To retrieve additional properties use the Properties 
        parameter. For more information about the how to determine the properties for service account objects, see the 
        Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291052
        Install-ADServiceAccount 
        New-ADServiceAccount 
        Remove-ADServiceAccount 
        Set-ADServiceAccount 
        Uninstall-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Get-ADServiceAccount -examples".
        For more information, type: "get-help Get-ADServiceAccount -detailed".
        For technical information, type: "get-help Get-ADServiceAccount -full".
        For online help, type: "get-help Get-ADServiceAccount -online"
    
    
    
    NAME
        Get-ADTrust
        
    SYNOPSIS
        Returns all trusted domain objects in the directory.
        
        
    SYNTAX
        Get-ADTrust [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-Server 
        <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADTrust [-Identity] <ADTrust> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties 
        <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADTrust [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-Server 
        <String>] -InputObject <Object> [<CommonParameters>]
        
        Get-ADTrust [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-Server 
        <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADTrust cmdlet returns all trusted domain objects in the directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291053
    
    REMARKS
        To see the examples, type: "get-help Get-ADTrust -examples".
        For more information, type: "get-help Get-ADTrust -detailed".
        For technical information, type: "get-help Get-ADTrust -full".
        For online help, type: "get-help Get-ADTrust -online"
    
    
    
    NAME
        Get-ADUser
        
    SYNOPSIS
        Gets one or more Active Directory users.
        
        
    SYNTAX
        Get-ADUser [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-ResultPageSize 
        <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | Subtree}] [-Server 
        <String>] -Filter <String> [<CommonParameters>]
        
        Get-ADUser [-Identity] <ADUser> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition <String>] 
        [-Properties <String[]>] [-Server <String>] [<CommonParameters>]
        
        Get-ADUser [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Properties <String[]>] [-ResultPageSize 
        <Int32>] [-ResultSetSize <Int32>] [-SearchBase <String>] [-SearchScope {Base | OneLevel | Subtree}] [-Server 
        <String>] -LDAPFilter <String> [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADUser cmdlet gets a user object or performs a search to retrieve multiple user objects.
        
        The Identity parameter specifies the Active Directory user to get. You can identify a user by its distinguished 
        name (DN), GUID, security identifier (SID), Security Accounts Manager (SAM) account name or name. You can also set 
        the parameter to a user object variable, such as $<localUserObject> or pass a user object through the pipeline to 
        the Identity parameter.
        
        To search for and retrieve more than one user, use the Filter or LDAPFilter parameters. The Filter parameter uses 
        the PowerShell Expression Language to write query strings for Active Directory. PowerShell Expression Language 
        syntax provides rich type conversion support for value types received by the Filter parameter. For more 
        information about the Filter parameter syntax, see about_ActiveDirectory_Filter. If you have existing LDAP query 
        strings, you can use the LDAPFilter parameter.
        
        This cmdlet retrieves a default set of user object properties. To retrieve additional properties use the 
        Properties parameter. For more information about the how to determine the properties for user objects, see the 
        Properties parameter description.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291054
        New-ADUser 
        Remove-ADUser 
        Set-ADUser 
    
    REMARKS
        To see the examples, type: "get-help Get-ADUser -examples".
        For more information, type: "get-help Get-ADUser -detailed".
        For technical information, type: "get-help Get-ADUser -full".
        For online help, type: "get-help Get-ADUser -online"
    
    
    
    NAME
        Get-ADUserResultantPasswordPolicy
        
    SYNOPSIS
        Gets the resultant password policy for a user.
        
        
    SYNTAX
        Get-ADUserResultantPasswordPolicy [-Identity] <ADUser> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-Server <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The Get-ADUserResultantPasswordPolicy gets the resultant password policy object (RSoP) for a user. The RSoP is 
        defined by the Active Directory attribute named msDS-ResultantPSO.
        
        A user can have multiple password policy objects (PSOs) associated with it, but only one PSO is the RSoP. A PSO is 
        associated with a user when the PSO applies directly to the user or when the PSO applies to an Active Directory 
        group that contains the user. When more than one PSO policy is associated with a user or group, the RSoP value 
        defines the PSO to apply.
        
        The resultant password policy or RSoP for a user is determined by using the following procedure.
        
        - If only one PSO is associated with a user, this PSO is the RSoP.
        
        - If more than one PSO is associated with a user, the PSO that applies directly to the user is the RSoP.
        
        - If more than one PSO applies directly to the user, the PSO with the lowest msDS-PasswordSettingsPrecedence 
        attribute value is the RSoP and this event is logged as a warning in the Active Directory event log. The lowest 
        attribute value represents the highest PSO precedence. For example, if the msDS-PasswordSettingsPrecedence values 
        of two PSOs are 100 and 200, the PSO with the attribute value of 100 is the RSoP.
        
        - If there are no PSOs that apply directly to the user, the PSOs of the global security groups that have the user 
        as a member are compared. The PSO with the lowest msDS-PasswordSettingsPrecedence value is the RSoP.
        
        The Identity parameter specifies the Active Directory user. You can identify a user by its distinguished name 
        (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can also set the 
        parameter to a user object variable, such as $<localUserObject> or pass a user object through the pipeline to the 
        Identity parameter. For example, you can use the Get-ADUser cmdlet to retrieve a user object and then pass the 
        object through the pipeline to the Get-ADUserResultantPasswordPolicy cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291055
        Get-ADUser 
    
    REMARKS
        To see the examples, type: "get-help Get-ADUserResultantPasswordPolicy -examples".
        For more information, type: "get-help Get-ADUserResultantPasswordPolicy -detailed".
        For technical information, type: "get-help Get-ADUserResultantPasswordPolicy -full".
        For online help, type: "get-help Get-ADUserResultantPasswordPolicy -online"
    
    
    
    NAME
        Grant-ADAuthenticationPolicySiloAccess
        
    SYNOPSIS
        Grants permission to join an authentication policy silo.
        
        
    SYNTAX
        Grant-ADAuthenticationPolicySiloAccess [-Identity] <ADAuthenticationPolicySilo> [-Account] <ADAccount> [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Grant-ADAuthenticationPolicySiloAccess cmdlet grants permission to an account to join an authentication policy 
        silo in Active Directoryr Domain Services.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=288446
        Revoke-ADAuthenticationPolicySiloAccess 
    
    REMARKS
        To see the examples, type: "get-help Grant-ADAuthenticationPolicySiloAccess -examples".
        For more information, type: "get-help Grant-ADAuthenticationPolicySiloAccess -detailed".
        For technical information, type: "get-help Grant-ADAuthenticationPolicySiloAccess -full".
        For online help, type: "get-help Grant-ADAuthenticationPolicySiloAccess -online"
    
    
    
    NAME
        Install-ADServiceAccount
        
    SYNOPSIS
        Installs an Active Directory managed service account on a computer or caches a group managed service account on a 
        computer.
        
        
    SYNTAX
        Install-ADServiceAccount [-Identity] <ADServiceAccount> [-AccountPassword <SecureString>] [-AuthType {Negotiate | 
        Basic}] [-Force] [-PromptForPassword] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Install-ADServiceAccount cmdlet installs an existing Active Directory managed service account (MSA) on the 
        computer on which the cmdlet is run. This cmdlet verifies that the computer is eligible to host the MSA. The 
        cmdlet also makes the required changes locally so that the MSA password can be managed without requiring any user 
        action.
        
        The Identity parameter specifies the Active Directory MSA to install. You can identify a MSA by its distinguished 
        name Members (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can also 
        set the parameter to a MSA object variable, such as $<localServiceaccountObject> or pass a MSA object through the 
        pipeline to the Identity parameter. For example, you can use Get-ADServiceAccount to get a MSA object and then 
        pass the object through the pipeline to the Install-ADServiceAccount.
        
        The AccountPassword parameter allows you to pass a SecureString that contains the password of  a standalone MSA 
        and is ignored for group MSAs. Alternatively you can use PromptForPassword switch parameter to be prompted for the 
        standalone MSA password. You need to enter the password of a standalone MSA if you want to install an account that 
        you have pre-provisioned early on. This is required when you are installing a standalone MSA on a server located 
        on a segmented network (site) with no access to writable DCs but only RODCs (e.g. perimeter network or DMZ). In 
        this case you should create the standalone MSA, link it with the appropriate computer account and assign a 
        well-known password that needs to be passed when installing the standalone MSA on the server on the RODC-only site 
        with no access to writable DCs. If you pass both AccountPassword and PromptForPassword parameters the 
        AccountPassword parameter takes precedence.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291056
        Get-ADServiceAccount 
        New-ADServiceAccount 
        Remove-ADServiceAccount 
        Reset-ADServiceAccountPassword 
        Set-ADServiceAccount 
        Uninstall-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Install-ADServiceAccount -examples".
        For more information, type: "get-help Install-ADServiceAccount -detailed".
        For technical information, type: "get-help Install-ADServiceAccount -full".
        For online help, type: "get-help Install-ADServiceAccount -online"
    
    
    
    NAME
        Move-ADDirectoryServer
        
    SYNOPSIS
        Moves a directory server in Active Directory to a new site.
        
        
    SYNTAX
        Move-ADDirectoryServer [-Identity] <ADDirectoryServer> [-Site] <ADReplicationSite> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Move-ADDirectoryServer cmdlet moves a directory server in Active Directory to a new site within the same 
        domain.
        
        The Identity parameter specifies the directory server to move. You can specify a directory server object by one of 
        the following values:
        
        Name of the server object (name)
        
        Distinguished Name (DN) of the NTDS Settings object
        
        Distinguished Name (DN) of the server object that represents the directory server
        
        GUID (objectGUID) of server object under the configuration partition
        
        GUID (objectGUID) of NTDS settings object under the configuration partition
        
        You can also set the Identity parameter to a directory server object variable such as 
        $<localDirectoryServerObject>, or you can pass an object through the pipeline to the Identity parameter. For 
        example, you can use the Get-ADDomainController to get a directory server object and then pass that object through 
        the pipeline to the Move-ADDirectoryServer cmdlet.
        
        The Site parameter specifies the new site for the directory server. You can identify a site by its distinguished 
        name (DN) or GUID.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291057
        Move-ADDirectoryServerOperationMasterRole 
    
    REMARKS
        To see the examples, type: "get-help Move-ADDirectoryServer -examples".
        For more information, type: "get-help Move-ADDirectoryServer -detailed".
        For technical information, type: "get-help Move-ADDirectoryServer -full".
        For online help, type: "get-help Move-ADDirectoryServer -online"
    
    
    
    NAME
        Move-ADDirectoryServerOperationMasterRole
        
    SYNOPSIS
        Moves operation master roles to an Active Directory directory server.
        
        
    SYNTAX
        Move-ADDirectoryServerOperationMasterRole [-Identity] <ADDirectoryServer> [-OperationMasterRole] {PDCEmulator | 
        RIDMaster | InfrastructureMaster | SchemaMaster | DomainNamingMaster} [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Force] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Move-ADDirectoryServerOperationMasterRole cmdlet moves one or more operation master roles to a directory 
        server. You can move operation master roles to a directory server in a different domain if the credentials are the 
        same in both domains.
        
        The Identity parameter specifies the directory server that receives the roles. You can specify a directory server 
        object by one of the following values:
        
        Name of the server object (name)
        
        Distinguished Name (DN) of the NTDS Settings object
        
        Distinguished Name (DN) of the server object that represents the directory server
        
        GUID (objectGUID) of server object under the configuration partition
        
        GUID (objectGUID) of NTDS settings object under the configuration partition
        
        For AD LDS instances the syntax for the server object name is <computer-name>$<instance-name>. The following is an 
        example of this syntax:
        
        asia-w7-vm4$instance1
        
        When you type this value in Windows PowerShell, you must use the backtick (`) as an escape character for the 
        dollar sign ($). Therefore, for this example, you would type the following:
        
        asia-w7-vm4`$instance1
        
        You can also set the parameter to a directory server object variable, such as $<localDirectoryServerObject>.
        
        The Move-ADDirectoryServerOperationMasteRole cmdlet provides two options for moving operation master roles:
        
        1. Role transfer, which involves transferring roles to be moved by running the cmdlet using the Identity parameter 
        to specify the current role holder and the OperationMasterRole parameter to specify the roles for transfer. This 
        is the recommended option.
        
        Operation roles include PDCEmulator, RIDMaster, InfrastructureMaster, SchemaMaster, or DomainNamingMaster. To 
        specify more than one role, use a comma-separated list.
        
        2.  Role seizure, which involves seizing roles you previously attempted to transfer by running the cmdlet a second 
        time using the same parameters as the transfer operation, and adding the Force parameter. The Force parameter must 
        be used as a switch to indicate that seizure (instead of transfer) of operation master roles is being performed. 
        This operation still attempts graceful transfer first, then seizes if transfer is not possible.
        
        Unlike using Ntdsutil.exe to move operation master roles, the Move-ADDirectoryServerOperationMasteRole cmdlet can 
        be remotely executed from any domain joined computer where the Active Directory PowerShell administration module 
        is installed and available for use. This can make the process of moving roles simpler and easier to centrally 
        administer as each of the two command operations required can be run remotely and do not have to be locally 
        executed at each of the corresponding role holders involved in the movement of the roles (i.e. role transfer only 
        allowed at the old role holder, role seizure only allowed at the new role holder).
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291058
        Move-ADDirectoryServer 
    
    REMARKS
        To see the examples, type: "get-help Move-ADDirectoryServerOperationMasterRole -examples".
        For more information, type: "get-help Move-ADDirectoryServerOperationMasterRole -detailed".
        For technical information, type: "get-help Move-ADDirectoryServerOperationMasterRole -full".
        For online help, type: "get-help Move-ADDirectoryServerOperationMasterRole -online"
    
    
    
    NAME
        Move-ADObject
        
    SYNOPSIS
        Moves an Active Directory object or a container of objects to a different container or domain.
        
        
    SYNTAX
        Move-ADObject [-Identity] <ADObject> [-TargetPath] <String> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-TargetServer <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Move-ADObject cmdlet moves an object or a container of objects from one container to another or from one 
        domain to another.
        
        The Identity parameter specifies the Active Directory object or container to move. You can identify an object or 
        container by its distinguished name (DN) or GUID. You can also set the Identity parameter to an object variable 
        such as $<localObject>, or you can pass an object through the pipeline to the Identity parameter. For example, you 
        can use the Get-ADObject cmdlet to retrieve an object and then pass the object through the pipeline to the 
        Move-ADObject cmdlet. You can also use the Get-ADGroup, Get-ADUser, Get-ADComputer, Get-ADServiceAccount, 
        Get-ADOrganizationalUnit and Get-ADFineGrainedPasswordPolicy cmdlets to get an object that you can pass through 
        the pipeline to this cmdlet.
        
        The TargetPath parameter must be specified. This parameter identifies the new location for the object or container.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291059
        Get-ADObject 
        New-ADObject 
        Remove-ADObject 
        Rename-ADObject 
        Restore-ADObject 
        Set-ADObject 
    
    REMARKS
        To see the examples, type: "get-help Move-ADObject -examples".
        For more information, type: "get-help Move-ADObject -detailed".
        For technical information, type: "get-help Move-ADObject -full".
        For online help, type: "get-help Move-ADObject -online"
    
    
    
    NAME
        New-ADAuthenticationPolicy
        
    SYNOPSIS
        Creates an Active Directory Domain Services authentication policy object.
        
        
    SYNTAX
        New-ADAuthenticationPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-ComputerAllowedToAuthenticateTo 
        <String>] [-ComputerTGTLifetimeMins <Int32>] [-Credential <PSCredential>] [-Description <String>] [-Enforce] 
        [-Instance <ADAuthenticationPolicy>] [-OtherAttributes <Hashtable>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Server <String>] [-ServiceAllowedToAuthenticateFrom <String>] [-ServiceAllowedToAuthenticateTo 
        <String>] [-ServiceTGTLifetimeMins <Int32>] [-UserAllowedToAuthenticateFrom <String>] 
        [-UserAllowedToAuthenticateTo <String>] [-UserTGTLifetimeMins <Int32>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADAuthenticationPolicy creates an authentication policy object in Active Directoryr Domain Services.
        
        Commonly used attributes of the object can be specified by the parameters of this cmdlet. To set attributes for 
        the object that are not represented by the parameters of this cmdlet, specify the OtherAttributes parameter.
        
        You can use the pipeline operator and the Import-Csv cmdlet to pass a list for bulk creation of objects in the 
        directory.  You can also specify a template object by using the Instance parameter to create objects from a 
        template.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=288462
        Get-ADAuthenticationPolicy 
        Remove-ADAuthenticationPolicy 
        Set-ADAuthenticationPolicy 
    
    REMARKS
        To see the examples, type: "get-help New-ADAuthenticationPolicy -examples".
        For more information, type: "get-help New-ADAuthenticationPolicy -detailed".
        For technical information, type: "get-help New-ADAuthenticationPolicy -full".
        For online help, type: "get-help New-ADAuthenticationPolicy -online"
    
    
    
    NAME
        New-ADAuthenticationPolicySilo
        
    SYNOPSIS
        Creates an Active Directory Domain Services authentication policy silo object.
        
        
    SYNTAX
        New-ADAuthenticationPolicySilo [-Name] <String> [-AuthType {Negotiate | Basic}] [-ComputerAuthenticationPolicy 
        <ADAuthenticationPolicy>] [-Credential <PSCredential>] [-Description <String>] [-Enforce] [-Instance 
        <ADAuthenticationPolicySilo>] [-OtherAttributes <Hashtable>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Server <String>] [-ServiceAuthenticationPolicy <ADAuthenticationPolicy>] [-UserAuthenticationPolicy 
        <ADAuthenticationPolicy>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADAuthenticationPolicySilo cmdlet creates an authentication policy silo object in Active Directoryr Domain 
        Services.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=290130
        Get-ADAuthenticationPolicySilo 
        Remove-ADAuthenticationPolicySilo 
        Set-ADAuthenticationPolicySilo 
    
    REMARKS
        To see the examples, type: "get-help New-ADAuthenticationPolicySilo -examples".
        For more information, type: "get-help New-ADAuthenticationPolicySilo -detailed".
        For technical information, type: "get-help New-ADAuthenticationPolicySilo -full".
        For online help, type: "get-help New-ADAuthenticationPolicySilo -online"
    
    
    
    NAME
        New-ADCentralAccessPolicy
        
    SYNOPSIS
        Creates a new central access policy in Active Directory containing a set of central access rules.
        
        
    SYNTAX
        New-ADCentralAccessPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-Instance <ADCentralAccessPolicy>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADCentralAccessPolicy cmdlet creates a new central access policy in Active Directory.  A central access 
        policy in Active Directory contains a set of central access rules.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291060
    
    REMARKS
        To see the examples, type: "get-help New-ADCentralAccessPolicy -examples".
        For more information, type: "get-help New-ADCentralAccessPolicy -detailed".
        For technical information, type: "get-help New-ADCentralAccessPolicy -full".
        For online help, type: "get-help New-ADCentralAccessPolicy -online"
    
    
    
    NAME
        New-ADCentralAccessRule
        
    SYNOPSIS
        Creates a new central access rule in Active Directory.
        
        
    SYNTAX
        New-ADCentralAccessRule [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-CurrentAcl 
        <String>] [-Description <String>] [-Instance <ADCentralAccessRule>] [-PassThru] [-ProposedAcl <String>] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-ResourceCondition <String>] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADCentralAccessRule cmdlet creates a new central access rule in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291061
        
    
    REMARKS
        To see the examples, type: "get-help New-ADCentralAccessRule -examples".
        For more information, type: "get-help New-ADCentralAccessRule -detailed".
        For technical information, type: "get-help New-ADCentralAccessRule -full".
        For online help, type: "get-help New-ADCentralAccessRule -online"
    
    
    
    NAME
        New-ADClaimTransformPolicy
        
    SYNOPSIS
        Creates a new claim transformation policy object in Active Directory.
        
        
    SYNTAX
        New-ADClaimTransformPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] -AllowAll 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADClaimTransformPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] 
        -AllowAllExcept <ADClaimType[]> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADClaimTransformPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] -DenyAll 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADClaimTransformPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] -DenyAllExcept 
        <ADClaimType[]> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADClaimTransformPolicy [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-Instance <ADClaimTransformPolicy>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Server <String>] -Rule <String> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADClaimTransformPolicy cmdlet creates a new claims transformation policy object in Active Directory. A 
        claims transformation policy object contains a set of rules authored in the transformation rule language. After 
        creating a policy object, you can link it with a forest trust to apply the claims transformation to the trust.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291062
    
    REMARKS
        To see the examples, type: "get-help New-ADClaimTransformPolicy -examples".
        For more information, type: "get-help New-ADClaimTransformPolicy -detailed".
        For technical information, type: "get-help New-ADClaimTransformPolicy -full".
        For online help, type: "get-help New-ADClaimTransformPolicy -online"
    
    
    
    NAME
        New-ADClaimType
        
    SYNOPSIS
        Creates a new claim type in Active Directory.
        
        
    SYNTAX
        New-ADClaimType [-DisplayName] <String> [-AppliesToClasses <String[]>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Description <String>] [-Enabled <Boolean>] [-ID <String>] [-Instance <ADClaimType>] 
        [-IsSingleValued <Boolean>] [-OtherAttributes <Hashtable>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-RestrictValues <Boolean>] [-Server <String>] [-SuggestedValues <ADSuggestedValueEntry[]>] 
        -SourceAttribute <String> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADClaimType [-DisplayName] <String> [-AppliesToClasses <String[]>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Description <String>] [-Enabled <Boolean>] [-ID <String>] [-Instance <ADClaimType>] 
        [-IsSingleValued <Boolean>] [-OtherAttributes <Hashtable>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-RestrictValues <Boolean>] [-Server <String>] -SourceOID <String> [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        New-ADClaimType [-DisplayName] <String> [-AppliesToClasses <String[]>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Description <String>] [-Enabled <Boolean>] [-ID <String>] [-Instance <ADClaimType>] 
        [-IsSingleValued <Boolean>] [-OtherAttributes <Hashtable>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-RestrictValues <Boolean>] [-Server <String>] [-SuggestedValues <ADSuggestedValueEntry[]>] 
        -SourceTransformPolicy -ValueType {Invalid | Int64 | UInt64 | String | FQBN | SID | Boolean | OctetString} 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADClaimType cmdlet creates a new claim type in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291063
    
    REMARKS
        To see the examples, type: "get-help New-ADClaimType -examples".
        For more information, type: "get-help New-ADClaimType -detailed".
        For technical information, type: "get-help New-ADClaimType -full".
        For online help, type: "get-help New-ADClaimType -online"
    
    
    
    NAME
        New-ADComputer
        
    SYNOPSIS
        Creates a new Active Directory computer.
        
        
    SYNTAX
        New-ADComputer [-Name] <String> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] 
        [-AccountPassword <SecureString>] [-AllowReversiblePasswordEncryption <Boolean>] [-AuthenticationPolicy 
        <ADAuthenticationPolicy>] [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] 
        [-CannotChangePassword <Boolean>] [-Certificates <X509Certificate[]>] [-ChangePasswordAtLogon <Boolean>] 
        [-CompoundIdentitySupported <Boolean>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName 
        <String>] [-DNSHostName <String>] [-Enabled <Boolean>] [-HomePage <String>] [-Instance <ADComputer>] 
        [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] [-Location <String>] [-ManagedBy <ADPrincipal>] 
        [-OperatingSystem <String>] [-OperatingSystemHotfix <String>] [-OperatingSystemServicePack <String>] 
        [-OperatingSystemVersion <String>] [-OtherAttributes <Hashtable>] [-PassThru] [-PasswordNeverExpires <Boolean>] 
        [-PasswordNotRequired <Boolean>] [-Path <String>] [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] 
        [-SAMAccountName <String>] [-Server <String>] [-ServicePrincipalNames <String[]>] [-TrustedForDelegation 
        <Boolean>] [-UserPrincipalName <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADComputer cmdlet creates a new Active Directory computer object. This cmdlet does not join a computer to 
        a domain. You can set commonly used computer property values by using the cmdlet parameters. Property values that 
        are not associated with cmdlet parameters can be modified by using the OtherAttributes parameter.
        
        You can use this cmdlet to provision a computer account before the computer is added to the domain. These 
        pre-created computer objects can be used with offline domain join, unsecure domain Join and RODC domain join 
        scenarios.
        
        The Path parameter specifies the container or organizational unit (OU) for the new computer. When you do not 
        specify the Path parameter, the cmdlet creates a computer account in the default container for computer objects in 
        the domain.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADComputer cmdlet, specify the required parameters, and set any additional property values 
        by using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new computer object or retrieve a copy of 
        an existing computer object and set the Instance parameter to this object. The object provided to the Instance 
        parameter is used as a template for the new object. You can override property values from the template by setting 
        cmdlet parameters. For examples and more information, see the Instance parameter description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the Add-ADComputer cmdlet to create multiple Active Directory computer 
        objects. To do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) 
        file that contains a list of object properties. Then pass these objects through the pipeline to the New-ADComputer 
        cmdlet to create the computer objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291064
        Add-ADComputerServiceAccount 
        Get-ADComputer 
        Get-ADComputerServiceAccount 
        Remove-ADComputer 
        Remove-ADComputerServiceAccount 
        Set-ADComputer 
    
    REMARKS
        To see the examples, type: "get-help New-ADComputer -examples".
        For more information, type: "get-help New-ADComputer -detailed".
        For technical information, type: "get-help New-ADComputer -full".
        For online help, type: "get-help New-ADComputer -online"
    
    
    
    NAME
        New-ADDCCloneConfigFile
        
    SYNOPSIS
        Performs prerequisite checks for cloning a domain controller and generates a clone configuration file if all 
        checks succeed.
        
        
    SYNTAX
        New-ADDCCloneConfigFile [-CloneComputerName <String>] [-IPv4DNSResolver <String[]>] [-Path <String>] [-SiteName 
        <String>] [<CommonParameters>]
        
        New-ADDCCloneConfigFile [-AlternateWINSServer <String>] [-CloneComputerName <String>] [-IPv4DefaultGateway 
        <String>] [-Path <String>] [-PreferredWINSServer <String>] [-SiteName <String>] -IPv4Address <String> 
        -IPv4DNSResolver <String[]> -IPv4SubnetMask <String> -Static [<CommonParameters>]
        
        New-ADDCCloneConfigFile [-AlternateWINSServer <String>] [-CloneComputerName <String>] [-IPv4Address <String>] 
        [-IPv4DefaultGateway <String>] [-IPv4DNSResolver <String[]>] [-IPv4SubnetMask <String>] [-IPv6DNSResolver 
        <String[]>] [-PreferredWINSServer <String>] [-SiteName <String>] [-Static] -Offline -Path <String> 
        [<CommonParameters>]
        
        New-ADDCCloneConfigFile [-CloneComputerName <String>] [-Path <String>] [-SiteName <String>] -IPv6DNSResolver 
        <String[]> -Static [<CommonParameters>]
        
        New-ADDCCloneConfigFile [-CloneComputerName <String>] [-IPv6DNSResolver <String[]>] [-Path <String>] [-SiteName 
        <String>] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-DCCloneConfigFile cmdlet performs prerequisite checks for cloning a domain controller (DC) when run 
        locally on the DC being prepared for cloning. This cmdlet generates a clone configuration file, DCCloneConfig.xml, 
        at an appropriate location, if all prerequisite checks succeed.
        
        There are two mode of operation for this cmdlet, depending on where it is executed. When run on the domain 
        controller that is being prepared for cloning, it will run the following pre-requisite checks to make sure this DC 
        is adequately prepared for cloning:
        
        (1) Is the PDC emulator FSMO role hosted on a DC running Windows Server 2012? 
        (2) Is this computer authorized for DC cloning (i.e. is the computer a member of the Cloneable Domain Controllers 
        group)?
        (3) Are all program and services listed in the output of the Get-ADDCCloningExcludedApplicationList cmdlet 
        captured in CustomDCCloneAllowList.xml?
        
        If these pre-requisite checks all pass, the New-DCCloneConfigFile cmdlet will generate a DCCloneConfig.xml file at 
        a suitable location based on the parameter values supplied. This cmdlet can also be run from a client (with RSAT) 
        and used to generate a DCCloneConfig.xml against offline media of the DC being cloned, however, none of the 
        pre-requisite checks will be performed in this usage mode. This usage is intended to generate DCCloneConfig.xml 
        files with specific configuration values for each clone on copies of the offline media.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291065
        Get-ADDCCloningExcludedApplicationList 
    
    REMARKS
        To see the examples, type: "get-help New-ADDCCloneConfigFile -examples".
        For more information, type: "get-help New-ADDCCloneConfigFile -detailed".
        For technical information, type: "get-help New-ADDCCloneConfigFile -full".
        For online help, type: "get-help New-ADDCCloneConfigFile -online"
    
    
    
    NAME
        New-ADFineGrainedPasswordPolicy
        
    SYNOPSIS
        Creates a new Active Directory fine grained password policy.
        
        
    SYNTAX
        New-ADFineGrainedPasswordPolicy [-Name] <String> [-Precedence] <Int32> [-AuthType {Negotiate | Basic}] 
        [-ComplexityEnabled <Boolean>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] 
        [-Instance <ADFineGrainedPasswordPolicy>] [-LockoutDuration <TimeSpan>] [-LockoutObservationWindow <TimeSpan>] 
        [-LockoutThreshold <Int32>] [-MaxPasswordAge <TimeSpan>] [-MinPasswordAge <TimeSpan>] [-MinPasswordLength <Int32>] 
        [-OtherAttributes <Hashtable>] [-PassThru] [-PasswordHistoryCount <Int32>] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-ReversibleEncryptionEnabled <Boolean>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADFineGrainedPasswordPolicy cmdlet creates a new Active Directory fine grained password policy. You can 
        set commonly used fine grained password policy property values by using the cmdlet parameters. Property values 
        that are not associated with cmdlet parameters can be set by using the OtherAttributes parameter.
        
        You must set the Name and Precedence parameters to create a new fine grained password policy.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADFineGrainedPasswordPolicy cmdlet, specify the required parameters, and set any additional 
        property values by using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new fine grained password policy object or 
        retrieve a copy of an existing fine grained password policy object and set the Instance parameter to this object. 
        The object provided to the Instance parameter is used as a template for the new object. You can override property 
        values from the template by setting cmdlet parameters. For examples and more information, see the Instance 
        parameter description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADFineGrainedPasswordPolicy cmdlet to create multiple Active 
        Directory fine grained password policy objects. To do this, use the Import-CSV cmdlet to create the custom objects 
        from a comma-separated value (CSV) file that contains a list of object properties. Then pass these objects through 
        the pipeline to the New-ADFineGrainedPasswordPolicy cmdlet to create the fine grained password policy objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291066
        Get-ADFineGrainedPasswordPolicy 
        Remove-ADFineGrainedPasswordPolicy 
        Set-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help New-ADFineGrainedPasswordPolicy -examples".
        For more information, type: "get-help New-ADFineGrainedPasswordPolicy -detailed".
        For technical information, type: "get-help New-ADFineGrainedPasswordPolicy -full".
        For online help, type: "get-help New-ADFineGrainedPasswordPolicy -online"
    
    
    
    NAME
        New-ADGroup
        
    SYNOPSIS
        Creates an Active Directory group.
        
        
    SYNTAX
        New-ADGroup [-Name] <String> [-GroupScope] {DomainLocal | Global | Universal} [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] [-GroupCategory {Distribution | 
        Security}] [-HomePage <String>] [-Instance <ADGroup>] [-ManagedBy <ADPrincipal>] [-OtherAttributes <Hashtable>] 
        [-PassThru] [-Path <String>] [-SamAccountName <String>] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADGroup cmdlet creates a new Active Directory group object. Many object properties are defined by setting 
        cmdlet parameters. Properties that cannot be set by cmdlet parameters can be set using the OtherAttributes 
        parameter.
        
        The Name and GroupScope parameters specify the name and scope of the group and are required to create a new group. 
        You can define the new group as a security or distribution group by setting the GroupType parameter. The Path 
        parameter specifies the container or organizational unit (OU) for the group.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADGroup cmdlet, specify the required parameters, and set any additional property values by 
        using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new group object or retrieve a copy of an 
        existing group object and set the Instance parameter to this object. The object provided to the Instance parameter 
        is used as a template for the new object. You can override property values from the template by setting cmdlet 
        parameters. For examples and more information, see the Instance parameter description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADGroup cmdlet to create multiple Active Directory group objects. 
        To do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) file that 
        contains a list of object properties. Then pass these objects through the pipeline to the New-ADGroup cmdlet to 
        create the group objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291067
        Get-ADGroup 
        Remove-ADGroup 
        Set-ADGroup 
        Import-CSV 
    
    REMARKS
        To see the examples, type: "get-help New-ADGroup -examples".
        For more information, type: "get-help New-ADGroup -detailed".
        For technical information, type: "get-help New-ADGroup -full".
        For online help, type: "get-help New-ADGroup -online"
    
    
    
    NAME
        New-ADObject
        
    SYNOPSIS
        Creates an Active Directory object.
        
        
    SYNTAX
        New-ADObject [-Name] <String> [-Type] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-DisplayName <String>] [-Instance <ADObject>] [-OtherAttributes <Hashtable>] [-PassThru] 
        [-Path <String>] [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADObject cmdlet creates a new Active Directory object such as a new organizational unit or new user 
        account. You can use this cmdlet to create any type of Active Directory object. Many object properties are defined 
        by setting cmdlet parameters. Properties that are not set by cmdlet parameters can be set by using the 
        OtherAttributes parameter.
        
        You must set the Name and Type parameters to create a new Active Directory object. The Name specifies the name of 
        the new object. The Type parameter specifies the LDAP display name of the Active Directory Schema Class that 
        represents the type of object you want to create. Examples of Type values include computer, group, organizational 
        unit, and user.
        
        The Path parameter specifies the container where the object will be created.. When you do not specify the Path 
        parameter, the cmdlet creates an object in the default naming context container for Active Directory objects in 
        the domain.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADObject cmdlet, specify the required parameters, and set any additional property values by 
        using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new Active Directory object or retrieve a 
        copy of an existing Active Directory object and set the Instance parameter to this object. The object provided to 
        the Instance parameter is used as a template for the new object. You can override property values from the 
        template by setting cmdlet parameters. For examples and more information, see the Instance parameter description 
        for this cmdlet. For information about Active Directory cmdlets use the Instance parameter, see 
        about_ActiveDirectory_Instance.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADObject cmdlet to create multiple Active Directory objects. To 
        do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) file that 
        contains a list of object properties. Then pass these objects through the pipeline to the New-ADObject cmdlet to 
        create the Active Directory objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291068
        Get-ADObject 
        Move-ADObject 
        Remove-ADObject 
        Rename-ADObject 
        Restore-ADObject 
        Set-ADObject 
    
    REMARKS
        To see the examples, type: "get-help New-ADObject -examples".
        For more information, type: "get-help New-ADObject -detailed".
        For technical information, type: "get-help New-ADObject -full".
        For online help, type: "get-help New-ADObject -online"
    
    
    
    NAME
        New-ADOrganizationalUnit
        
    SYNOPSIS
        Creates a new Active Directory organizational unit.
        
        
    SYNTAX
        New-ADOrganizationalUnit [-Name] <String> [-AuthType {Negotiate | Basic}] [-City <String>] [-Country <String>] 
        [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] [-Instance <ADOrganizationalUnit>] 
        [-ManagedBy <ADPrincipal>] [-OtherAttributes <Hashtable>] [-PassThru] [-Path <String>] [-PostalCode <String>] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] [-State <String>] [-StreetAddress <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADOrganizationalUnit cmdlet creates a new Active Directory organizational unit. You can set commonly used 
        organizational unit property values by using the cmdlet parameters. Property values that are not associated with 
        cmdlet parameters can be set by using the OtherAttributes parameter.
        
        You must set the Name parameter to create a new organizational unit. When you do not specify the Path parameter, 
        the cmdlet creates an organizational unit under the default NC head for the domain.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADOrganizationalUnit cmdlet, specify the required parameters, and set any additional 
        property values by using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new organizational unit object or retrieve 
        a copy of an existing organizational unit object and set the Instance parameter to this object. The object 
        provided to the Instance parameter is used as a template for the new object. You can override property values from 
        the template by setting cmdlet parameters. For examples and more information, see the Instance parameter 
        description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADOrganizationalUnit cmdlet to create multiple Active Directory 
        organizational unit objects. To do this, use the Import-CSV cmdlet to create the custom objects from a 
        comma-separated value (CSV) file that contains a list of object properties. Then pass these objects through the 
        pipeline to the New-ADOrganizationalUnit cmdlet to create the organizational unit objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291069
        Get-ADOrganizationalUnit 
        Remove-ADOrganizationalUnit 
        Set-ADOrganizationalUnit 
    
    REMARKS
        To see the examples, type: "get-help New-ADOrganizationalUnit -examples".
        For more information, type: "get-help New-ADOrganizationalUnit -detailed".
        For technical information, type: "get-help New-ADOrganizationalUnit -full".
        For online help, type: "get-help New-ADOrganizationalUnit -online"
    
    
    
    NAME
        New-ADReplicationSite
        
    SYNOPSIS
        Creates a new Active Directory replication site in the directory.
        
        
    SYNTAX
        New-ADReplicationSite [-Name] <String> [-AuthType {Negotiate | Basic}] 
        [-AutomaticInterSiteTopologyGenerationEnabled <Boolean>] [-AutomaticTopologyGenerationEnabled <Boolean>] 
        [-Credential <PSCredential>] [-Description <String>] [-Instance <ADReplicationSite>] [-InterSiteTopologyGenerator 
        <ADDirectoryServer>] [-ManagedBy <ADPrincipal>] [-OtherAttributes <Hashtable>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-RedundantServerTopologyEnabled <Boolean>] [-ReplicationSchedule 
        <ActiveDirectorySchedule>] [-ScheduleHashingEnabled <Boolean>] [-Server <String>] [-TopologyCleanupEnabled 
        <Boolean>] [-TopologyDetectStaleEnabled <Boolean>] [-TopologyMinimumHopsEnabled <Boolean>] 
        [-UniversalGroupCachingEnabled <Boolean>] [-UniversalGroupCachingRefreshSite <ADReplicationSite>] 
        [-WindowsServer2000BridgeheadSelectionMethodEnabled <Boolean>] [-WindowsServer2000KCCISTGSelectionBehaviorEnabled 
        <Boolean>] [-WindowsServer2003KCCBehaviorEnabled <Boolean>] [-WindowsServer2003KCCIgnoreScheduleEnabled <Boolean>] 
        [-WindowsServer2003KCCSiteLinkBridgingEnabled <Boolean>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADReplicationSite cmdlet is used to create new sites in Active Directory replication. Sites are used in 
        Active Directory to either enable clients to discover network resources (published shares, domain controllers) 
        close to the physical location of a client computer or to reduce network traffic over wide area network (WAN) 
        links. Sites can also be used to optimize replication between domain controllers.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291070
        Get-ADReplicationSite 
        Remove-ADReplicationSite 
        Set-ADReplicationSite 
    
    REMARKS
        To see the examples, type: "get-help New-ADReplicationSite -examples".
        For more information, type: "get-help New-ADReplicationSite -detailed".
        For technical information, type: "get-help New-ADReplicationSite -full".
        For online help, type: "get-help New-ADReplicationSite -online"
    
    
    
    NAME
        New-ADReplicationSiteLink
        
    SYNOPSIS
        Creates a new Active Directory site link for in managing replication.
        
        
    SYNTAX
        New-ADReplicationSiteLink [-Name] <String> [[-SitesIncluded] <ADReplicationSite[]>] [-AuthType {Negotiate | 
        Basic}] [-Cost <Int32>] [-Credential <PSCredential>] [-Description <String>] [-Instance <ADReplicationSiteLink>] 
        [-InterSiteTransportProtocol {IP | SMTP}] [-OtherAttributes <Hashtable>] [-PassThru] 
        [-ReplicationFrequencyInMinutes <Int32>] [-ReplicationSchedule <ActiveDirectorySchedule>] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADReplicationSiteLink cmdlet can be used to create a new Active Directory site link.  A site link connects 
        two or more sites. Site links reflect the administrative policy for how sites are to be interconnected and the 
        methods used to transfer replication traffic. You must connect sites with site links so that domain controllers at 
        each site can replicate Active Directory changes.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291071
        Get-ADReplicationSiteLink 
        Remove-ADReplicationSiteLink 
        Set-ADReplicationSiteLink 
    
    REMARKS
        To see the examples, type: "get-help New-ADReplicationSiteLink -examples".
        For more information, type: "get-help New-ADReplicationSiteLink -detailed".
        For technical information, type: "get-help New-ADReplicationSiteLink -full".
        For online help, type: "get-help New-ADReplicationSiteLink -online"
    
    
    
    NAME
        New-ADReplicationSiteLinkBridge
        
    SYNOPSIS
        Creates a new site link bridge in Active Directory for replication.
        
        
    SYNTAX
        New-ADReplicationSiteLinkBridge [-Name] <String> [[-SiteLinksIncluded] <ADReplicationSiteLink[]>] [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-Description <String>] [-Instance 
        <ADReplicationSiteLinkBridge>] [-InterSiteTransportProtocol {IP | SMTP}] [-OtherAttributes <Hashtable>] 
        [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADReplicationSiteLinkBridge cmdlet creates a new site link bridge in Active Directory for use in 
        replication. A site link bridge connects two or more site links and enables transitivity between site links. Each 
        site link in a bridge must have a site in common with another site link in the bridge.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291072
        Get-ADReplicationSiteLinkBridge 
        Remove-ADReplicationSiteLinkBridge 
        Set-ADReplicationSiteLinkBridge 
    
    REMARKS
        To see the examples, type: "get-help New-ADReplicationSiteLinkBridge -examples".
        For more information, type: "get-help New-ADReplicationSiteLinkBridge -detailed".
        For technical information, type: "get-help New-ADReplicationSiteLinkBridge -full".
        For online help, type: "get-help New-ADReplicationSiteLinkBridge -online"
    
    
    
    NAME
        New-ADReplicationSubnet
        
    SYNOPSIS
        Creates a new Active Directory replication subnet object.
        
        
    SYNTAX
        New-ADReplicationSubnet [-Name] <String> [[-Site] <ADReplicationSite>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Description <String>] [-Instance <ADReplicationSubnet>] [-Location <String>] 
        [-OtherAttributes <Hashtable>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADReplicationSubnet cmdlet creates a new Active Directory subnet object. Subnet objects (class subnet) 
        define network subnets in Active Directory. A network subnet is a segment of a TCP/IP network to which a set of 
        logical IP addresses is assigned. Subnets group computers in a way that identifies their physical proximity on the 
        network. Subnet objects in Active Directory are used to map computers to sites.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291073
        Get-ADReplicationSubnet 
        Remove-ADReplicationSubnet 
        Set-ADReplicationSubnet 
    
    REMARKS
        To see the examples, type: "get-help New-ADReplicationSubnet -examples".
        For more information, type: "get-help New-ADReplicationSubnet -detailed".
        For technical information, type: "get-help New-ADReplicationSubnet -full".
        For online help, type: "get-help New-ADReplicationSubnet -online"
    
    
    
    NAME
        New-ADResourceProperty
        
    SYNOPSIS
        Creates a new resource property in Active Directory.
        
        
    SYNTAX
        New-ADResourceProperty [-DisplayName] <String> [-AppliesToResourceTypes <String[]>] [-AuthType {Negotiate | 
        Basic}] [-Credential <PSCredential>] [-Description <String>] [-Enabled <Boolean>] [-ID <String>] [-Instance 
        <ADResourceProperty>] [-IsSecured <Boolean>] [-OtherAttributes <Hashtable>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Server <String>] [-SharesValuesWith <ADClaimType>] 
        [-SuggestedValues <ADSuggestedValueEntry[]>] -ResourcePropertyValueType <ADResourcePropertyValueType> [-Confirm] 
        [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADResourceProperty cmdlet creates a new resource property in the directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291074
        Get-ADResourceProperty 
    
    REMARKS
        To see the examples, type: "get-help New-ADResourceProperty -examples".
        For more information, type: "get-help New-ADResourceProperty -detailed".
        For technical information, type: "get-help New-ADResourceProperty -full".
        For online help, type: "get-help New-ADResourceProperty -online"
    
    
    
    NAME
        New-ADResourcePropertyList
        
    SYNOPSIS
        Creates a new resource property list in Active Directory.
        
        
    SYNTAX
        New-ADResourcePropertyList [-Name] <String> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Description <String>] [-Instance <ADResourcePropertyList>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADResourcePropertyList cmdlet creates a resource property list in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291075
    
    REMARKS
        To see the examples, type: "get-help New-ADResourcePropertyList -examples".
        For more information, type: "get-help New-ADResourcePropertyList -detailed".
        For technical information, type: "get-help New-ADResourcePropertyList -full".
        For online help, type: "get-help New-ADResourcePropertyList -online"
    
    
    
    NAME
        New-ADServiceAccount
        
    SYNOPSIS
        Creates a new Active Directory managed service account or group managed service account object.
        
        
    SYNTAX
        New-ADServiceAccount [-Name] <String> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] 
        [-AuthenticationPolicy <ADAuthenticationPolicy>] [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] 
        [-AuthType {Negotiate | Basic}] [-Certificates <String[]>] [-CompoundIdentitySupported <Boolean>] [-Credential 
        <PSCredential>] [-Description <String>] [-DisplayName <String>] [-Enabled <Boolean>] [-HomePage <String>] 
        [-Instance <ADServiceAccount>] [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] 
        [-ManagedPasswordIntervalInDays <Int32>] [-OtherAttributes <Hashtable>] [-PassThru] [-Path <String>] 
        [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] [-PrincipalsAllowedToRetrieveManagedPassword 
        <ADPrincipal[]>] [-SamAccountName <String>] [-Server <String>] [-ServicePrincipalNames <String[]>] 
        [-TrustedForDelegation <Boolean>] -DNSHostName <String> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADServiceAccount [-Name] <String> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] 
        [-AccountPassword <SecureString>] [-AuthenticationPolicy <ADAuthenticationPolicy>] [-AuthenticationPolicySilo 
        <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-Certificates <String[]>] [-Credential 
        <PSCredential>] [-Description <String>] [-DisplayName <String>] [-Enabled <Boolean>] [-HomePage <String>] 
        [-Instance <ADServiceAccount>] [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] [-OtherAttributes 
        <Hashtable>] [-PassThru] [-Path <String>] [-SamAccountName <String>] [-Server <String>] [-ServicePrincipalNames 
        <String[]>] [-TrustedForDelegation <Boolean>] -RestrictToSingleComputer [-Confirm] [-WhatIf] [<CommonParameters>]
        
        New-ADServiceAccount [-Name] <String> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] 
        [-AuthenticationPolicy <ADAuthenticationPolicy>] [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] 
        [-AuthType {Negotiate | Basic}] [-Certificates <String[]>] [-Credential <PSCredential>] [-Description <String>] 
        [-DisplayName <String>] [-Enabled <Boolean>] [-HomePage <String>] [-Instance <ADServiceAccount>] 
        [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] [-OtherAttributes <Hashtable>] [-PassThru] [-Path 
        <String>] [-SamAccountName <String>] [-Server <String>] [-ServicePrincipalNames <String[]>] [-TrustedForDelegation 
        <Boolean>] -RestrictToOutboundAuthenticationOnly [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADServiceAccount cmdlet creates a new Active Directory managed service account (MSA). By default a group 
        MSA is created. To create a standalone MSA which is linked to a specific computer, the -Standalone parameter is 
        used.  To create a group MSA which can only be used in client roles, the -Agent parameter is used. This creates a 
        group MSA which can be used for outbound connections only and attempts to connect to services using this account 
        will fail since the account does not have enough information for authentication to be successful. You can set 
        commonly used MSA property values by using the cmdlet parameters. Property values that are not associated with 
        cmdlet parameters can be set by using the OtherAttributes parameter.
        
        The Path parameter specifies the container or organizational unit (OU) for the new MSA object. When you do not 
        specify the Path parameter, the cmdlet creates an object in the default Managed Service Accounts container for MSA 
        objects in the domain.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADServiceAccount cmdlet, specify the required parameters, and set any additional property 
        values by using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new MSA object or retrieve a copy of an 
        existing MSA object and set the Instance parameter to this object. The object provided to the Instance parameter 
        is used as a template for the new object. You can override property values from the template by setting cmdlet 
        parameters. For examples and more information, see the Instance parameter description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADServiceAccount cmdlet to create multiple Active Directory MSA 
        objects. To do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) 
        file that contains a list of object properties. Then pass these objects through the pipeline to the 
        New-ADServiceAccount cmdlet to create the MSA objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291076
        Get-ADServiceAccount 
        Install-ADServiceAccount 
        Remove-ADServiceAccount 
        Set-ADServiceAccount 
        Uninstall-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help New-ADServiceAccount -examples".
        For more information, type: "get-help New-ADServiceAccount -detailed".
        For technical information, type: "get-help New-ADServiceAccount -full".
        For online help, type: "get-help New-ADServiceAccount -online"
    
    
    
    NAME
        New-ADUser
        
    SYNOPSIS
        Creates a new Active Directory user.
        
        
    SYNTAX
        New-ADUser [-Name] <String> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] [-AccountPassword 
        <SecureString>] [-AllowReversiblePasswordEncryption <Boolean>] [-AuthenticationPolicy <ADAuthenticationPolicy>] 
        [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-CannotChangePassword 
        <Boolean>] [-Certificates <X509Certificate[]>] [-ChangePasswordAtLogon <Boolean>] [-City <String>] [-Company 
        <String>] [-CompoundIdentitySupported <Boolean>] [-Country <String>] [-Credential <PSCredential>] [-Department 
        <String>] [-Description <String>] [-DisplayName <String>] [-Division <String>] [-EmailAddress <String>] 
        [-EmployeeID <String>] [-EmployeeNumber <String>] [-Enabled <Boolean>] [-Fax <String>] [-GivenName <String>] 
        [-HomeDirectory <String>] [-HomeDrive <String>] [-HomePage <String>] [-HomePhone <String>] [-Initials <String>] 
        [-Instance <ADUser>] [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] [-LogonWorkstations <String>] 
        [-Manager <ADUser>] [-MobilePhone <String>] [-Office <String>] [-OfficePhone <String>] [-Organization <String>] 
        [-OtherAttributes <Hashtable>] [-OtherName <String>] [-PassThru] [-PasswordNeverExpires <Boolean>] 
        [-PasswordNotRequired <Boolean>] [-Path <String>] [-POBox <String>] [-PostalCode <String>] 
        [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] [-ProfilePath <String>] [-SamAccountName <String>] 
        [-ScriptPath <String>] [-Server <String>] [-ServicePrincipalNames <String[]>] [-SmartcardLogonRequired <Boolean>] 
        [-State <String>] [-StreetAddress <String>] [-Surname <String>] [-Title <String>] [-TrustedForDelegation 
        <Boolean>] [-Type <String>] [-UserPrincipalName <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The New-ADUser cmdlet creates a new Active Directory user. You can set commonly used user property values by using 
        the cmdlet parameters.
        
        Property values that are not associated with cmdlet parameters can be set by using the OtherAttributes parameter.  
        When using this parameter be sure to place single quotes around the attribute name as in the following example.
        
        New-ADUser -SamAccountName "glenjohn"  -GivenName "Glen" -Surname "John" -DisplayName "Glen John" -Path 
        'CN=Users,DC=fabrikam,DC=local' -OtherAttributes @{'msDS-PhoneticDisplayName'="GlenJohn"}
        
        You must specify the SAMAccountName parameter to create a user.
        
        You can use the New-ADUser cmdlet to create different types of user accounts such as iNetOrgPerson accounts. To do 
        this in AD DS, set the Type parameter to the LDAP display name for the type of account you want to create. This 
        type can be any class in the Active Directory schema that is a subclass of user and that has an object category of 
        person.
        
        The Path parameter specifies the container or organizational unit (OU) for the new user. When you do not specify 
        the Path parameter, the cmdlet creates a user object in the default container for user objects in the domain.
        
        The following methods explain different ways to create an object by using this cmdlet.
        
        Method 1: Use the New-ADUser cmdlet, specify the required parameters, and set any additional property values by 
        using the cmdlet parameters.
        
        Method 2: Use a template to create the new object. To do this, create a new user object or retrieve a copy of an 
        existing user object and set the Instance parameter to this object. The object provided to the Instance parameter 
        is used as a template for the new object. You can override property values from the template by setting cmdlet 
        parameters. For examples and more information, see the Instance parameter description for this cmdlet.
        
        Method 3: Use the Import-CSV cmdlet with the New-ADUser cmdlet to create multiple Active Directory user objects. 
        To do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) file that 
        contains a list of object properties. Then pass these objects through the pipeline to the New-ADUser cmdlet to 
        create the user objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291077
        Get-ADUser 
        Remove-ADUser 
        Set-ADUser 
    
    REMARKS
        To see the examples, type: "get-help New-ADUser -examples".
        For more information, type: "get-help New-ADUser -detailed".
        For technical information, type: "get-help New-ADUser -full".
        For online help, type: "get-help New-ADUser -online"
    
    
    
    NAME
        Remove-ADAuthenticationPolicy
        
    SYNOPSIS
        Removes an Active Directory Domain Services authentication policy object.
        
        
    SYNTAX
        Remove-ADAuthenticationPolicy [-Identity] <ADAuthenticationPolicy> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADAuthenticationPolicy cmdlet removes an Active Directoryr Domain Services authentication policy.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy to remove. You can 
        identify an authentication policy by its distinguished name (DN), GUID or name. You can also use the Identity 
        parameter to specify a variable that contains an authentication policy object, or you can use the pipeline 
        operator to pass an authentication policy object to the Identity parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=296766
        Get-ADAuthenticationPolicy 
        New-ADAuthenticationPolicy 
        Set-ADAuthenticationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADAuthenticationPolicy -examples".
        For more information, type: "get-help Remove-ADAuthenticationPolicy -detailed".
        For technical information, type: "get-help Remove-ADAuthenticationPolicy -full".
        For online help, type: "get-help Remove-ADAuthenticationPolicy -online"
    
    
    
    NAME
        Remove-ADAuthenticationPolicySilo
        
    SYNOPSIS
        Removes an Active Directory Domain Services authentication policy silo object.
        
        
    SYNTAX
        Remove-ADAuthenticationPolicySilo [-Identity] <ADAuthenticationPolicySilo> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADAuthenticationPolicySilo cmdlet removes an Active Directoryr Domain Services authentication policy 
        silo object.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy silo to remove. You 
        can identify an authentication policy silo by its distinguished name (DN), GUID or name. You can also use the 
        Identity parameter to specify a variable that contains an authentication policy silo object, or you can use the 
        pipeline operator to pass an authentication policy silo object to the Identity parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=296768
        Get-ADAuthenticationPolicySilo 
        New-ADAuthenticationPolicySilo 
        Set-ADAuthenticationPolicySilo 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADAuthenticationPolicySilo -examples".
        For more information, type: "get-help Remove-ADAuthenticationPolicySilo -detailed".
        For technical information, type: "get-help Remove-ADAuthenticationPolicySilo -full".
        For online help, type: "get-help Remove-ADAuthenticationPolicySilo -online"
    
    
    
    NAME
        Remove-ADCentralAccessPolicy
        
    SYNOPSIS
        Removes a central access policy from Active Directory.
        
        
    SYNTAX
        Remove-ADCentralAccessPolicy [-Identity] <ADCentralAccessPolicy> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADCentralAccessPolicy cmdlet can be used to remove a central access policy from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291078
    
    REMARKS
        To see the examples, type: "get-help Remove-ADCentralAccessPolicy -examples".
        For more information, type: "get-help Remove-ADCentralAccessPolicy -detailed".
        For technical information, type: "get-help Remove-ADCentralAccessPolicy -full".
        For online help, type: "get-help Remove-ADCentralAccessPolicy -online"
    
    
    
    NAME
        Remove-ADCentralAccessPolicyMember
        
    SYNOPSIS
        Removes central access rules from a central access policy in Active Directory.
        
        
    SYNTAX
        Remove-ADCentralAccessPolicyMember [-Identity] <ADCentralAccessPolicy> [-Members] <ADCentralAccessRule[]> 
        [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADCentralAccessPolicyMember cmdlet removes central access rules from a central access policy in Active 
        Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291079
    
    REMARKS
        To see the examples, type: "get-help Remove-ADCentralAccessPolicyMember -examples".
        For more information, type: "get-help Remove-ADCentralAccessPolicyMember -detailed".
        For technical information, type: "get-help Remove-ADCentralAccessPolicyMember -full".
        For online help, type: "get-help Remove-ADCentralAccessPolicyMember -online"
    
    
    
    NAME
        Remove-ADCentralAccessRule
        
    SYNOPSIS
        Removes a central access rule from Active Directory.
        
        
    SYNTAX
        Remove-ADCentralAccessRule [-Identity] <ADCentralAccessRule> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADCentralAccessRule cmdlet can be used to remove a central access rule from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291080
    
    REMARKS
        To see the examples, type: "get-help Remove-ADCentralAccessRule -examples".
        For more information, type: "get-help Remove-ADCentralAccessRule -detailed".
        For technical information, type: "get-help Remove-ADCentralAccessRule -full".
        For online help, type: "get-help Remove-ADCentralAccessRule -online"
    
    
    
    NAME
        Remove-ADClaimTransformPolicy
        
    SYNOPSIS
        Removes a claim transformation policy object from Active Directory.
        
        
    SYNTAX
        Remove-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADClaimTransformPolicy cmdlet can be used to remove a claim transformation policy object from Active 
        Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291081
    
    REMARKS
        To see the examples, type: "get-help Remove-ADClaimTransformPolicy -examples".
        For more information, type: "get-help Remove-ADClaimTransformPolicy -detailed".
        For technical information, type: "get-help Remove-ADClaimTransformPolicy -full".
        For online help, type: "get-help Remove-ADClaimTransformPolicy -online"
    
    
    
    NAME
        Remove-ADClaimType
        
    SYNOPSIS
        Removes a claim type from Active Directory.
        
        
    SYNTAX
        Remove-ADClaimType [-Identity] <ADClaimType> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Force] 
        [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADClaimType cmdlet can be used to remove a claim type from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291082
    
    REMARKS
        To see the examples, type: "get-help Remove-ADClaimType -examples".
        For more information, type: "get-help Remove-ADClaimType -detailed".
        For technical information, type: "get-help Remove-ADClaimType -full".
        For online help, type: "get-help Remove-ADClaimType -online"
    
    
    
    NAME
        Remove-ADComputer
        
    SYNOPSIS
        Removes an Active Directory computer.
        
        
    SYNTAX
        Remove-ADComputer [-Identity] <ADComputer> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-Partition <String>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADComputer cmdlet removes an Active Directory computer.
        
        The Identity parameter specifies the Active Directory computer to remove. You can identify a computer by its 
        distinguished name Members (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. 
        You can also set the Identity parameter to a computer object variable, such as $<localComputerObject>, or you can 
        pass a computer object through the pipeline to the Identity parameter. For example, you can use the Get-ADComputer 
        cmdlet to retrieve a computer object and then pass the object through the pipeline to the Remove-ADComputer cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291083
        Add-ADComputerServiceAccount 
        Get-ADComputer 
        Get-ADComputerServiceAccount 
        New-ADComputer 
        Remove-ADComputerServiceAccount 
        Set-ADComputer 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADComputer -examples".
        For more information, type: "get-help Remove-ADComputer -detailed".
        For technical information, type: "get-help Remove-ADComputer -full".
        For online help, type: "get-help Remove-ADComputer -online"
    
    
    
    NAME
        Remove-ADComputerServiceAccount
        
    SYNOPSIS
        Removes one or more service accounts from a computer.
        
        
    SYNTAX
        Remove-ADComputerServiceAccount [-Identity] <ADComputer> [-ServiceAccount] <ADServiceAccount[]> [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] 
        [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADComputerServiceAccount cmdlet removes service accounts from an Active Directory computer.
        
        The Computer parameter specifies the Active Directory computer that contains the service accounts to remove. You 
        can identify a computer by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts 
        Manager (SAM) account name. You can also set the Computer parameter to a computer object variable, such as 
        $<localComputerobject>, or pass a computer object through the pipeline to the Computer parameter. For example, you 
        can use the Get-ADComputer cmdlet to retrieve a computer object and then pass the object through the pipeline to 
        the Remove-ADComputerServiceAccount cmdlet.
        
        The ServiceAccount parameter specifies the service accounts to remove. You can identify a service account by its 
        distinguished name (DN), GUID, security identifier (SID) or security accounts manager (SAM) account name. You can 
        also specify service account object variables, such as $<localServiceAccountObject>. If you are specifying more 
        than one service account, use a comma-separated list.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291084
        Add-ADComputerServiceAccount 
        Get-ADComputer 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADComputerServiceAccount -examples".
        For more information, type: "get-help Remove-ADComputerServiceAccount -detailed".
        For technical information, type: "get-help Remove-ADComputerServiceAccount -full".
        For online help, type: "get-help Remove-ADComputerServiceAccount -online"
    
    
    
    NAME
        Remove-ADDomainControllerPasswordReplicationPolicy
        
    SYNOPSIS
        Removes users, computers and groups from the allowed or denied list of a read-only domain controller password 
        replication policy.
        
        
    SYNTAX
        Remove-ADDomainControllerPasswordReplicationPolicy [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADDomainControllerPasswordReplicationPolicy cmdlet removes one or more users, computers and groups from 
        the allowed or denied list of a read-only domain controller (RODC) password replication policy.
        
        The Identity parameter specifies the RODC that uses the allowed and denied lists to apply the password replication 
        policy. You can identify a domain controller by its GUID, IPV4Address, global IPV6Address, or DNS host name. You 
        can also identify a domain controller by the name of the server object that represents the domain controller, the 
        Distinguished Name (DN) of the NTDS settings object or the server object, the GUID of the NTDS settings object or 
        the server object under the configuration partition, or the DN of the computer object that represents the domain 
        controller. You can also set the Identity parameter to a domain controller object variable, such as 
        $<localDomainControllerobject>, or pass a domain controller object through the pipeline to the Identity parameter. 
        For example, you can use the Get-ADDomainController cmdlet to retrieve a domain controller object and then pass 
        the object through the pipeline to the Remove-ADDomainControllerPasswordReplicationPolicy cmdlet. You must provide 
        a read-only domain controller.
        
        The AllowedList parameters specify the users, computers and groups to remove from the allowed list. Similarly, the 
        DeniedList parameter specifies the users, computers and groups to remove from the denied list. You must specify 
        either one or both of the AllowedList and DeniedList parameters. You can identify a user, computer or group by 
        distinguished name (DN), GUID, security identifier (SID) or security accounts manager (SAM) account name. You can 
        also specify user, computer or group variables, such as $<localUserObject>. If you are specifying more than one 
        item, use a comma-separated list.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291085
        Add-ADDomainControllerPasswordReplicationPolicy 
        Get-ADDomainController 
        Get-ADDomainControllerPasswordReplicationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADDomainControllerPasswordReplicationPolicy -examples".
        For more information, type: "get-help Remove-ADDomainControllerPasswordReplicationPolicy -detailed".
        For technical information, type: "get-help Remove-ADDomainControllerPasswordReplicationPolicy -full".
        For online help, type: "get-help Remove-ADDomainControllerPasswordReplicationPolicy -online"
    
    
    
    NAME
        Remove-ADFineGrainedPasswordPolicy
        
    SYNOPSIS
        Removes an Active Directory fine grained password policy.
        
        
    SYNTAX
        Remove-ADFineGrainedPasswordPolicy [-Identity] <ADFineGrainedPasswordPolicy> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADFineGrainedPasswordPolicy cmdlet removes an Active Directory fine grained password policy.
        
        The Identity parameter specifies the Active Directory fine grained password policy to remove. You can identify a 
        fine grained password policy by its distinguished name, or GUID. You can also set the Identity parameter to a fine 
        grained password object variable, such as $<localFineGrainedPasswordPolicyObject>, or you can pass a fine grained 
        password policy object through the pipeline to the Identity parameter. For example, you can use the 
        Get-ADFineGrainedPasswordPolicy cmdlet to retrieve a fine grained password policy object and then pass the object 
        through the pipeline to the Remove-ADFineGrainedPasswordPolicy cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291086
        Add-ADFineGrainedPasswordPolicySubject 
        Get-ADFineGrainedPasswordPolicy 
        Get-ADFineGrainedPasswordPolicySubject 
        New-ADFineGrainedPasswordPolicy 
        Remove-ADFineGrainedPasswordPolicySubject 
        Set-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADFineGrainedPasswordPolicy -examples".
        For more information, type: "get-help Remove-ADFineGrainedPasswordPolicy -detailed".
        For technical information, type: "get-help Remove-ADFineGrainedPasswordPolicy -full".
        For online help, type: "get-help Remove-ADFineGrainedPasswordPolicy -online"
    
    
    
    NAME
        Remove-ADFineGrainedPasswordPolicySubject
        
    SYNOPSIS
        Removes one or more users from a fine grained password policy.
        
        
    SYNTAX
        Remove-ADFineGrainedPasswordPolicySubject [-Identity] <ADFineGrainedPasswordPolicy> [-Subjects] <ADPrincipal[]> 
        [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADFineGrainedPasswordPolicySubject cmdlet removes one or more global security groups and users from a 
        fine grained password policy.
        
        The Identity parameter specifies the fine grained password policy. You can identify a fine grained password policy 
        by its distinguished name or GUID. You can also set the Identity parameter to a fine grained password policy 
        object variable, such as $<localFineGrainedPasswordPolicyObject>, or pass a fine grained password policy object 
        through the pipeline to the Identity parameter. For example, you can use the Get-ADFineGrainedPasswordPolicy 
        cmdlet to retrieve a fine grained password policy object and then pass the object through the pipeline to the 
        Remove-ADFineGrainedPasswordPolicySubject cmdlet.
        
        The Subjects parameter specifies the users and groups to remove from the password policy. You can identify a user 
        or group by its distinguished name (DN), GUID, security identifier (SID), security accounts manager (SAM) account 
        name, or canonical name. You can also specify user or group object variables, such as $<localUserObject>. If you 
        are specifying more than one user or group, use a comma-separated list.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291087
        Add-ADFineGrainedPasswordPolicySubject 
        Get-ADFineGrainedPasswordPolicy 
        Get-ADFineGrainedPasswordPolicySubject 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADFineGrainedPasswordPolicySubject -examples".
        For more information, type: "get-help Remove-ADFineGrainedPasswordPolicySubject -detailed".
        For technical information, type: "get-help Remove-ADFineGrainedPasswordPolicySubject -full".
        For online help, type: "get-help Remove-ADFineGrainedPasswordPolicySubject -online"
    
    
    
    NAME
        Remove-ADGroup
        
    SYNOPSIS
        Removes an Active Directory group.
        
        
    SYNTAX
        Remove-ADGroup [-Identity] <ADGroup> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADGroup cmdlet removes an Active Directory group object. You can use this cmdlet to remove security and 
        distribution groups.
        
        The Identity parameter specifies the Active Directory group to remove. You can identify a group by its 
        distinguished name (DN), GUID, security identifier (SID), Security Accounts Manager (SAM) account name, or 
        canonical name. You can also set the Identity parameter to an object variable such as $<localADGroupObject>, or 
        you can pass an object through the pipeline to the Identity parameter. For example, you can use the Get-ADGroup 
        cmdlet to retrieve a group object and then pass the object through the pipeline to the Remove-ADGroup cmdlet.
        
        If the ADGroup is being identified by its DN, the Partition parameter will be automatically determined.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        - The cmdlet is run from an Active Directory provider drive.
        
        - A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291088
        Add-ADGroupMember 
        Get-ADGroup 
        Get-ADGroupMember 
        New-ADGroup 
        Remove-ADGroupMember 
        Set-ADGroup 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADGroup -examples".
        For more information, type: "get-help Remove-ADGroup -detailed".
        For technical information, type: "get-help Remove-ADGroup -full".
        For online help, type: "get-help Remove-ADGroup -online"
    
    
    
    NAME
        Remove-ADGroupMember
        
    SYNOPSIS
        Removes one or more members from an Active Directory group.
        
        
    SYNTAX
        Remove-ADGroupMember [-Identity] <ADGroup> [-Members] <ADPrincipal[]> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADGroupMember cmdlet removes one or more users, groups, service accounts, or computers from an Active 
        Directory group.
        
        The Identity parameter specifies the Active Directory group that contains the members to remove. You can identify 
        a group by its distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) 
        account name. You can also specify a group object variable, such as $<localGroupObject>, or pass a group object 
        through the pipeline to the Identity parameter. For example, you can use the Get-ADGroup cmdlet to retrieve a 
        group object and then pass the object through the pipeline to the Remove-ADGroupMember cmdlet.
        
        The Members parameter specifies the users, computers and groups to remove from the group specified by the Identity 
        parameter. You can identify a user, computer or group by its distinguished name (DN), GUID, security identifier 
        (SID), or Security Accounts Manager (SAM) account name. You can also specify user, computer, and group object 
        variables, such as $<localUserObject>. If you are specifying more than one new member, use a comma-separated list. 
        You cannot pass user, computer, or group objects through the pipeline to this cmdlet. To remove user, computer, or 
        group objects from a group by using the pipeline, use the Remove-ADPrincipalGroupMembership cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291089
        Add-ADGroupMember 
        Add-ADPrincipalGroupMembership 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADPrincipalGroupMembership 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADGroupMember -examples".
        For more information, type: "get-help Remove-ADGroupMember -detailed".
        For technical information, type: "get-help Remove-ADGroupMember -full".
        For online help, type: "get-help Remove-ADGroupMember -online"
    
    
    
    NAME
        Remove-ADObject
        
    SYNOPSIS
        Removes an Active Directory object.
        
        
    SYNTAX
        Remove-ADObject [-Identity] <ADObject> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-IncludeDeletedObjects] [-Partition <String>] [-Recursive] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADObject cmdlet removes an Active Directory object. You can use this cmdlet to remove any type of 
        Active Directory object.
        
        The Identity parameter specifies the Active Directory object to remove. You can identify an object by its 
        distinguished name (DN) or GUID. You can also set the Identity parameter to an Active Directory object variable, 
        such as $<localObject>, or pass an object through the pipeline to the Identity parameter. For example, you can use 
        the Get-ADObject cmdlet to retrieve an object and then pass the object through the pipeline to the Remove-ADObject 
        cmdlet.
        
        If the object you specify to remove has child objects, you must specify the Recursive parameter.
        
        For AD LDS environments, the Partition parameter must be specified except when:     - Using a DN to identify 
        objects: the partition will be auto-generated from the DN.     - Running cmdlets from an Active Directory provider 
        drive: the current path will be used to set the partition.     - A default naming context or partition is 
        specified.
        
        To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the 
        Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291090
        Get-ADObject 
        New-ADObject 
        Set-ADObject 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADObject -examples".
        For more information, type: "get-help Remove-ADObject -detailed".
        For technical information, type: "get-help Remove-ADObject -full".
        For online help, type: "get-help Remove-ADObject -online"
    
    
    
    NAME
        Remove-ADOrganizationalUnit
        
    SYNOPSIS
        Removes an Active Directory organizational unit.
        
        
    SYNTAX
        Remove-ADOrganizationalUnit [-Identity] <ADOrganizationalUnit> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-Recursive] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADOrganizationalUnit cmdlet removes an Active Directory organizational unit.
        
        The Identity parameter specifies the organizational unit to remove. You can identify an organizational unit by its 
        distinguished name (DN) or GUID. You can also set the parameter to an organizational unit object variable, such as 
        $<localOrganizationUnitObject> or you can pass an object through the pipeline to the Identity parameter. For 
        example, you can use the Get-ADOrganizationalUnit cmdlet to retrieve the object and then pass the object through 
        the pipeline to the Remove-ADOrganizationalUnit cmdlet.
        
        If the object you specify to remove has child objects, you must specify the Recursive parameter.
        
        If the ProtectedFromAccidentalDeletion property of the organizational unit object is set to true, the cmdlet 
        returns a terminating error.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291091
        Get-ADOrganizationalUnit 
        New-ADOrganizationalUnit 
        Set-ADOrganizationalUnit 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADOrganizationalUnit -examples".
        For more information, type: "get-help Remove-ADOrganizationalUnit -detailed".
        For technical information, type: "get-help Remove-ADOrganizationalUnit -full".
        For online help, type: "get-help Remove-ADOrganizationalUnit -online"
    
    
    
    NAME
        Remove-ADPrincipalGroupMembership
        
    SYNOPSIS
        Removes a member from one or more Active Directory groups.
        
        
    SYNTAX
        Remove-ADPrincipalGroupMembership [-Identity] <ADPrincipal> [-MemberOf] <ADGroup[]> [-AuthType {Negotiate | 
        Basic}] [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADPrincipalGroupMembership cmdlet removes a user, group, computer, service account, or any other 
        account object from one or more Active Directory groups.
        
        The Identity parameter specifies the user, group, or computer to remove. You can identify the user, group, or 
        computer by its distinguished name (DN), GUID, security identifier (SID) or SAM account name. You can also specify 
        a user, group, or computer object variable, such as $<localGroupObject>, or pass an object through the pipeline to 
        the Identity parameter. For example, you can use the Get-ADUser cmdlet to retrieve a user object and then pass the 
        object through the pipeline to the Remove-ADPrincipalGroupMembership cmdlet. Similarly, you can use Get-ADGroup or 
        Get-ADComputer to get group, service account and computer objects to pass through the pipeline.
        
        This cmdlet collects all of the user, computer, service account and group objects from the pipeline, and then 
        removes these objects from the specified group by using one Active Directory operation.
        
        The MemberOf parameter specifies the groups that you want to remove the member from. You can identify a group by 
        its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You 
        can also specify group object variable, such as $<localGroupObject>. To specify more than one group, use a 
        comma-separated list. You cannot pass group objects through the pipeline to the MemberOf parameter. To remove a 
        member from groups that are passed through the pipeline, use the Remove-ADGroupMember cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291092
        Add-ADGroupMember 
        Add-ADPrincipalGroupMembership 
        Get-ADComputer 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADPrincipalGroupMembership 
        Get-ADServiceAccount 
        Get-ADUser 
        Remove-ADGroupMember 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADPrincipalGroupMembership -examples".
        For more information, type: "get-help Remove-ADPrincipalGroupMembership -detailed".
        For technical information, type: "get-help Remove-ADPrincipalGroupMembership -full".
        For online help, type: "get-help Remove-ADPrincipalGroupMembership -online"
    
    
    
    NAME
        Remove-ADReplicationSite
        
    SYNOPSIS
        Deletes the specified replication site object from Active Directory.
        
        
    SYNTAX
        Remove-ADReplicationSite [-Identity] <ADReplicationSite> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADReplicationSite deletes a specified replication site object from Active Directory. If domain 
        controllers are no longer needed in a network location, you can remove them from a site and then delete the site 
        object. Before deleting the site, you must remove all domain controllers from the site either by removing them 
        entirely or by moving them to a new location.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291093
        Get-ADReplicationSite 
        New-ADReplicationSite 
        Set-ADReplicationSite 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADReplicationSite -examples".
        For more information, type: "get-help Remove-ADReplicationSite -detailed".
        For technical information, type: "get-help Remove-ADReplicationSite -full".
        For online help, type: "get-help Remove-ADReplicationSite -online"
    
    
    
    NAME
        Remove-ADReplicationSiteLink
        
    SYNOPSIS
        Deletes an Active Directory site link used to manage replication.
        
        
    SYNTAX
        Remove-ADReplicationSiteLink [-Identity] <ADReplicationSiteLink> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADReplicationSiteLink cmdlet removes a site link object used to manage replication traffic between two 
        sites in your Active Directory installation. For more information on site links, see the following topic "Creating 
        a Site Link Design" in the TechNet Library: http://go.microsoft.com/fwlink/?LinkId=221870
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291094
        Get-ADReplicationSiteLink 
        New-ADReplicationSiteLink 
        Set-ADReplicationSiteLink 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADReplicationSiteLink -examples".
        For more information, type: "get-help Remove-ADReplicationSiteLink -detailed".
        For technical information, type: "get-help Remove-ADReplicationSiteLink -full".
        For online help, type: "get-help Remove-ADReplicationSiteLink -online"
    
    
    
    NAME
        Remove-ADReplicationSiteLinkBridge
        
    SYNOPSIS
        Deletes the specified replication site link bridge from Active Directory.
        
        
    SYNTAX
        Remove-ADReplicationSiteLinkBridge [-Identity] <ADReplicationSiteLinkBridge> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADReplicationSiteLinkBridge object deletes the specified replication site link bridge from Active 
        Directory.  A site link bridge connects two or more site links and enables transitivity between site links. Each 
        site link in a bridge must have a site in common with another site link in the bridge.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291095
        Get-ADReplicationSiteLinkBridge 
        New-ADReplicationSiteLinkBridge 
        Set-ADReplicationSiteLinkBridge 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADReplicationSiteLinkBridge -examples".
        For more information, type: "get-help Remove-ADReplicationSiteLinkBridge -detailed".
        For technical information, type: "get-help Remove-ADReplicationSiteLinkBridge -full".
        For online help, type: "get-help Remove-ADReplicationSiteLinkBridge -online"
    
    
    
    NAME
        Remove-ADReplicationSubnet
        
    SYNOPSIS
        Deletes the specified Active Directory replication subnet object from the directory.
        
        
    SYNTAX
        Remove-ADReplicationSubnet [-Identity] <ADReplicationSubnet> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADReplicationSubnet cmdlet deletes the specified Active Directory replication subnet object from the 
        directory. Subnet objects (class subnet) define network subnets in Active Directory. A network subnet is a segment 
        of a TCP/IP network to which a set of logical IP addresses is assigned. Subnets group computers in a way that 
        identifies their physical proximity on the network. Subnet objects in Active Directory are used to map computers 
        to sites.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291096
        Get-ADReplicationSubnet 
        New-ADReplicationSubnet 
        Set-ADReplicationSubnet 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADReplicationSubnet -examples".
        For more information, type: "get-help Remove-ADReplicationSubnet -detailed".
        For technical information, type: "get-help Remove-ADReplicationSubnet -full".
        For online help, type: "get-help Remove-ADReplicationSubnet -online"
    
    
    
    NAME
        Remove-ADResourceProperty
        
    SYNOPSIS
        Removes a resource property from Active Directory.
        
        
    SYNTAX
        Remove-ADResourceProperty [-Identity] <ADResourceProperty> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADResourceProperty cmdlet removes a resource property from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291097
    
    REMARKS
        To see the examples, type: "get-help Remove-ADResourceProperty -examples".
        For more information, type: "get-help Remove-ADResourceProperty -detailed".
        For technical information, type: "get-help Remove-ADResourceProperty -full".
        For online help, type: "get-help Remove-ADResourceProperty -online"
    
    
    
    NAME
        Remove-ADResourcePropertyList
        
    SYNOPSIS
        Removes one or more resource property lists from Active Directory.
        
        
    SYNTAX
        Remove-ADResourcePropertyList [-Identity] <ADResourcePropertyList> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADResourcePropertyList cmdlet removes one or more claim lists from Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291098
    
    REMARKS
        To see the examples, type: "get-help Remove-ADResourcePropertyList -examples".
        For more information, type: "get-help Remove-ADResourcePropertyList -detailed".
        For technical information, type: "get-help Remove-ADResourcePropertyList -full".
        For online help, type: "get-help Remove-ADResourcePropertyList -online"
    
    
    
    NAME
        Remove-ADResourcePropertyListMember
        
    SYNOPSIS
        Removes one or more resource properties from a resource property list in Active Directory.
        
        
    SYNTAX
        Remove-ADResourcePropertyListMember [-Identity] <ADResourcePropertyList> [-Members] <ADResourceProperty[]> 
        [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADResourcePropertyListMember cmdlet can be used to remove one or more resource properties from a 
        resource property list in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291099
    
    REMARKS
        To see the examples, type: "get-help Remove-ADResourcePropertyListMember -examples".
        For more information, type: "get-help Remove-ADResourcePropertyListMember -detailed".
        For technical information, type: "get-help Remove-ADResourcePropertyListMember -full".
        For online help, type: "get-help Remove-ADResourcePropertyListMember -online"
    
    
    
    NAME
        Remove-ADServiceAccount
        
    SYNOPSIS
        Remove an Active Directory managed service account or group managed service account object.
        
        
    SYNTAX
        Remove-ADServiceAccount [-Identity] <ADServiceAccount> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADServiceAccount cmdlet removes an Active Directory managed service account (MSA). This cmdlet does not 
        make changes to any computers that use the MSA. After this operation, the MSA no longer exists in the directory, 
        but computers will still be configured to use the MSA.
        
        The Identity parameter specifies the Active Directory MSA to remove. You can identify a MSA by its distinguished 
        name (DN), GUID, security identifier (SID) or security accounts manager (SAM) account name. You can also set the 
        Identity parameter to a MSA object variable, such as $<localSerivceAccountObject>, or you can pass a MSA object 
        through the pipeline to the Identity parameter. For example, you can use the Get-ADServiceAccount cmdlet to 
        retrieve a MSA object and then pass the object through the pipeline to the Remove-ADServiceAccount cmdlet.
        
        Note: Removing the service account is a different operation than uninstalling the service account locally.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291100
        Get-ADServiceAccount 
        Install-ADServiceAccount 
        New-ADServiceAccount 
        Set-ADServiceAccount 
        Uninstall-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADServiceAccount -examples".
        For more information, type: "get-help Remove-ADServiceAccount -detailed".
        For technical information, type: "get-help Remove-ADServiceAccount -full".
        For online help, type: "get-help Remove-ADServiceAccount -online"
    
    
    
    NAME
        Remove-ADUser
        
    SYNOPSIS
        Removes an Active Directory user.
        
        
    SYNTAX
        Remove-ADUser [-Identity] <ADUser> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Remove-ADUser cmdlet removes an Active Directory user.
        
        The Identity parameter specifies the Active Directory user to remove. You can identify a user by its distinguished 
        name (DN), GUID, security identifier (SID) or security accounts manager (SAM) account name. You can also set the 
        Identity parameter to a user object variable, such as $<localUserObject>, or you can pass a user object through 
        the pipeline to the Identity parameter. For example, you can use the Get-ADUser cmdlet to retrieve a user object 
        and then pass the object through the pipeline to the Remove-ADUser cmdlet.
        
        If the ADUser is being identified by its DN, the Partition parameter will be automatically determined.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291101
        Get-ADUser 
        New-ADUser 
        Set-ADUser 
    
    REMARKS
        To see the examples, type: "get-help Remove-ADUser -examples".
        For more information, type: "get-help Remove-ADUser -detailed".
        For technical information, type: "get-help Remove-ADUser -full".
        For online help, type: "get-help Remove-ADUser -online"
    
    
    
    NAME
        Rename-ADObject
        
    SYNOPSIS
        Changes the name of an Active Directory object.
        
        
    SYNTAX
        Rename-ADObject [-Identity] <ADObject> [-NewName] <String> [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Rename-ADObject cmdlet renames an Active Directory object. This cmdlet sets the Name property of an Active 
        Directory object that has an LDAP Display Name (ldapDisplayName) of "name". To modify the given name, surname and 
        other name of a user, use the Set-ADUser cmdlet. To modify the Security Accounts Manager (SAM) account name of a 
        user, computer, or group, use the Set-ADUser, Set-ADComputer or Set-ADGroup cmdlet.
        
        The Identity parameter specifies the object to rename. You can identify an object or container by its 
        distinguished name (DN) or GUID. You can also set the Identity parameter to an object variable such as 
        $<localObject>, or you can pass an object through the pipeline to the Identity parameter. For example, you can use 
        the Get-ADObject cmdlet to retrieve an object and then pass the object through the pipeline to the Rename-ADObject 
        cmdlet. You can also use the Get-ADGroup, Get-ADUser, Get-ADComputer, Get-ADServiceAccount, 
        Get-ADOrganizationalUnit and Get-ADFineGrainedPasswordPolicy cmdlets to get an object that you can pass through 
        the pipeline to this cmdlet.
        
        The NewName parameter defines the new name for the object and must be specified.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291102
        Get-ADObject 
        Move-ADObject 
        New-ADObject 
        Remove-ADObject 
        Restore-ADObject 
        Set-ADObject 
        
    
    REMARKS
        To see the examples, type: "get-help Rename-ADObject -examples".
        For more information, type: "get-help Rename-ADObject -detailed".
        For technical information, type: "get-help Rename-ADObject -full".
        For online help, type: "get-help Rename-ADObject -online"
    
    
    
    NAME
        Revoke-ADAuthenticationPolicySiloAccess
        
    SYNOPSIS
        Revokes membership in an authentication policy silo for the specified account.
        
        
    SYNTAX
        Revoke-ADAuthenticationPolicySiloAccess [-Identity] <ADAuthenticationPolicySilo> [-Account] <ADAccount> [-AuthType 
        {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Revoke-ADAuthenticationPolicySiloAccess cmdlet revokes the membership in an authentication policy silo for one 
        or more accounts in Active Directoryr Domain Services.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy silo that contains the 
        user accounts to remove. You can identify an authentication policy silo by its distinguished name (DN), GUID or 
        name. You can also use the Identity parameter to specify a variable that contains an authentication policy silo 
        object, or you can use the pipeline operator to pass an authentication policy object to the Identity parameter.
        
        The Account parameter specifies the users, computers and service accounts to remove from the authentication policy 
        silo specified by the Identity parameter. You can identify a user, computer or service account by its DN, GUID, 
        security identifier (SID), or Security Accounts Manager (SAM) account name. You can also use the Account parameter 
        to specify a variable that contains user, computer, and service account objects.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=296772
        Grant-ADAuthenticationPolicySiloAccess 
    
    REMARKS
        To see the examples, type: "get-help Revoke-ADAuthenticationPolicySiloAccess -examples".
        For more information, type: "get-help Revoke-ADAuthenticationPolicySiloAccess -detailed".
        For technical information, type: "get-help Revoke-ADAuthenticationPolicySiloAccess -full".
        For online help, type: "get-help Revoke-ADAuthenticationPolicySiloAccess -online"
    
    
    
    NAME
        Reset-ADServiceAccountPassword
        
    SYNOPSIS
        Resets the password for a standalone managed service account. Reset is not supported for group managed service 
        accounts.
        
        
    SYNTAX
        Reset-ADServiceAccountPassword [-Identity] <ADServiceAccount> [-AuthType {Negotiate | Basic}] [-Partition 
        <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Reset-ADServiceAccountPassword cmdlet resets the password for the standalone managed service account (MSA) on 
        the local computer. This cmdlet needs to be run on the computer where the standalone MSA is installed.
        
        The Identity parameter specifies the Active Directory standalone MSA that receives the password reset. You can 
        identify a MSA by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) 
        account name. You can also set the Identity parameter to a MSA object variable, such as 
        $<localServiceAccountObject>, or pass a MSA object through the pipeline to the Identity parameter. For example, 
        you can use the Get-ADServiceAccount cmdlet to retrieve a standalone MSA object and then pass the object through 
        the pipeline to the Reset-ADServiceAccountPassword cmdlet.
        
        Note: When you reset the password for a computer, you also reset all of the standalone MSA passwords for that 
        computer.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291103
        Get-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Reset-ADServiceAccountPassword -examples".
        For more information, type: "get-help Reset-ADServiceAccountPassword -detailed".
        For technical information, type: "get-help Reset-ADServiceAccountPassword -full".
        For online help, type: "get-help Reset-ADServiceAccountPassword -online"
    
    
    
    NAME
        Restore-ADObject
        
    SYNOPSIS
        Restores an Active Directory object.
        
        
    SYNTAX
        Restore-ADObject [-Identity] <ADObject> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-NewName 
        <String>] [-Partition <String>] [-PassThru] [-Server <String>] [-TargetPath <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Restore-ADObject cmdlet restores a deleted Active Directory object.
        
        The NewName parameter specifies the new name for the restored object. If the NewName parameter is not specified, 
        the value of the Active Directory attribute with an LDAP display name of "msDS-lastKnownRDN" is used. The 
        TargetPath parameter specifies the new location for the restored object. If the TargetPath is not specified, the 
        value of the Active Directory attribute with an LDAP display name of "lastKnownParent" is used.
        
        The Identity parameter specifies the Active Directory object to restore. You can identify an object by its 
        distinguished name (DN) or GUID. You can also set the Identity parameter to an object variable such as 
        $<localObject>, or you can pass an object through the pipeline to the Identity parameter. For example, you can use 
        the Get-ADObject cmdlet to retrieve a deleted object by specifying the IncludeDeletedObjects parameter. You can 
        then pass the object through the pipeline to the Restore-ADObject cmdlet.
        
        Note: You can get the distinguished names of deleted objects by using the Get-ADObject cmdlet with the 
        -IncludedeDeletedObjects parameter specified.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291104
        Get-ADObject 
        Move-ADObject 
        New-ADObject 
        Remove-ADObject 
        Rename-ADObject 
        Set-ADObject 
        
    
    REMARKS
        To see the examples, type: "get-help Restore-ADObject -examples".
        For more information, type: "get-help Restore-ADObject -detailed".
        For technical information, type: "get-help Restore-ADObject -full".
        For online help, type: "get-help Restore-ADObject -online"
    
    
    
    NAME
        Search-ADAccount
        
    SYNOPSIS
        Gets Active Directory user, computer, or service accounts.
        
        
    SYNTAX
        Search-ADAccount [<CommonParameters>]
        
        
    DESCRIPTION
        The Search-ADAccount cmdlet retrieves one or more user, computer, or service accounts that meet the criteria 
        specified by the parameters. Search criteria include account and password status. For example, you can search for 
        all accounts that have expired by specifying the AccountExpired parameter. Similarly, you can search for all 
        accounts with an expired password by specifying the PasswordExpired parameter. You can limit the search to user 
        accounts by specifying the UsersOnly parameter. Similarly, when you specify the ComputersOnly parameter, the 
        cmdlet only retrieves computer accounts.
        
        Some search parameters, such as AccountExpiring and AccountInactive use a default time that you can change by 
        specifying the DateTime or TimeSpan parameter. The DateTime parameter specifies a distinct time. The TimeSpan 
        parameter specifies a time range from the current time. For example, to search for all accounts that expire in 10 
        days, specify the AccountExpiring and TimeSpan parameter and set the value of TimeSpan to "10.00:00:00". To search 
        for all accounts that expire before December 31, 2012, set the DateTime parameter to "12/31/2012".
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291105
        Clear-ADAccountExpiration 
        Disable-ADAccount 
        Enable-ADAccount 
        Get-ADAccountResultantPasswordReplicationPolicy 
        Set-ADAccountControl 
        Set-ADAccountExpiration 
        Set-ADAccountPassword 
        Unlock-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Search-ADAccount -examples".
        For more information, type: "get-help Search-ADAccount -detailed".
        For technical information, type: "get-help Search-ADAccount -full".
        For online help, type: "get-help Search-ADAccount -online"
    
    
    
    NAME
        Set-ADAccountAuthenticationPolicySilo
        
    SYNOPSIS
        Modifies the authentication policy or authentication policy silo of an account.
        
        
    SYNTAX
        Set-ADAccountAuthenticationPolicySilo [-Identity] <ADAccount> [-AuthenticationPolicy <ADAuthenticationPolicy>] 
        [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-Credential 
        <PSCredential>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAccountAuthenticationPolicySilo cmdlet modifies the authentication policy or authentication policy silo 
        of an account. This cmdlet assigns authentication policy silo objects and authentication policy object to an 
        Active Directory Domain Services account. In order for the account to belong to an authentication policy silo, you 
        must use the Grant-ADAuthenticationPolicySiloAccess cmdlet to grant access to the object.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy to modify. You can 
        identify an authentication policy by its distinguished name (DN), GUID or name. You can also use the Identity 
        parameter to specify a variable that contains an authentication policy object, or you can use the pipeline 
        operator to pass an authentication policy object to the Identity parameter.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=313379
        Grant-ADAuthenticationPolicySiloAccess 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAccountAuthenticationPolicySilo -examples".
        For more information, type: "get-help Set-ADAccountAuthenticationPolicySilo -detailed".
        For technical information, type: "get-help Set-ADAccountAuthenticationPolicySilo -full".
        For online help, type: "get-help Set-ADAccountAuthenticationPolicySilo -online"
    
    
    
    NAME
        Set-ADAccountControl
        
    SYNOPSIS
        Modifies user account control (UAC) values for an Active Directory account.
        
        
    SYNTAX
        Set-ADAccountControl [-Identity] <ADAccount> [-AccountNotDelegated <Boolean>] [-AllowReversiblePasswordEncryption 
        <Boolean>] [-AuthType {Negotiate | Basic}] [-CannotChangePassword <Boolean>] [-Credential <PSCredential>] 
        [-DoesNotRequirePreAuth <Boolean>] [-Enabled <Boolean>] [-HomedirRequired <Boolean>] [-MNSLogonAccount <Boolean>] 
        [-Partition <String>] [-PassThru] [-PasswordNeverExpires <Boolean>] [-PasswordNotRequired <Boolean>] [-Server 
        <String>] [-TrustedForDelegation <Boolean>] [-TrustedToAuthForDelegation <Boolean>] [-UseDESKeyOnly <Boolean>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAccountControl cmdlet modifies the user account control (UAC) values for an Active Directory user or 
        computer account. UAC values are represented by cmdlet parameters. For example, set the PasswordExpired parameter 
        to change whether an account is expired and to modify the ADS_UF_PASSWORD_EXPIRED UAC value.
        
        The Identity parameter specifies the Active Directory account to modify.
        
        You can identify an account by its distinguished name (DN), GUID, security identifier (SID) or security accounts 
        manager (SAM) account name. You can also set the Identity parameter to an object variable such as 
        $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity parameter. For 
        example, you can use the Search-ADAccount cmdlet to retrieve an account object and then pass the object through 
        the pipeline to the Set-ADAccountControl cmdlet. Similarly, you can use Get-ADUser, Get-ADComputer or 
        Get-ADServiceAccount cmdlets to retrieve account objects that you can pass through the pipeline to this cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291106
        Get-ADComputer 
        Get-ADServiceAccount 
        Get-ADUser 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAccountControl -examples".
        For more information, type: "get-help Set-ADAccountControl -detailed".
        For technical information, type: "get-help Set-ADAccountControl -full".
        For online help, type: "get-help Set-ADAccountControl -online"
    
    
    
    NAME
        Set-ADAccountExpiration
        
    SYNOPSIS
        Sets the expiration date for an Active Directory account.
        
        
    SYNTAX
        Set-ADAccountExpiration [-Identity] <ADAccount> [[-DateTime] <DateTime>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Partition <String>] [-PassThru] [-Server <String>] [-TimeSpan <TimeSpan>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAccountExpiration cmdlet sets the expiration time for a user, computer or service account. To specify an 
        exact time, use the DateTime parameter. To specify a time period from the current time, use the TimeSpan parameter.
        
        The Identity parameter specifies the Active Directory account to modify.
        
        You can identify an account by its distinguished name (DN), GUID, security identifier (SID), or Security Accounts 
        Manager (SAM) account name. You can also set the Identity parameter to an object variable such as 
        $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity parameter. For 
        example, you can use the Search-ADAccount cmdlet to retrieve an account object and then pass the object through 
        the pipeline to the Set-ADAccountExpiration cmdlet. Similarly, you can use Get-ADUser, Get-ADComputer or 
        Get-ADServiceAccount cmdlets to retrieve account objects that you can pass through the pipeline to this cmdlet.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291107
        Clear-ADAccountExpiration 
        Get-ADComputer 
        Get-ADServiceAccount 
        Get-ADUser 
        Search-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAccountExpiration -examples".
        For more information, type: "get-help Set-ADAccountExpiration -detailed".
        For technical information, type: "get-help Set-ADAccountExpiration -full".
        For online help, type: "get-help Set-ADAccountExpiration -online"
    
    
    
    NAME
        Set-ADAccountPassword
        
    SYNOPSIS
        Modifies the password of an Active Directory account.
        
        
    SYNTAX
        Set-ADAccountPassword [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-NewPassword <SecureString>] [-OldPassword <SecureString>] [-Partition <String>] [-PassThru] [-Reset] [-Server 
        <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAccountPassword cmdlet sets the password for a user, computer or service account.
        
        The Identity parameter specifies the Active Directory account to modify.
        
        You can identify an account by its distinguished name (DN), GUID, security identifier (SID) or security accounts 
        manager (SAM) account name. You can also set the Identity parameter to an object variable such as 
        $<localADAccountObject>, or you can pass an object through the pipeline to the Identity parameter. For example, 
        you can use the Search-ADAccount cmdlet to retrieve an account object and then pass the object through the 
        pipeline to the Set-ADAccountPassword cmdlet. Similarly, you can use Get-ADUser, Get-ADComputer or 
        Get-ADServiceAccount, for standalone MSAs, cmdlets to retrieve account objects that you can pass through the 
        pipeline to this cmdlet.
        
        Note: Group MSAs cannot set password since they are changed at predetermined intervals.
        
        You must set the OldPassword and the NewPassword parameters to set the password unless you specify the Reset 
        parameter. When you specify the Reset parameter, the password is set to the NewPassword value that you provide and 
        the OldPassword parameter is not required.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291108
        Get-ADComputer 
        Get-ADServiceAccount 
        Get-ADUser 
        Search-ADAccount 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAccountPassword -examples".
        For more information, type: "get-help Set-ADAccountPassword -detailed".
        For technical information, type: "get-help Set-ADAccountPassword -full".
        For online help, type: "get-help Set-ADAccountPassword -online"
    
    
    
    NAME
        Set-ADAuthenticationPolicy
        
    SYNOPSIS
        Modifies an Active Directory Domain Services authentication policy object.
        
        
    SYNTAX
        Set-ADAuthenticationPolicy [-Identity] <ADAuthenticationPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-ComputerAllowedToAuthenticateTo <String>] [-ComputerTGTLifetimeMins <Int32>] [-Credential 
        <PSCredential>] [-Description <String>] [-Enforce <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion 
        <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-ServiceAllowedToAuthenticateFrom 
        <String>] [-ServiceAllowedToAuthenticateTo <String>] [-ServiceTGTLifetimeMins <Int32>] 
        [-UserAllowedToAuthenticateFrom <String>] [-UserAllowedToAuthenticateTo <String>] [-UserTGTLifetimeMins <Int32>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADAuthenticationPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADAuthenticationPolicy> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAuthenticationPolicy cmdlet modifies the properties of an Active Directoryr Domain Services 
        authentication policy. Commonly used attributes of the object can be specified by the parameters of this cmdlet.  
        Property values that are not associated with cmdlet parameters can be modified by using the Add, Replace, Clear 
        and Remove parameters.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy to modify. You can 
        specify an authentication policy object by using a distinguished name (DN), a GUID, or a name. You can also use 
        the Identity parameter to specify a variable that contains an authentication policy object, or you can use the 
        pipeline operator to pass an authentication policy object to the Identity parameter. To get an authentication 
        policy object, use the Get-ADAuthenticationPolicy cmdlet.
        
        Use the Instance parameter to specify an authentication policy object to use as a template for the object being 
        modified. Do not specify both the Instance parameter and the Identity parameter.
        
        For more information about how the Instance concept is used in Active Directory Domain Services cmdlets, see 
        about_ActiveDirectory_Instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=313377
        Get-ADAuthenticationPolicy 
        New-ADAuthenticationPolicy 
        Remove-ADAuthenticationPolicy 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAuthenticationPolicy -examples".
        For more information, type: "get-help Set-ADAuthenticationPolicy -detailed".
        For technical information, type: "get-help Set-ADAuthenticationPolicy -full".
        For online help, type: "get-help Set-ADAuthenticationPolicy -online"
    
    
    
    NAME
        Set-ADAuthenticationPolicySilo
        
    SYNOPSIS
        Modifies an Active Directory Domain Services authentication policy silo object.
        
        
    SYNTAX
        Set-ADAuthenticationPolicySilo [-Identity] <ADAuthenticationPolicySilo> [-Add <Hashtable>] [-AuthType {Negotiate | 
        Basic}] [-Clear <String[]>] [-ComputerAuthenticationPolicy <ADAuthenticationPolicy>] [-Credential <PSCredential>] 
        [-Description <String>] [-Enforce <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-ServiceAuthenticationPolicy <ADAuthenticationPolicy>] 
        [-UserAuthenticationPolicy <ADAuthenticationPolicy>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADAuthenticationPolicySilo [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADAuthenticationPolicySilo> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADAuthenticationPolicySilo cmdlet modifies the properties of an Active Directoryr Domain Services 
        authentication policy silo. You can modify commonly used property values by using the cmdlet parameters. Property 
        values that are not associated with cmdlet parameters can be modified by using the Add, Replace, Clear and Remove 
        parameters.
        
        The Identity parameter specifies the Active Directory Domain Services authentication policy to modify. You can 
        specify an authentication policy object by using a distinguished name (DN), a GUID, or a name. You can also use 
        the Identity parameter to specify a variable that contains an authentication policy object, or you can use the 
        pipeline operator to pass an authentication policy object to the Identity parameter. To get an authentication 
        policy object, use the Get-ADAuthenticationPolicycmdlet.
        
        Use the Instance parameter to specify an authentication policy object to use as a template for the object being 
        modified. Do not specify both the Instance parameter and the Identity parameter.
        
        For more information about how the Instance concept is used in Active Directory Domain Services cmdlets, see 
        about_ActiveDirectory_Instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=298364
        Get-ADAuthenticationPolicySilo 
        New-ADAuthenticationPolicySilo 
        Remove-ADAuthenticationPolicySilo 
    
    REMARKS
        To see the examples, type: "get-help Set-ADAuthenticationPolicySilo -examples".
        For more information, type: "get-help Set-ADAuthenticationPolicySilo -detailed".
        For technical information, type: "get-help Set-ADAuthenticationPolicySilo -full".
        For online help, type: "get-help Set-ADAuthenticationPolicySilo -online"
    
    
    
    NAME
        Set-ADCentralAccessPolicy
        
    SYNOPSIS
        Modifies a central access policy in Active Directory.
        
        
    SYNTAX
        Set-ADCentralAccessPolicy [-Identity] <ADCentralAccessPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADCentralAccessPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADCentralAccessPolicy> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADCentralAccessPolicy cmdlet can be used to modify a central access policy in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291109
    
    REMARKS
        To see the examples, type: "get-help Set-ADCentralAccessPolicy -examples".
        For more information, type: "get-help Set-ADCentralAccessPolicy -detailed".
        For technical information, type: "get-help Set-ADCentralAccessPolicy -full".
        For online help, type: "get-help Set-ADCentralAccessPolicy -online"
    
    
    
    NAME
        Set-ADCentralAccessRule
        
    SYNOPSIS
        Modifies a central access rule in Active Directory.
        
        
    SYNTAX
        Set-ADCentralAccessRule [-Identity] <ADCentralAccessRule> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-CurrentAcl <String>] [-Description <String>] [-PassThru] 
        [-ProposedAcl <String>] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] 
        [-ResourceCondition <String>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADCentralAccessRule [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADCentralAccessRule> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADCentralAccessRule cmdlet can be used to modify a central access rule in a central access policy that is 
        stored in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291110
    
    REMARKS
        To see the examples, type: "get-help Set-ADCentralAccessRule -examples".
        For more information, type: "get-help Set-ADCentralAccessRule -detailed".
        For technical information, type: "get-help Set-ADCentralAccessRule -full".
        For online help, type: "get-help Set-ADCentralAccessRule -online"
    
    
    
    NAME
        Set-ADClaimTransformLink
        
    SYNOPSIS
        Applies a claims transformation to one or more cross-forest trust relationships in Active Directory.
        
        
    SYNTAX
        Set-ADClaimTransformLink [-Identity] <ADTrust> [-Policy] <ADClaimTransformPolicy> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-PassThru] [-Server <String>] -TrustRole {Trusted | Trusting} [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADClaimTransformLink cmdlet can be used to apply a claims transformation to one or more cross-forest trust 
        relationships in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291111
    
    REMARKS
        To see the examples, type: "get-help Set-ADClaimTransformLink -examples".
        For more information, type: "get-help Set-ADClaimTransformLink -detailed".
        For technical information, type: "get-help Set-ADClaimTransformLink -full".
        For online help, type: "get-help Set-ADClaimTransformLink -online"
    
    
    
    NAME
        Set-ADClaimTransformPolicy
        
    SYNOPSIS
        Sets the properties of a claims transformation policy in Active Directory.
        
        
    SYNTAX
        Set-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        -DenyAll [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        -AllowAll [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        -AllowAllExcept <ADClaimType[]> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        -DenyAllExcept <ADClaimType[]> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimTransformPolicy [-Identity] <ADClaimTransformPolicy> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Rule <String>] 
        [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimTransformPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADClaimTransformPolicy> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADClaimTransformPolicy cmdlet can be used to set the properties of a claims transformation policy in 
        Active Directory. A claims transformation policy object contains a set of  rules authored in the transformation 
        rule language.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291112
    
    REMARKS
        To see the examples, type: "get-help Set-ADClaimTransformPolicy -examples".
        For more information, type: "get-help Set-ADClaimTransformPolicy -detailed".
        For technical information, type: "get-help Set-ADClaimTransformPolicy -full".
        For online help, type: "get-help Set-ADClaimTransformPolicy -online"
    
    
    
    NAME
        Set-ADClaimType
        
    SYNOPSIS
        Modify a claim type in Active Directory.
        
        
    SYNTAX
        Set-ADClaimType [-Identity] <ADClaimType> [-Add <Hashtable>] [-AppliesToClasses <String[]>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] 
        [-Enabled <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace 
        <Hashtable>] [-RestrictValues <Boolean>] [-Server <String>] [-SuggestedValues <ADSuggestedValueEntry[]>] 
        -SourceAttribute <String> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimType [-Identity] <ADClaimType> [-Add <Hashtable>] [-AppliesToClasses <String[]>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] 
        [-Enabled <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace 
        <Hashtable>] [-RestrictValues <Boolean>] [-Server <String>] [-SuggestedValues <ADSuggestedValueEntry[]>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimType [-Identity] <ADClaimType> [-Add <Hashtable>] [-AppliesToClasses <String[]>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] 
        [-Enabled <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace 
        <Hashtable>] [-RestrictValues <Boolean>] [-Server <String>] -SourceOID <String> [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Set-ADClaimType [-Identity] <ADClaimType> [-Add <Hashtable>] [-AppliesToClasses <String[]>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] 
        [-Enabled <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace 
        <Hashtable>] [-RestrictValues <Boolean>] [-Server <String>] [-SuggestedValues <ADSuggestedValueEntry[]>] 
        -SourceTransformPolicy [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADClaimType [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        -Instance <ADClaimType> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADClaimType cmdlet can be used to modify a claim type in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291113
    
    REMARKS
        To see the examples, type: "get-help Set-ADClaimType -examples".
        For more information, type: "get-help Set-ADClaimType -detailed".
        For technical information, type: "get-help Set-ADClaimType -full".
        For online help, type: "get-help Set-ADClaimType -online"
    
    
    
    NAME
        Set-ADComputer
        
    SYNOPSIS
        Modifies an Active Directory computer object.
        
        
    SYNTAX
        Set-ADComputer [-Identity] <ADComputer> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] [-Add 
        <Hashtable>] [-AllowReversiblePasswordEncryption <Boolean>] [-AuthenticationPolicy <ADAuthenticationPolicy>] 
        [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-CannotChangePassword 
        <Boolean>] [-Certificates <Hashtable>] [-ChangePasswordAtLogon <Boolean>] [-Clear <String[]>] 
        [-CompoundIdentitySupported <Boolean>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName 
        <String>] [-DNSHostName <String>] [-Enabled <Boolean>] [-HomePage <String>] [-KerberosEncryptionType {None | DES | 
        RC4 | AES128 | AES256}] [-Location <String>] [-ManagedBy <ADPrincipal>] [-OperatingSystem <String>] 
        [-OperatingSystemHotfix <String>] [-OperatingSystemServicePack <String>] [-OperatingSystemVersion <String>] 
        [-Partition <String>] [-PassThru] [-PasswordNeverExpires <Boolean>] [-PasswordNotRequired <Boolean>] 
        [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] [-Remove <Hashtable>] [-Replace <Hashtable>] 
        [-SAMAccountName <String>] [-Server <String>] [-ServicePrincipalNames <Hashtable>] [-TrustedForDelegation 
        <Boolean>] [-UserPrincipalName <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADComputer [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        -Instance <ADComputer> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADComputer cmdlet modifies the properties of an Active Directory computer object. You can modify commonly 
        used property values by using the cmdlet parameters. Property values that are not associated with cmdlet 
        parameters can be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory computer to modify. You can identify a computer by its 
        distinguished name Members (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. 
        You can also set the Identity parameter to an object variable such as $<localComputerObject>, or you can pass an 
        object through the pipeline to the Identity parameter. For example, you can use the Get-ADComputer cmdlet to 
        retrieve a computer object and then pass the object through the pipeline to Set-ADComputer.
        
        The Instance parameter provides a way to update a computer by applying the changes made to a copy of the computer 
        object. When you set the Instance parameter to a copy of an Active Directory computer object that has been 
        modified, the Set-ADComputer cmdlet makes the same changes to the original computer object. To get a copy of the 
        object to modify, use the Get-ADComputer object. When you specify the Instance parameter you should not pass the 
        identity parameter. For more information about the Instance parameter, see the Instance parameter description. For 
        more information about how the instance concept is used in Active Directory cmdlets, see 
        about_ActiveDirectory_Instance.
        
        The following examples show how to modify the Location property of a computer object by using three methods:
        
        -By specifying the Identity and the Location parameters
        
        -By passing a computer object through the pipeline and specifying the Location parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the Location property for the saraDavisLaptop computer by using the Identity and Location 
        parameters.
        
        Set-ADComputer  -Identity SaraDavisLaptop  -Location  "W4013"
        
        Method 2: Modify the Location property for the saraDavisLaptop computer by passing the computer object through the 
        pipeline and specifying the Location parameter.
        
        Get-ADComputer SaraDavisLaptop | Set-ADcomputer -Location  "W4013"
        
        Method 3:  Modify the Location property for the saraDavisLaptop computer by using the Windows PowerShell command 
        line to modify a local instance of the computer object. Then set the Instance parameter to the local instance.
        
        $computer = Get-ADcomputer saraDavisLaptop
        
        $computer.Location=  "W4013"
        
        Set-ADComputer -Instance $computer
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291114
        Add-ADComputerServiceAccount 
        Get-ADComputer 
        Get-ADComputerServiceAccount 
        New-ADComputer 
        Remove-ADComputer 
        Remove-ADComputerServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Set-ADComputer -examples".
        For more information, type: "get-help Set-ADComputer -detailed".
        For technical information, type: "get-help Set-ADComputer -full".
        For online help, type: "get-help Set-ADComputer -online"
    
    
    
    NAME
        Set-ADDefaultDomainPasswordPolicy
        
    SYNOPSIS
        Modifies the default password policy for an Active Directory domain.
        
        
    SYNTAX
        Set-ADDefaultDomainPasswordPolicy [-Identity] <ADDefaultDomainPasswordPolicy> [-AuthType {Negotiate | Basic}] 
        [-ComplexityEnabled <Boolean>] [-Credential <PSCredential>] [-LockoutDuration <TimeSpan>] 
        [-LockoutObservationWindow <TimeSpan>] [-LockoutThreshold <Int32>] [-MaxPasswordAge <TimeSpan>] [-MinPasswordAge 
        <TimeSpan>] [-MinPasswordLength <Int32>] [-PassThru] [-PasswordHistoryCount <Int32>] [-ReversibleEncryptionEnabled 
        <Boolean>] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADDefaultDomainPasswordPolicy cmdlet modifies the properties of the default password policy for a domain. 
        You can modify property values by using the cmdlet parameters.
        
        The Identity parameter specifies the domain whose default password policy you want modify. You can identify a 
        domain by its Distinguished Name (DN), GUID, Security Identifier (SID), DNS domain name, or NETBIOS name. You can 
        also set the parameter to an ADDomain  object variable,  or pass an ADDomain object through the pipeline to the 
        Identity parameter. For example, you can use the Get-ADDomain cmdlet to retrieve a domain object and then pass the 
        object through the pipeline to the Set-ADDomainDefaultPasswordPolicy cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291115
        Get-ADDefaultDomainPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Set-ADDefaultDomainPasswordPolicy -examples".
        For more information, type: "get-help Set-ADDefaultDomainPasswordPolicy -detailed".
        For technical information, type: "get-help Set-ADDefaultDomainPasswordPolicy -full".
        For online help, type: "get-help Set-ADDefaultDomainPasswordPolicy -online"
    
    
    
    NAME
        Set-ADDomain
        
    SYNOPSIS
        Modifies an Active Directory domain.
        
        
    SYNTAX
        Set-ADDomain [-Identity] <ADDomain> [-Add <Hashtable>] [-AllowedDNSSuffixes <Hashtable>] [-AuthType {Negotiate | 
        Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-LastLogonReplicationInterval <TimeSpan>] [-ManagedBy 
        <ADPrincipal>] [-PassThru] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Set-ADDomain [-AllowedDNSSuffixes <Hashtable>] [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] 
        [-LastLogonReplicationInterval <TimeSpan>] [-ManagedBy <ADPrincipal>] [-PassThru] [-Server <String>] -Instance 
        <ADDomain> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADDomain cmdlet modifies the properties of an Active Directory domain. You can modify commonly used 
        property values by using the cmdlet parameters. Property values that are not associated with cmdlet parameters can 
        be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the domain to modify. You can identify a domain by its distinguished name (DN), 
        GUID, security identifier (SID), DNS domain name, or NetBIOS name. You can also set the Identity parameter to an 
        object variable such as $<localDomainObject>, or you can pass an object through the pipeline to the Identity 
        parameter. For example, you can use the Get-ADDomain cmdlet to retrieve a domain object and then pass the object 
        through the pipeline to the Set-ADDomain cmdlet.
        
        The Instance parameter provides a way to update a domain object by applying the changes made to a copy of the 
        domain object. When you set the Instance parameter to a copy of an Active Directory domain object that has been 
        modified, the Set-ADDomain cmdlet makes the same changes to the original domain object. To get a copy of the 
        object to modify, use the Get-ADDomain object. When you specify the Instance parameter you should not pass the 
        identity parameter.  For more information about the Instance parameter, see the Instance parameter description.
        
        The following examples show how to modify the ManagedBy property of a domain object by using three methods:
        
        -By specifying the Identity and the ManagedBy parameters
        
        -By passing a domain object through the pipeline and specifying the ManagedBy parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the ManagedBy property for the London domain by using the Identity and ManagedBy parameters.
        
        Set-ADDomain -Identity London -ManagedBy SaraDavis
        
        Method 2: Modify the ManagedBy property for the London domain by passing the London domain through the pipeline 
        and specifying the ManagedBy parameter.
        
        Get-ADDomain London | Set-ADDomain -ManagedBy SaraDavis
        
        Method 3: Modify the ManagedBy property for the London domain by using the Windows PowerShell command line to 
        modify a local instance of the London domain. Then set the Instance parameter to the local instance.
        
        $domain = Get-ADDomain London
        
        $domain.ManagedBy = SaraDavis
        
        Set-ADDomain -Instance $domain.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291116
        Get-ADDomain 
    
    REMARKS
        To see the examples, type: "get-help Set-ADDomain -examples".
        For more information, type: "get-help Set-ADDomain -detailed".
        For technical information, type: "get-help Set-ADDomain -full".
        For online help, type: "get-help Set-ADDomain -online"
    
    
    
    NAME
        Set-ADDomainMode
        
    SYNOPSIS
        Sets the domain mode for an Active Directory domain.
        
        
    SYNTAX
        Set-ADDomainMode [-Identity] <ADDomain> [-DomainMode] {UnknownDomain | Windows2000Domain | 
        Windows2003InterimDomain | Windows2003Domain | Windows2008Domain | Windows2008R2Domain | Windows2012Domain | 
        Windows2012R2Domain} [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADDomainMode cmdlet sets the domain mode for a domain. You specify the domain mode by setting the 
        DomainMode parameter.
        
        The domain mode can be set to the following values that are listed in order of functionality from lowest to 
        highest.
        
        Windows2000Domain
        
        Windows2003InterimDomain
        
        Windows2003Domain
        
        Windows2008Domain
        
        Windows2008R2Domain
        
        You can change the domain mode to a mode with higher functionality only. For example, if the domain mode for a 
        domain is set to Windows 2003, you can use this cmdlet to change the mode to Windows 2008. However, in the same 
        situation, you cannot use this cmdlet to change the domain mode from Windows 2003 to Windows 2000.
        
        The Identity parameter specifies the Active Directory domain to modify. You can identify a domain by its 
        distinguished name (DN), GUID, security identifier (SID), DNS domain name, or NetBIOS name. You can also set the 
        Identity parameter to a domain object variable such as $<localADDomainObject>, or you can pass a domain object 
        through the pipeline to the Identity parameter. For example, you can use the Get-ADDomain cmdlet to retrieve a 
        domain object and then pass the object through the pipeline to the Set-ADDomainMode cmdlet.
        
        The Set-ADDomainMode always prompts for permission unless you specify -confirm:$false.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291117
        Get-ADDomain 
    
    REMARKS
        To see the examples, type: "get-help Set-ADDomainMode -examples".
        For more information, type: "get-help Set-ADDomainMode -detailed".
        For technical information, type: "get-help Set-ADDomainMode -full".
        For online help, type: "get-help Set-ADDomainMode -online"
    
    
    
    NAME
        Set-ADFineGrainedPasswordPolicy
        
    SYNOPSIS
        Modifies an Active Directory fine grained password policy.
        
        
    SYNTAX
        Set-ADFineGrainedPasswordPolicy [-Identity] <ADFineGrainedPasswordPolicy> [-Add <Hashtable>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-ComplexityEnabled <Boolean>] [-Credential <PSCredential>] [-Description <String>] 
        [-DisplayName <String>] [-LockoutDuration <TimeSpan>] [-LockoutObservationWindow <TimeSpan>] [-LockoutThreshold 
        <Int32>] [-MaxPasswordAge <TimeSpan>] [-MinPasswordAge <TimeSpan>] [-MinPasswordLength <Int32>] [-PassThru] 
        [-PasswordHistoryCount <Int32>] [-Precedence <Int32>] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-ReversibleEncryptionEnabled <Boolean>] [-Server <String>] [-Confirm] 
        [-WhatIf] [<CommonParameters>]
        
        Set-ADFineGrainedPasswordPolicy [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADFineGrainedPasswordPolicy> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADFineGrainedPasswordPolicy cmdlet modifies the properties of an Active Directory fine grained password 
        policy. You can modify commonly used property values by using the cmdlet parameters. Property values that are not 
        associated with cmdlet parameters can be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory fine grained password policy to modify. You can identify a 
        fine grained password policy by its distinguished name (DN), GUID or name. You can also set the Identity parameter 
        to an object variable such as $<localFineGrainedPasswordPolicyObject>, or you can pass an object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADFineGrainedPasswordPolicy cmdlet to 
        retrieve a fine grained password policy object and then pass the object through the pipeline to the 
        Set-ADFineGrainedPasswordPolicy cmdlet.
        
        The Instance parameter provides a way to update a fine grained password policy object by applying the changes made 
        to a copy of the object. When you set the Instance parameter to a copy of an Active Directory fine grained 
        password policy object that has been modified, the Set-ADFineGrainedPasswordPolicy cmdlet makes the same changes 
        to the original fine grained password policy object. To get a copy of the object to modify, use the 
        Get-ADFineGrainedPasswordPolicy object. The Identity parameter is not allowed when you use the Instance parameter. 
        For more information about the Instance parameter, see the Instance parameter description. For more information 
        about how the Instance concept is used in Active Directory cmdlets, see about_ActiveDirectory_Instance
        
        The following examples show how to modify the Precedence property of a fine grained password policy object by 
        using three methods:
        
        -By specifying the Identity and the Precedence parameters
        
        -By passing a fine grained password policy object through the pipeline and specifying the Precedence parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the Precedence property for the Level3Policyfine grained password policy by using the Identity 
        and Precedence parameters.
        
        Set-ADFineGrainedPasswordPolicy -Identity "Level3Policy" -Precedence 150
        
        Method 2: Modify the Precedence property for the Level3Policyfine grained password policy by passing the 
        Level3Policyfine grained password policy through the pipeline and specifying the Precedence parameter.
        
        Get-ADFineGrainedPasswordPolicy -Identity "Level3Policy"| Set-ADFineGrainedPasswordPolicy -Precedence 150
        
        Method 3: Modify the Precedence property for the Level3Policy fine grained password policy by using the Windows 
        PowerShell command line to modify a local instance of the Level3Policyfine grained password policy. Then set the 
        Instance parameter to the local instance.
        
        $fineGrainedPasswordPolicy = Get-ADFineGrainedPasswordPolicy Level3Policy
        
        $fineGrainedPasswordPolicy.Precedence = 150
        
        Set-ADFineGrainedPasswordPolicy -Instance $fineGrainedPasswordPolicy
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291118
        Get-ADFineGrainedPasswordPolicy 
        New-ADFineGrainedPasswordPolicy 
        Remove-ADFineGrainedPasswordPolicy 
    
    REMARKS
        To see the examples, type: "get-help Set-ADFineGrainedPasswordPolicy -examples".
        For more information, type: "get-help Set-ADFineGrainedPasswordPolicy -detailed".
        For technical information, type: "get-help Set-ADFineGrainedPasswordPolicy -full".
        For online help, type: "get-help Set-ADFineGrainedPasswordPolicy -online"
    
    
    
    NAME
        Set-ADForest
        
    SYNOPSIS
        Modifies an Active Directory forest.
        
        
    SYNTAX
        Set-ADForest [-Identity] <ADForest> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] 
        [-Server <String>] [-SPNSuffixes <Hashtable>] [-UPNSuffixes <Hashtable>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADForest cmdlet modifies the properties of an Active Directory forest. You can modify commonly used 
        property values by using the cmdlet parameters. Property values that are not associated with cmdlet parameters can 
        be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory forest to modify. You can identify a forest by its fully 
        qualified domain name (FQDN), GUID, DNS host name, or NetBIOS name. You can also set the Identity parameter to an 
        object variable such as $<localADForestObject>, or you can pass an object through the pipeline to the Identity 
        parameter. For example, you can use the Get-ADForest cmdlet to retrieve a forest object and then pass the object 
        through the pipeline to the Set-ADForest cmdlet.
        
        The Instance parameter provides a way to update a forest object by applying the changes made to a copy of the 
        object. When you set the Instance parameter to a copy of an Active Directory forest object that has been modified, 
        the Set-ADForest cmdlet makes the same changes to the original forest object. To get a copy of the object to 
        modify, use the Get-ADForest object. The Identity parameter is not allowed when you use the Instance parameter. 
        For more information about the Instance parameter, see the Instance parameter description.
        
        The following examples show how to modify the UPNSuffixes property of a forest object by using three methods:
        
        -By specifying the Identity and the UPNSuffixes parameters
        
        -By passing a forest object through the pipeline and specifying the UPNSuffixes parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the UPNSuffixes property for the fabrikam.com forest by using the Identity and UPNSuffixes 
        parameters.
        
        Set-ADForest -Identity fabrikam.com -UPNSuffixes @{replace="fabrikam.com","fabrikam","corp.fabrikam.com"}
        
        Method 2: Modify the UPNSuffixes property for the fabrikam.com forest by passing the fabrikam.com forest through 
        the pipeline and specifying the UPNSuffixes parameter.
        
        Get-ADForest -Identity fabrikam.com | Set-ADForest -UPNSuffixes 
        @{replace="fabrikam.com","fabrikam","corp.fabrikam.com"}
        
        Method 3: Modify the UPNSuffixes property for the fabrikam.com forest by using the Windows PowerShell command line 
        to modify a local instance of the fabrikam.com forest. Then set the Instance parameter to the local instance.
        
        $forest = Get-ADForest -Identity fabrikam.com
        
        $forest.UPNSuffixes = "fabrikam.com","fabrikam","corp.fabrikam.com"
        
        Set-ADForest -Instance $forest.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291119
        Get-ADForest 
        Set-ADForestMode 
    
    REMARKS
        To see the examples, type: "get-help Set-ADForest -examples".
        For more information, type: "get-help Set-ADForest -detailed".
        For technical information, type: "get-help Set-ADForest -full".
        For online help, type: "get-help Set-ADForest -online"
    
    
    
    NAME
        Set-ADForestMode
        
    SYNOPSIS
        Sets the forest mode for an Active Directory forest.
        
        
    SYNTAX
        Set-ADForestMode [-Identity] <ADForest> [-ForestMode] {UnknownForest | Windows2000Forest | 
        Windows2003InterimForest | Windows2003Forest | Windows2008Forest | Windows2008R2Forest | Windows2012Forest | 
        Windows2012R2Forest} [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADForestMode cmdlet sets the Forest mode for an Active Directory forest. You specify the forest mode by 
        setting the ForestMode parameter. The forest mode can be set to the following values that are listed in order of 
        functionality from lowest to highest.
        
        Windows2000Forest
        
        Windows2003InterimForest
        
        Windows2003Forest
        
        Windows2008Forest
        
        Windows2008R2Forest
        
        The Identity parameter specifies the Active Directory forest to modify. You can identify a forest by its fully 
        qualified domain name (FQDN), GUID, DNS host name, or NetBIOS name. You can also specify the forest by passing a 
        forest object through the pipeline. For example, you can use the Get-ADForest cmdlet to retrieve a forest object 
        and then pass the object through the pipeline to the Set-ADForestMode.
        
        Set-ADForestMode will prompt for confirmation by default.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291120
        Get-ADForest 
    
    REMARKS
        To see the examples, type: "get-help Set-ADForestMode -examples".
        For more information, type: "get-help Set-ADForestMode -detailed".
        For technical information, type: "get-help Set-ADForestMode -full".
        For online help, type: "get-help Set-ADForestMode -online"
    
    
    
    NAME
        Set-ADGroup
        
    SYNOPSIS
        Modifies an Active Directory group.
        
        
    SYNTAX
        Set-ADGroup [-Identity] <ADGroup> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] [-Clear <String[]>] 
        [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] [-GroupCategory {Distribution | 
        Security}] [-GroupScope {DomainLocal | Global | Universal}] [-HomePage <String>] [-ManagedBy <ADPrincipal>] 
        [-Partition <String>] [-PassThru] [-Remove <Hashtable>] [-Replace <Hashtable>] [-SamAccountName <String>] [-Server 
        <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADGroup [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] -Instance 
        <ADGroup> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADGroup cmdlet modifies the properties of an Active Directory group. You can modify commonly used property 
        values by using the cmdlet parameters. Property values that are not associated with cmdlet parameters can be 
        modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory group to modify. You can identify a group by its 
        distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can 
        also set the Identity parameter to an object variable such as $<localGroupObject>, or you can pass a group object 
        through the pipeline to the Identity parameter. For example, you can use the Get-ADGroup cmdlet to retrieve a 
        group object and then pass the object through the pipeline to the Set-ADGroup cmdlet.
        
        The Instance parameter provides a way to update a group object by applying the changes made to a copy of the 
        object. When you set the Instance parameter to a copy of an Active Directory group object that has been modified, 
        the Set-ADGroup cmdlet makes the same changes to the original group object. To get a copy of the object to modify, 
        use the Get-ADGroup object. The Identity parameter is not allowed when you use the Instance parameter. For more 
        information about the Instance parameter, see the Instance parameter description. For more information about how 
        the Instance concept is used in Active Directory cmdlets, see about_ActiveDirectory_Instance
        
        The following examples show how to modify the Description property of a group object by using three methods:
        
        -By specifying the Identity and the Description parameters
        
        -By passing a group object through the pipeline and specifying the Description parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the Description property for the SecurityLevel2Access group by using the Identity and Description 
        parameters.
        
        Set-ADGroup -Identity SecurityLevel2Access -Description "Used to authorize Security Level 2 access."
        
        Method 2: Modify the Description property for the SecurityLevel2Access group by passing the SecurityLevel2Access 
        group through the pipeline and specifying the Description parameter.
        
        Get-ADGroup -Identity "SecurityLevel2Access" | Set-ADGroup -Description "Used to authorize Security Level 2 
        access."
        
        Method 3: Modify the <property> property for the SecurityLevel2Access group by using the Windows PowerShell 
        command line to modify a local instance of the SecurityLevel2Access group. Then set the Instance parameter to the 
        local instance.
        
        $group = Get-ADGroup -Identity "SecurityLevel2Access"
        
        $group.Description = "Used to authorize Security Level 2 access."
        
        Set-ADGroup -Instance $group.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291121
        Add-ADGroupMember 
        Add-ADPrincipalGroupMembership 
        Get-ADGroup 
        Get-ADGroupMember 
        Get-ADPrincipalGroupMembership 
        New-ADGroup 
        Remove-ADGroup 
        Remove-ADGroupMember 
        Remove-ADPrincipalGroupMembership 
    
    REMARKS
        To see the examples, type: "get-help Set-ADGroup -examples".
        For more information, type: "get-help Set-ADGroup -detailed".
        For technical information, type: "get-help Set-ADGroup -full".
        For online help, type: "get-help Set-ADGroup -online"
    
    
    
    NAME
        Set-ADObject
        
    SYNOPSIS
        Modifies an Active Directory object.
        
        
    SYNTAX
        Set-ADObject [-Identity] <ADObject> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] [-Clear <String[]>] 
        [-Credential <PSCredential>] [-Description <String>] [-DisplayName <String>] [-Partition <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADObject [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] -Instance 
        <ADObject> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADObject cmdlet modifies the properties of an Active Directory object. You can modify commonly used 
        property values by using the cmdlet parameters. Property values that are not associated with cmdlet parameters can 
        be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory object to modify. You can identify an object by its 
        distinguished name (DN) or GUID. You can also set the Identity parameter to an object variable such as 
        $<localObject>, or you can pass an object through the pipeline to the Identity parameter. For example, you can use 
        the Get-ADObject cmdlet to retrieve an object and then pass the object through the pipeline to the Set-ADObject 
        cmdlet.
        
        The Instance parameter provides a way to update an object by applying the changes made to a copy of the object. 
        When you set the Instance parameter to a copy of an Active Directory object that has been modified, the 
        Set-ADObject cmdlet makes the same changes to the original object. To get a copy of the object to modify, use the 
        Get-ADObject object. The Identity parameter is not allowed when you use the Instance parameter. For more 
        information about the Instance parameter, see the Instance parameter description. For more information about how 
        the Instance concept is used in Active Directory cmdlets, see about_ActiveDirectory_Instance.
        
        The following examples show how to modify the DisplayName property of an object by using three methods:
        
        -By specifying the Identity and the DisplayName parameters
        
        -By passing an object through the pipeline and specifying the DisplayName parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the DisplayName property for the SecurityLevel2AccessGroup object by using the Identity and 
        DisplayName parameters.
        
        Set-ADObject -Identity "SecurityLevel2AccessGroup" -DisplayName "Security Level 2"
        
        Method 2: Modify the DisplayName property for the SecurityLevel2AccessGroup object by passing the 
        SecurityLevel2AccessGroup object through the pipeline and specifying the DisplayName parameter.
        
        Get-ADObject -Identity "SecurityLevel2AccessGroup" | Set-ADObject -DisplayName "Security Level 2"
        
        Method 3: Modify the DisplayName property for the SecurityLevel2AccessGroup object by using the Windows PowerShell 
        command line to modify a local instance of the SecurityLevel2AccessGroup object. Then set the Instance parameter 
        to the local instance.
        
        $adobject = Get-ADObject -Identity "SecurityLevel2AccessGroup"
        
        $adobject.DisplayName = "Security Level 2"
        
        Set-ADObject -Instance $adobject.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291122
        Get-ADObject 
        New-ADObject 
        Remove-ADObject 
    
    REMARKS
        To see the examples, type: "get-help Set-ADObject -examples".
        For more information, type: "get-help Set-ADObject -detailed".
        For technical information, type: "get-help Set-ADObject -full".
        For online help, type: "get-help Set-ADObject -online"
    
    
    
    NAME
        Set-ADOrganizationalUnit
        
    SYNOPSIS
        Modifies an Active Directory organizational unit.
        
        
    SYNTAX
        Set-ADOrganizationalUnit [-Identity] <ADOrganizationalUnit> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-City <String>] [-Clear <String[]>] [-Country <String>] [-Credential <PSCredential>] [-Description <String>] 
        [-DisplayName <String>] [-ManagedBy <ADPrincipal>] [-Partition <String>] [-PassThru] [-PostalCode <String>] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        [-State <String>] [-StreetAddress <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADOrganizationalUnit [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADOrganizationalUnit> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADOrganizationalUnit cmdlet modifies the properties of an Active Directory organizational unit. You can 
        modify commonly used property values by using the cmdlet parameters. Property values that are not associated with 
        cmdlet parameters can be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory organizational unit to modify. You can identify an 
        organizational unit by its distinguished name (DN) or GUID.
        
        You can also set the Identity parameter to an object variable such as $<localADOrganizationalUnitObject>, or you 
        can pass an object through the pipeline to the Identity parameter. For example, you can use the 
        Get-ADOrganizationalUnit cmdlet to retrieve an organizational unit object and then pass the object through the 
        pipeline to the Set-ADOrganizationalUnit cmdlet.
        
        The Instance parameter provides a way to update an organizational unit object by applying the changes made to a 
        copy of the object. When you set the Instance parameter to a copy of an Active Directory organizational unit 
        object that has been modified, the Set-ADOrganizationalUnit cmdlet makes the same changes to the original 
        organizational unit object. To get a copy of the object to modify, use the Get-ADOrganizationalUnit object. When 
        you specify the Instance parameter you should not pass the Identity parameter. For more information about the 
        Instance parameter, see the Instance parameter description.
        
        For more information about how the Instance concept is used in Active Directory cmdlets, see 
        about_ActiveDirectory_Instance.
        
        The following examples show how to modify the ManagedBy property of an organizational unit object by using three 
        methods:
        
        -By specifying the Identity and the ManagedBy parameters
        
        -By passing an organizational unit object through the pipeline and specifying the ManagedBy parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the ManagedBy property for the "AccountingDepartment" organizational unit by using the Identity 
        and ManagedBy parameters.
        
        Set-ADOrganizationalUnit -Identity "AccountingDepartment" -ManagedBy "SaraDavisGroup"
        
        Method 2: Modify the ManagedBy property for the "AccountingDepartment" organizational unit by passing the 
        "AccountingDepartment" organizational unit through the pipeline and specifying the ManagedBy parameter.
        
        Get-ADOrganizationalUnit -Identity ""AccountingDepartment"" | Set-ADOrganizationalUnit -ManagedBy "SaraDavisGroup"
        
        Method 3: Modify the ManagedBy property for the "AccountingDepartment" organizational unit by using the Windows 
        PowerShell command line to modify a local instance of the "AccountingDepartment" organizational unit. Then set the 
        Instance parameter to the local instance.
        
        $organizational unit = Get-ADOrganizationalUnit -Identity "AccountingDepartment"
        
        $organizational unit.ManagedBy = "SaraDavisGroup"
        
        Set-ADOrganizationalUnit -Instance $organizational unit.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291123
        Get-ADOrganizationalUnit 
        New-ADOrganizationalUnit 
        Remove-ADOrganizationalUnit 
    
    REMARKS
        To see the examples, type: "get-help Set-ADOrganizationalUnit -examples".
        For more information, type: "get-help Set-ADOrganizationalUnit -detailed".
        For technical information, type: "get-help Set-ADOrganizationalUnit -full".
        For online help, type: "get-help Set-ADOrganizationalUnit -online"
    
    
    
    NAME
        Set-ADReplicationConnection
        
    SYNOPSIS
        Sets properties on Active Directory replication connections.
        
        
    SYNTAX
        Set-ADReplicationConnection [-Identity] <ADReplicationConnection> [-Add <Hashtable>] [-AuthType {Negotiate | 
        Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-PassThru] [-Remove <Hashtable>] [-Replace <Hashtable>] 
        [-ReplicateFromDirectoryServer <ADDirectoryServer>] [-ReplicationSchedule <ActiveDirectorySchedule>] [-Server 
        <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADReplicationConnection [-AuthType {Negotiate | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] 
        [-PassThru] [-Server <String>] -Instance <ADReplicationConnection> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADReplicationConnection cmdlet sets properties on Active Directory replication connections.  Connections 
        are used to enable domain controllers to replicate with each other. A connection defines a one-way, inbound route 
        from one domain controller, the source, to another domain controller, the destination. The Kerberos consistency 
        checker (KCC) reuses existing connections where it can, deletes unused connections, and creates new connections if 
        none exist that meet the current need.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291124
        Get-ADReplicationConnection 
    
    REMARKS
        To see the examples, type: "get-help Set-ADReplicationConnection -examples".
        For more information, type: "get-help Set-ADReplicationConnection -detailed".
        For technical information, type: "get-help Set-ADReplicationConnection -full".
        For online help, type: "get-help Set-ADReplicationConnection -online"
    
    
    
    NAME
        Set-ADReplicationSite
        
    SYNOPSIS
        Sets the replication properties for an Active Directory site.
        
        
    SYNTAX
        Set-ADReplicationSite [-Identity] <ADReplicationSite> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-AutomaticInterSiteTopologyGenerationEnabled <Boolean>] [-AutomaticTopologyGenerationEnabled <Boolean>] [-Clear 
        <String[]>] [-Credential <PSCredential>] [-Description <String>] [-InterSiteTopologyGenerator <ADDirectoryServer>] 
        [-ManagedBy <ADPrincipal>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] 
        [-RedundantServerTopologyEnabled <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-ReplicationSchedule 
        <ActiveDirectorySchedule>] [-ScheduleHashingEnabled <Boolean>] [-Server <String>] [-TopologyCleanupEnabled 
        <Boolean>] [-TopologyDetectStaleEnabled <Boolean>] [-TopologyMinimumHopsEnabled <Boolean>] 
        [-UniversalGroupCachingEnabled <Boolean>] [-UniversalGroupCachingRefreshSite <ADReplicationSite>] 
        [-WindowsServer2000BridgeheadSelectionMethodEnabled <Boolean>] [-WindowsServer2000KCCISTGSelectionBehaviorEnabled 
        <Boolean>] [-WindowsServer2003KCCBehaviorEnabled <Boolean>] [-WindowsServer2003KCCIgnoreScheduleEnabled <Boolean>] 
        [-WindowsServer2003KCCSiteLinkBridgingEnabled <Boolean>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADReplicationSite [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        -Instance <ADReplicationSite> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADReplicationSite cmdlet is used to set the properties for an Active Directory site that is being used for 
        replication. Sites are used in Active Directory to either enable clients to discover network resources (published 
        shares, domain controllers) close to the physical location of a client computer or to reduce network traffic over 
        wide area network (WAN) links. Sites can also be used to optimize replication between domain controllers.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291125
        Get-ADReplicationSite 
        New-ADReplicationSite 
        Remove-ADReplicationSite 
    
    REMARKS
        To see the examples, type: "get-help Set-ADReplicationSite -examples".
        For more information, type: "get-help Set-ADReplicationSite -detailed".
        For technical information, type: "get-help Set-ADReplicationSite -full".
        For online help, type: "get-help Set-ADReplicationSite -online"
    
    
    
    NAME
        Set-ADReplicationSiteLink
        
    SYNOPSIS
        Sets the properties for an Active Directory site link.
        
        
    SYNTAX
        Set-ADReplicationSiteLink [-Identity] <ADReplicationSiteLink> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Cost <Int32>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-ReplicationFrequencyInMinutes <Int32>] [-ReplicationSchedule 
        <ActiveDirectorySchedule>] [-Server <String>] [-SitesIncluded <Hashtable>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Set-ADReplicationSiteLink [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Instance 
        <ADReplicationSiteLink>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADReplicationSiteLink cmdlet can be used to set properties on an Active Directory site link.  A site link 
        connects two or more sites. Site links reflect the administrative policy for how sites are to be interconnected 
        and the methods used to transfer replication traffic. You must connect sites with site links so that domain 
        controllers at each site can replicate Active Directory changes.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291126
        Get-ADReplicationSiteLink 
        New-ADReplicationSiteLink 
        Remove-ADReplicationSiteLink 
    
    REMARKS
        To see the examples, type: "get-help Set-ADReplicationSiteLink -examples".
        For more information, type: "get-help Set-ADReplicationSiteLink -detailed".
        For technical information, type: "get-help Set-ADReplicationSiteLink -full".
        For online help, type: "get-help Set-ADReplicationSiteLink -online"
    
    
    
    NAME
        Set-ADReplicationSiteLinkBridge
        
    SYNOPSIS
        Sets the properties of a replication site link bridge in Active Directory.
        
        
    SYNTAX
        Set-ADReplicationSiteLinkBridge [-Identity] <ADReplicationSiteLinkBridge> [-Add <Hashtable>] [-AuthType {Negotiate 
        | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-SiteLinksIncluded <Hashtable>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Set-ADReplicationSiteLinkBridge [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Instance 
        <ADReplicationSiteLinkBridge>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADReplicationSiteLinkBridge object sets the properties for a replication site link bridge in Active 
        Directory.  A site link bridge connects two or more site links and enables transitivity between site links. Each 
        site link in a bridge must have a site in common with another site link in the bridge.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291127
        Get-ADReplicationSiteLinkBridge 
        New-ADReplicationSiteLinkBridge 
        Remove-ADReplicationSiteLinkBridge 
    
    REMARKS
        To see the examples, type: "get-help Set-ADReplicationSiteLinkBridge -examples".
        For more information, type: "get-help Set-ADReplicationSiteLinkBridge -detailed".
        For technical information, type: "get-help Set-ADReplicationSiteLinkBridge -full".
        For online help, type: "get-help Set-ADReplicationSiteLinkBridge -online"
    
    
    
    NAME
        Set-ADReplicationSubnet
        
    SYNOPSIS
        Sets the properties of an Active Directory replication subnet object.
        
        
    SYNTAX
        Set-ADReplicationSubnet [-Identity] <ADReplicationSubnet> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-Location <String>] [-PassThru] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-Site <ADReplicationSite>] [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Set-ADReplicationSubnet [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Instance 
        <ADReplicationSubnet>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADReplicationSubnet cmdlet sets the properties of an Active Directory replication subnet object. Subnet 
        objects (class subnet) define network subnets in Active Directory. A network subnet is a segment of a TCP/IP 
        network to which a set of logical IP addresses is assigned. Subnets group computers in a way that identifies their 
        physical proximity on the network. Subnet objects in Active Directory are used to map computers to sites.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291128
        Get-ADReplicationSubnet 
        New-ADReplicationSubnet 
        Remove-ADReplicationSubnet 
    
    REMARKS
        To see the examples, type: "get-help Set-ADReplicationSubnet -examples".
        For more information, type: "get-help Set-ADReplicationSubnet -detailed".
        For technical information, type: "get-help Set-ADReplicationSubnet -full".
        For online help, type: "get-help Set-ADReplicationSubnet -online"
    
    
    
    NAME
        Set-ADResourceProperty
        
    SYNOPSIS
        Modifies a resource property in Active Directory.
        
        
    SYNTAX
        Set-ADResourceProperty [-Identity] <ADResourceProperty> [-Add <Hashtable>] [-AppliesToResourceTypes <Hashtable>] 
        [-AuthType {Negotiate | Basic}] [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] 
        [-DisplayName <String>] [-Enabled <Boolean>] [-PassThru] [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove 
        <Hashtable>] [-Replace <Hashtable>] [-Server <String>] [-SharesValuesWith <ADClaimType>] [-SuggestedValues 
        <ADSuggestedValueEntry[]>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADResourceProperty [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        -Instance <ADResourceProperty> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADResourceProperty cmdlet can be used to modify a resource property in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291129
    
    REMARKS
        To see the examples, type: "get-help Set-ADResourceProperty -examples".
        For more information, type: "get-help Set-ADResourceProperty -detailed".
        For technical information, type: "get-help Set-ADResourceProperty -full".
        For online help, type: "get-help Set-ADResourceProperty -online"
    
    
    
    NAME
        Set-ADResourcePropertyList
        
    SYNOPSIS
        Modifies a resource property list in Active Directory.
        
        
    SYNTAX
        Set-ADResourcePropertyList [-Identity] <ADResourcePropertyList> [-Add <Hashtable>] [-AuthType {Negotiate | Basic}] 
        [-Clear <String[]>] [-Credential <PSCredential>] [-Description <String>] [-PassThru] 
        [-ProtectedFromAccidentalDeletion <Boolean>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-Server <String>] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADResourcePropertyList [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server 
        <String>] -Instance <ADResourcePropertyList> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADResourcePropertyList cmdlet can be used to modify a resource property list in Active Directory.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291130
    
    REMARKS
        To see the examples, type: "get-help Set-ADResourcePropertyList -examples".
        For more information, type: "get-help Set-ADResourcePropertyList -detailed".
        For technical information, type: "get-help Set-ADResourcePropertyList -full".
        For online help, type: "get-help Set-ADResourcePropertyList -online"
    
    
    
    NAME
        Set-ADServiceAccount
        
    SYNOPSIS
        Modifies an Active Directory managed service account or group managed service account object.
        
        
    SYNTAX
        Set-ADServiceAccount [-Identity] <ADServiceAccount> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated 
        <Boolean>] [-Add <Hashtable>] [-AuthenticationPolicy <ADAuthenticationPolicy>] [-AuthenticationPolicySilo 
        <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-Certificates <String[]>] [-Clear <String[]>] 
        [-CompoundIdentitySupported <Boolean>] [-Credential <PSCredential>] [-Description <String>] [-DisplayName 
        <String>] [-DNSHostName <String>] [-Enabled <Boolean>] [-HomePage <String>] [-KerberosEncryptionType {None | DES | 
        RC4 | AES128 | AES256}] [-Partition <String>] [-PassThru] [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] 
        [-PrincipalsAllowedToRetrieveManagedPassword <ADPrincipal[]>] [-Remove <Hashtable>] [-Replace <Hashtable>] 
        [-SamAccountName <String>] [-Server <String>] [-ServicePrincipalNames <Hashtable>] [-TrustedForDelegation 
        <Boolean>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADServiceAccount [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-Server <String>] 
        -Instance <ADServiceAccount> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADServiceAccount cmdlet modifies the properties of an Active Directory managed service account (MSA). You 
        can modify commonly used property values by using the cmdlet parameters. Property values that are not associated 
        with cmdlet parameters can be modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory MSA to modify. You can identify a MSA by its distinguished 
        name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can also set the 
        Identity parameter to an object variable such as $<localServiceAccountObject>, or you can pass an object through 
        the pipeline to the Identity parameter. For example, you can use the Get-ADServiceAccount cmdlet to retrieve a MSA 
        object and then pass the object through the pipeline to the Set-ADServiceAccount cmdlet.
        
        The Instance parameter provides a way to update a MSA object by applying the changes made to a copy of the object. 
        When you set the Instance parameter to a copy of an Active Directory MSA object that has been modified, the 
        Set-ADServiceAccount cmdlet makes the same changes to the original MSA object. To get a copy of the object to 
        modify, use the Get-ADServiceAccount object. When you specify the Instance parameter you should not pass the 
        Identity parameter. For more information about the Instance parameter, see the Instance parameter description.
        
        For more information about how the Instance concept is used in Active Directory cmdlets, see 
        about_ActiveDirectory_Instance.
        
        The following examples show how to modify the ServicePrincipalNames property of a MSA object by using three 
        methods:
        
        -By specifying the Identity and the ServicePrincipalNames parameters
        
        -By passing a service account object through the pipeline and specifying the ServicePrincipalNames parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the ServicePrincipalNames property for the AccessIndia MSA by using the Identity and 
        ServicePrincipalNames parameters.
        
        Set-ADServiceAccount -Identity AccessIndia -ServicePrincipalNames @{Add=ACCESSAPP/india.contoso.com}
        
        Method 2: Modify the ServicePrincipalNames property for the AccessIndia MSA by passing the AccessIndia MSA through 
        the pipeline and specifying the ServicePrincipalNames parameter.
        
        Get-ADServiceAccount -Identity "AccessIndia" | Set-ADServiceAccount -ServicePrincipalNames 
        @{Add=ACCESSAPP/india.contoso.com}
        
        Method 3: Modify the <property> property for the AccessIndia MSA by using the Windows PowerShell command line to 
        modify a local instance of the AccessIndia MSA. Then set the Instance parameter to the local instance.
        
        $serviceAccount = Get-ADServiceAccount -Identity "AccessIndia"
        
        $serviceAccount.ServicePrincipalNames = @{Add=ACCESSAPP/india.contoso.com}
        
        Set-ADServiceAccount -Instance $serviceAccount.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291131
        Get-ADServiceAccount 
        Install-ADServiceAccount 
        New-ADServiceAccount 
        Remove-ADServiceAccount 
        Uninstall-ADServiceAccount 
    
    REMARKS
        To see the examples, type: "get-help Set-ADServiceAccount -examples".
        For more information, type: "get-help Set-ADServiceAccount -detailed".
        For technical information, type: "get-help Set-ADServiceAccount -full".
        For online help, type: "get-help Set-ADServiceAccount -online"
    
    
    
    NAME
        Set-ADUser
        
    SYNOPSIS
        Modifies an Active Directory user.
        
        
    SYNTAX
        Set-ADUser [-Identity] <ADUser> [-AccountExpirationDate <DateTime>] [-AccountNotDelegated <Boolean>] [-Add 
        <Hashtable>] [-AllowReversiblePasswordEncryption <Boolean>] [-AuthenticationPolicy <ADAuthenticationPolicy>] 
        [-AuthenticationPolicySilo <ADAuthenticationPolicySilo>] [-AuthType {Negotiate | Basic}] [-CannotChangePassword 
        <Boolean>] [-Certificates <Hashtable>] [-ChangePasswordAtLogon <Boolean>] [-City <String>] [-Clear <String[]>] 
        [-Company <String>] [-CompoundIdentitySupported <Boolean>] [-Country <String>] [-Credential <PSCredential>] 
        [-Department <String>] [-Description <String>] [-DisplayName <String>] [-Division <String>] [-EmailAddress 
        <String>] [-EmployeeID <String>] [-EmployeeNumber <String>] [-Enabled <Boolean>] [-Fax <String>] [-GivenName 
        <String>] [-HomeDirectory <String>] [-HomeDrive <String>] [-HomePage <String>] [-HomePhone <String>] [-Initials 
        <String>] [-KerberosEncryptionType {None | DES | RC4 | AES128 | AES256}] [-LogonWorkstations <String>] [-Manager 
        <ADUser>] [-MobilePhone <String>] [-Office <String>] [-OfficePhone <String>] [-Organization <String>] [-OtherName 
        <String>] [-Partition <String>] [-PassThru] [-PasswordNeverExpires <Boolean>] [-PasswordNotRequired <Boolean>] 
        [-POBox <String>] [-PostalCode <String>] [-PrincipalsAllowedToDelegateToAccount <ADPrincipal[]>] [-ProfilePath 
        <String>] [-Remove <Hashtable>] [-Replace <Hashtable>] [-SamAccountName <String>] [-ScriptPath <String>] [-Server 
        <String>] [-ServicePrincipalNames <Hashtable>] [-SmartcardLogonRequired <Boolean>] [-State <String>] 
        [-StreetAddress <String>] [-Surname <String>] [-Title <String>] [-TrustedForDelegation <Boolean>] 
        [-UserPrincipalName <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        Set-ADUser [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-PassThru] [-SamAccountName <String>] 
        [-Server <String>] -Instance <ADUser> [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Set-ADUser cmdlet modifies the properties of an Active Directory user. You can modify commonly used property 
        values by using the cmdlet parameters. Property values that are not associated with cmdlet parameters can be 
        modified by using the Add, Replace, Clear and Remove parameters.
        
        The Identity parameter specifies the Active Directory user to modify. You can identify a user by its distinguished 
        name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can also set the 
        Identity parameter to an object variable such as $<localUserObject>, or you can pass an object through the 
        pipeline to the Identity parameter. For example, you can use the Get-ADUser cmdlet to retrieve a user object and 
        then pass the object through the pipeline to the Set-ADUser cmdlet.
        
        The Instance parameter provides a way to update a user object by applying the changes made to a copy of the 
        object. When you set the Instance parameter to a copy of an Active Directory user object that has been modified, 
        the Set-ADUser cmdlet makes the same changes to the original user object. To get a copy of the object to modify, 
        use the Get-ADUser object. The Identity parameter is not allowed when you use the Instance parameter. For more 
        information about the Instance parameter, see the Instance parameter description. For more information about how 
        the Instance concept is used in Active Directory cmdlets, see about_ActiveDirectory_Instance.
        
        Accounts created with the New-ADUser cmdlet will be disabled if no password is provided.
        
        The following examples show how to modify the Manager property of a user object by using three methods:
        
        -By specifying the Identity and the Manager parameters
        
        -By passing a user object through the pipeline and specifying the Manager parameter
        
        -By specifying the Instance parameter.
        
        Method 1: Modify the Manager property for the "saraDavis" user by using the Identity and Manager parameters.
        
        Set-ADUser -Identity "saraDavis" -Manager "JimCorbin"
        
        Method 2: Modify the Manager property for the "saraDavis" user by passing the "saraDavis" user through the 
        pipeline and specifying the Manager parameter.
        
        Get-ADUser -Identity "saraDavis" | Set-ADUser -Manager "JimCorbin"
        
        Method 3: Modify the Manager property for the "saraDavis" user by using the Windows PowerShell command line to 
        modify a local instance of the "saraDavis" user. Then set the Instance parameter to the local instance.
        
        $user = Get-ADUser -Identity "saraDavis"
        
        $user.Manager = "JimCorbin"
        
        Set-ADUser -Instance $user.
        
        For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
        
        -The cmdlet is run from an Active Directory provider drive.
        
        -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context 
        for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service 
        agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291132
        Get-ADUser 
        New-ADUser 
        Remove-ADUser 
        Set-ADAccountControl 
    
    REMARKS
        To see the examples, type: "get-help Set-ADUser -examples".
        For more information, type: "get-help Set-ADUser -detailed".
        For technical information, type: "get-help Set-ADUser -full".
        For online help, type: "get-help Set-ADUser -online"
    
    
    
    NAME
        Show-ADAuthenticationPolicyExpression
        
    SYNOPSIS
        Displays the Edit Access Control Conditions window update or create security descriptor definition language (SDDL) 
        security descriptors.
        
        
    SYNTAX
        Show-ADAuthenticationPolicyExpression [[-SDDL] <String>] [[-Title] <String>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] -AllowedToAuthenticateFrom [-Confirm] [-WhatIf] 
        [<CommonParameters>]
        
        Show-ADAuthenticationPolicyExpression [[-SDDL] <String>] [[-Title] <String>] [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-Server <String>] -AllowedToAuthenticateTo [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Show-ADAuthenticationPolicyExpression cmdlet creates or modifies an SDDL security descriptor using the Edit 
        Access Control Conditions window.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=298321
    
    REMARKS
        To see the examples, type: "get-help Show-ADAuthenticationPolicyExpression -examples".
        For more information, type: "get-help Show-ADAuthenticationPolicyExpression -detailed".
        For technical information, type: "get-help Show-ADAuthenticationPolicyExpression -full".
        For online help, type: "get-help Show-ADAuthenticationPolicyExpression -online"
    
    
    
    NAME
        Sync-ADObject
        
    SYNOPSIS
        Replicates a single object between any two domain controllers that have partitions in common.
        
        
    SYNTAX
        Sync-ADObject [-Object] <ADObject> [[-Source] <String>] [-Destination] <String> [-AuthType {Negotiate | Basic}] 
        [-Credential <PSCredential>] [-PassThru] [-PasswordOnly] [<CommonParameters>]
        
        
    DESCRIPTION
        The Sync-ADObject cmdlet replicates a single object between any two domain controllers that have partitions in 
        common. The two domain controllers do not need to be direct replication partners. It can also be used to populate 
        passwords in a read-only domain controller (RODC) cache.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291133
        Get-ADObject 
        Move-ADObject 
        New-ADObject 
        Remove-ADObject 
        Rename-ADObject 
        Restore-ADObject 
        Set-ADObject 
    
    REMARKS
        To see the examples, type: "get-help Sync-ADObject -examples".
        For more information, type: "get-help Sync-ADObject -detailed".
        For technical information, type: "get-help Sync-ADObject -full".
        For online help, type: "get-help Sync-ADObject -online"
    
    
    
    NAME
        Test-ADServiceAccount
        
    SYNOPSIS
        Tests a managed service account from a computer.
        
        
    SYNTAX
        Test-ADServiceAccount [-Identity] <ADServiceAccount> [-AuthType {Negotiate | Basic}] [<CommonParameters>]
        
        
    DESCRIPTION
        The Test-ADServiceAccount cmdlet tests a managed service account (MSA) from a local computer.
        
        The Identity parameter specifies the Active Directory MSA account to test. You can identify a MSA by its 
        distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can 
        also set the parameter to a MSA object variable, such as $<localMSA> or pass a MSA object through the pipeline to 
        the Identity parameter. For example, you can use the Get-ADServiceAccount to get a MSA object and then pass that 
        object through the pipeline to the Test-ADServiceAccount cmdlet.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291134
    
    REMARKS
        To see the examples, type: "get-help Test-ADServiceAccount -examples".
        For more information, type: "get-help Test-ADServiceAccount -detailed".
        For technical information, type: "get-help Test-ADServiceAccount -full".
        For online help, type: "get-help Test-ADServiceAccount -online"
    
    
    
    NAME
        Uninstall-ADServiceAccount
        
    SYNOPSIS
        Uninstalls an Active Directory managed service account from a computer or removes a cached group managed service 
        account from a computer.
        
        
    SYNTAX
        Uninstall-ADServiceAccount [-Identity] <ADServiceAccount> [-AuthType {Negotiate | Basic}] [-ForceRemoveLocal] 
        [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Uninstall-ADServiceAccount cmdlet removes an Active Directory standalone managed service account (MSA) on the 
        computer on which the cmdlet is run. For group MSAs, the cmdlet removes the group MSA from the cache, however, if 
        a service is still using the group MSA and the host has permission to retrieve the password a new cache entry will 
        be created. The specified MSA must be installed on the computer.
        
        The Identity parameter specifies the Active Directory MSA to uninstall. You can identify a MSA by its 
        distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can 
        also set the parameter to a MSA object variable, such as $<localServiceAccountObject> or pass a MSA object through 
        the pipeline to the Identity parameter. For example, you can use the Get-ADServiceAccount to get a MSA object and 
        then pass that object through the pipeline to the Uninstall-ADServiceAccount cmdlet.
        
        For standalone MSA, the ForceRemoveLocal switch parameter will allow you to remove the account from the local LSA 
        without failing the command if an access to a writable DC is not possible. This is required if you are 
        uninstalling the standalone MSA from a server that is placed in a segmented network (i.e. perimeter network) with 
        access only to an RODC. If you pass this parameter and the server has access to a writable DC the standalone MSA 
        will be un-linked from the computer account in the directory as well.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291135
        Get-ADServiceAccount 
        Install-ADServiceAccount 
        New-ADService account 
        Remove-ADService account 
        Set-ADService account 
    
    REMARKS
        To see the examples, type: "get-help Uninstall-ADServiceAccount -examples".
        For more information, type: "get-help Uninstall-ADServiceAccount -detailed".
        For technical information, type: "get-help Uninstall-ADServiceAccount -full".
        For online help, type: "get-help Uninstall-ADServiceAccount -online"
    
    
    
    NAME
        Unlock-ADAccount
        
    SYNOPSIS
        Unlocks an Active Directory account.
        
        
    SYNTAX
        Unlock-ADAccount [-Identity] <ADAccount> [-AuthType {Negotiate | Basic}] [-Credential <PSCredential>] [-Partition 
        <String>] [-PassThru] [-Server <String>] [-Confirm] [-WhatIf] [<CommonParameters>]
        
        
    DESCRIPTION
        The Unlock-ADAccount cmdlet restores Active Directory Domain Services (AD DS) access for an account that is 
        locked. AD DS access is suspended or locked for an account when the number of incorrect password entries exceeds 
        the maximum number allowed by the account password policy.
        
        The Identity parameter specifies the Active Directory account to unlock. You can identify an account by its 
        distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name. You can 
        also set the Identity parameter to an account object variable such as $<localADAccountObject>, or you can pass an 
        object through the pipeline to the Identity parameter. For example, you can use the Search-ADAccount cmdlet to get 
        an account object and then pass the object through the pipeline to the Unlock-ADAccount cmdlet to unlock the 
        account. Similarly, you can use Get-ADUser and Get-ADComputer to get objects to pass through the pipeline.
        
        For AD LDS environments, the Partition parameter must be specified except when:     - Using a DN to identify 
        objects: the partition will be auto-generated from the DN.     - Running cmdlets from an Active Directory provider 
        drive: the current path will be used to set the partition.     - A default naming context or partition is 
        specified.
        
        To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the 
        Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.
        
    
    RELATED LINKS
        Online Version: http://go.microsoft.com/fwlink/p/?linkid=291136
        Clear-ADAccountExpiration 
        Disable-ADAccount 
        Enable-ADAccount 
        Get-ADAccountAuthorizationGroup 
        Search-ADAccount 
        Set-ADAccountControl 
        Set-ADAccountExpiration 
        Set-ADAccountPassword 
    
    REMARKS
        To see the examples, type: "get-help Unlock-ADAccount -examples".
        For more information, type: "get-help Unlock-ADAccount -detailed".
        For technical information, type: "get-help Unlock-ADAccount -full".
        For online help, type: "get-help Unlock-ADAccount -online"


