# Classes Needed for Input Validation


### [ADUser]

    Distinguished Name
    Example:  CN=SaraDavis,CN=Europe,CN=Users,DC=corp,DC=contoso,DC=com
    GUID (objectGUID)    Example: 599c3d2e-f72d-4d20-8a88-030d99495f20
    Security Identifier (objectSid)    Example: S-1-5-21-3165297888-301567370-576410423-1103
    SAM account name  (sAMAccountName)
    Example: saradavis

### [ADAuthType]

    [ValidateSet('Negotiate','Basic')]
	[System.DirectoryServices.Protocols.AuthType]$AuthType

### [ADSearchScope]

    Base or 0
    OneLevel or 1
    Subtree or 2
    
    [ValidateSet('Base',0,'OneLevel',1,'Subtree',2)]
	$SearchScope

