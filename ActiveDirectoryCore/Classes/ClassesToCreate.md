# Classes Needed for Input Validation


### [ADUser]

    Distinguished Name
    Example:  CN=SaraDavis,CN=Europe,CN=Users,DC=corp,DC=contoso,DC=com
    GUID (objectGUID)
    Security Identifier (objectSid)
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
