### Get/Validate Domain


    Domain name values:
        
        Fully qualified domain name
        Examples: corp.contoso.com
        
        NetBIOS name
        Example: CORP
        
        Directory server values:
        
            Fully qualified directory server name
            Example: corp-DC12.corp.contoso.com
        
            NetBIOS name
            Example: corp-DC12
        
        Fully qualified directory server name and port
        Example: corp-DC12.corp.contoso.com:3268
        
        The default value for the Server parameter is determined by one of the following methods in the order that 
        they are listed:
        
            -By using Server value from objects passed through the pipeline.
        
            -By using the server information associated with the Active Directory PowerShell provider drive, when running 
            under that drive.
        
            -By using the domain of the computer running Powershell.
        
        The following example shows how to specify a full qualified domain name as the parameter value.
        
            -Server "corp.contoso.com"