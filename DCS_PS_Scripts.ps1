import-module activedirectory
function Show-Menu
 {
            Clear-Host
            Write-Host “================ DCS-Bitlocker ================”
            Write-Host “1: Press ‘1’ to get Bitlocker by using computer name.”`n`

            Write-Host “================ DCS-Loaner Computer -Local Users ================”
            Write-Host “2: Press ‘2’ to add user to the target Loaner group as User Privilege”
            Write-Host “3: Press ‘3’ to remove user from target Loaner (User Group)”
            Write-Host “4: Press ‘4’ to list all users for target Loaner (Local Users Group)" `n`
            

            Write-Host “================ DCS-Loaner Computer- Local Admins ================”
            Write-Host “5: Press ‘5’ to add user to the target Loaner group as Admin Privilege”
            Write-Host “6: Press ‘6’ to remove user from target Loaner (Admin Group)”
            Write-Host “7: Press ‘7’ to list all users from target Loaner (Local Admins Group)" `n`

            Write-Host “================ DCS-Loaner Computer- Clean Groups ================”
            Write-Host “8: Press ‘8’ to clean target Loaner computer (Local Users Group)"
            Write-Host “9: Press ‘9’ to clean target Loaner computer (Local Admins Group)" `n`
            
            Write-Host “================ Search for computer in all SPSS activation groups  ================”
            Write-Host “10: Press ‘10’ to search for computer name in SPSS activation group” `n`

            Write-Host “== Add computer name to SPSS Activation Demo Group (Permission needed to use this option)===”
            Write-Host “11: Press ‘11’ to search for computer name in SPSS activation group” `n`

            Write-Host “======== Get LAPS Password========”
            Write-Host “12: Press ‘12’ to Get LAPS Password” `n`

            Write-Host “Q: Press ‘Q’ to quit.”
 }

 do
 {
            Show-Menu
            $input = Read-Host “Please make a selection”
            switch ($input)
            { ‘1’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter computer name"
                 $objComputer = Get-ADComputer $ComputerName
                 $Bitlocker_Object = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
                 $Bitlocker_Object
            } ‘2’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $UserName = Read-Host -Prompt "Enter user name"
                 $GroupName = "GRP_QUAD_LocalUsers_$ComputerName"
                 Add-ADGroupMember -Identity $GroupName -Members $UserName
                 $Members_Group = Get-ADGroupMember -Identity $GroupName
                 $IsMember = $Members_Group | Where-Object { $_.Name -eq $ComputerName }
                 if ($IsMember) { 
                        Write-Host "$ComputerName is a member of $GroupName"  -ForeGroundColor Green `n`
                   } else {  
                        Write-Host "$ComputerName is NOT a member of $GroupName" -ForeGroundColor Red `n`
                   }

                 $GRP_Object = Get-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" | ft
                 $GRP_Object

                 #$users = Get-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" | Get-ADUser -Properties SamAccountName | Select SamAccountName

             } ‘3’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $UserName = Read-Host -Prompt "Enter user name"
                 Remove-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" -Members $UserName
                 Get-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" | ft
             } ‘4’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $GRP_Object = Get-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" | ft
                 $GRP_Object
             } ‘5’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $UserName = Read-Host -Prompt "Enter user name"
                 Add-ADGroupMember -Identity "GRP_QUAD_LocalAdmins_$ComputerName" -Members $UserName
                 $GRP_Object= Get-ADGroupMember -Identity "GRP_QUAD_LocalAdmins_$ComputerName" | ft
                 $GRP_Object
             } ‘6’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $UserName = Read-Host -Prompt "Enter user name"
                 Remove-ADGroupMember -Identity "GRP_QUAD_LocalAdmins_$ComputerName" -Members $UserName
                 Get-ADGroupMember -Identity "GRP_QUAD_LocalAdmins_$ComputerName" | ft
             } ‘7’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 $GRP_Object = Get-ADGroupMember -Identity "GRP_QUAD_LocalAdmins_$ComputerName" | ft
                 $GRP_Object
             } ‘8’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 Get-ADGroupMember "GRP_QUAD_LocalUsers_$ComputerName" | ForEach-Object {Remove-ADGroupMember "GRP_QUAD_LocalUsers_$ComputerName" -Confirm:$false}
            
                 #$users = Get-ADGroupMember -Identity "GRP_QUAD_LocalUsers_$ComputerName" | Get-ADUser -Properties SamAccountName | Select SamAccountName
            } ‘9’ {
                 cls
                 $ComputerName = Read-Host -Prompt "Enter Computer loaner name"
                 Get-ADGroupMember "GRP_QUAD_LocalAdmins_$ComputerName" | ForEach-Object {Remove-ADGroupMember "GRP_QUAD_LocalAdmins_$ComputerName" -Confirm:$false}
             } ‘10’ {
                 cls
                 # Define the group name and the computer name  
                   $GroupName = "CN=GRP_SCCM_App_Device_IBM_SPSS_Statistics_Demo,OU=ConfigMgrApplicationsDeviceAccess,OU=AppsIntegration,OU=Groups,DC=qu,DC=edu,DC=qa"
                   $GroupName_2 = "CN=GRP_SCCM_App_Device_IBM_SPSS_Statistics_licensed_x64,OU=ConfigMgrApplicationsDeviceAccess,OU=AppsIntegration,OU=Groups,DC=qu,DC=edu,DC=qa"  
                   $ComputerName = Read-Host -Prompt "Enter Computer name"
                   $ComputerName = $ComputerName.ToUpper()

                 # Get the members of the group  
                   $Members_SPSS_Demo = Get-ADGroupMember -Identity $GroupName
                   $Members_SPSS_Device_licensed_x64 = Get-ADGroupMember -Identity $GroupName_2  

                 # Check if the specified computer is a member of the Demo group  
                   $IsMember = $Members_SPSS_Demo | Where-Object { $_.Name -eq $ComputerName }  
                   $GroupName = "GRP_SCCM_App_Device_IBM_SPSS_Statistics_Demo"
                   if ($IsMember) { 
                        Write-Host "$ComputerName is a member of $GroupName"  -ForeGroundColor Green `n`
                   } else {  
                        Write-Host "$ComputerName is NOT a member of $GroupName" -ForeGroundColor Red `n`
                   }

                   # Get count of group members
                   $MemberCount = (Get-ADGroup $GroupName -Properties *).Member.Count
                   Write-Host "There are $MemberCount Computer devices Member in Securtiy Group Name: $GroupName" -ForegroundColor Yellow `n`
                   
                   # Check if the specified computer is a member of the Demo group  
                   $IsMember_2 = $Members_SPSS_Device_licensed_x64 | Where-Object { $_.Name -eq $ComputerName }  
                   $GroupName_2 = "GRP_SCCM_App_Device_IBM_SPSS_Statistics_licensed_x64"
                   if ($IsMember_2) {
                         
                        Write-Host "$ComputerName is a member of $GroupName_2" -ForeGroundColor Green `n`
                   } else {  
                        Write-Host "$ComputerName is NOT a member of $GroupName_2" -ForeGroundColor Red `n`
                   }

                   # Get count of group members
                   $MemberCount_2 = (Get-ADGroup $GroupName_2 -Properties *).Member.Count
                   Write-Host "There are $MemberCount_2 Computer devices Member in Securtiy Group Name: $GroupName_2" -ForegroundColor Yellow `n`
            } ‘11’ {
                cls
                # Define the computer name and the distinguished name of the security group
                $computerName = Read-Host -Prompt "Enter Computer Name"
                $groupDN = "CN=GRP_SCCM_App_Device_IBM_SPSS_Statistics_Demo,OU=ConfigMgrApplicationsDeviceAccess,OU=AppsIntegration,OU=Groups,DC=qu,DC=edu,DC=qa" 
                 
                 #Get-ADComputer -LDAPFilter "(name=$computerName)" -searchbase "OU=QU_Computers,DC=qu,DC=edu,DC=qa" #| Add-ADPrincipalGroupMembership -MemberOf $groupDN
                 Add-ADGroupMember -Identity $groupDN -Members (Get-ADComputer $computerName)
                 $GRP_Object = Get-ADGroupMember -Identity "$groupDN" | ft SamAccountName
                 $GRP_Object
                 
            } ‘12’ {
                cls
                # Define the LAPS password anf history by using computer name 
                 
                #Get-LapsADPassword -Identity $ComputerName -AsPlainText -IncludeHistory
                 
                

                # Specify the computer name  
                $computerName = Read-Host -Prompt "Enter Computer Name"
                $computerName = $computerName.ToUpper()  
                #Get-LapsADPassword -Identity $computerName -AsPlainText

                # Retrieve the password and history  
                $passwordInfo = Get-LapsADPassword -Identity $computerName -AsPlainText 

                # Check if the password is retrieved successfully  
                if ($passwordInfo) {  
                    # Display the password in a different color  
                    Write-Host "Current LAPS Password for $computerName :" -ForegroundColor Green  
                    Write-Host $passwordInfo.Password -ForegroundColor Yellow `n`
                    
                    $PasswordUpdateTime = $passwordInfo.PasswordUpdateTime 
                    $PasswordExpireDate = $passwordInfo.ExpirationTimestamp
                    Write-Host "Password Update Time: $PasswordUpdateTime" -ForegroundColor Green
                    Write-Host "Password Expiration Date: $PasswordExpireDate"  -ForegroundColor Red `n`  
                      

                    # Display password history  
                    Write-Host "Password History:" -ForegroundColor Green  
                    foreach ($entry in $passwordInfo.PasswordHistory) {  
                            Write-Host $entry -ForegroundColor Gray  
                            }  
                } else {  
                    Write-Host "Failed to retrieve password for $computerName." -ForegroundColor Red  
                }
                     
            } ‘q’ {
                 return
            }
            }
            pause
 }
 until ($input -eq ‘q’)
