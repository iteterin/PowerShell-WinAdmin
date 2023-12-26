<#
    Changed: 2023.12.26
    #CHANGEME - Изменить параметры LDAP запроса
#>

[CmdletBinding(
    SupportsShouldProcess=$true,
    ConfirmImpact="High"
)]
param(
    [Parameter(Position=0,
        Mandatory=$true,
        HelpMessage="Введите полный путь до директории с профилями")]
    [ValidateScript( {Test-Path -Path $_} )]
    [string]
    $Path,
    [Parameter(Position=1,
        Mandatory=$true,
        ParameterSetName="FR",
        HelpMessage="Введите полный путь до директории на том же логическом разделе для перемещения профилей и последующего резервного копирования")]
    [string]
    $Destination,
    [Parameter(Position=2,
        Mandatory=$true,
        HelpMessage="Введите количество дней после увольнения для совершения действия")]
    [ValidateRange( 0, 2147483647 )]
    [int32]
    $Days,
    [Parameter(Position=3,
        Mandatory=$true,
        ParameterSetName="UPM",
        HelpMessage="Удалить профиль")]
    [switch]
    $Remove,
    [Parameter(Mandatory=$false,
        HelpMessage="Укажите шаблон именования профилей")]
    [ValidateSet( "UserName", "UserName.Domain", "UserName.v#" )]
    [string]
    $Pattern,
    [Parameter(Mandatory=$false,
        HelpMessage="Введите исключения по обработке (через запятую)")]
    [string[]]
    $Exclude = "",
    [parameter(Mandatory=$false,
        HelpMessage="Введите путь для размещения log-файла")]
    [string]
    $Log,
    [parameter(Mandatory=$false,
        HelpMessage="Удалять/перемещать профили без подтверждения")]
    [Switch]
    $Force,
    [parameter(Mandatory=$false,
        HelpMessage="Директория в параметре Path также используется для размещения Home профилей")]
    [Switch]
    $HomeDirectory,
    [parameter(Mandatory=$false,
        ParameterSetName="FR",
        HelpMessage="Удалять/перемещать профили не состоящие в AD группах (через запятую)")]
    [ValidateScript( {foreach($group in $_) {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]'')
            $searcher.filter = "(&(objectClass=group)(objectCategory=group)(sAMAccountName= $group))"
            $searcher.SizeLimit = 100
            $groups = @($searcher.findall())
            if ( $groups.Count -eq 1 ) { $true } else { $false }
        }
        } )]
    [string[]]
    $FRGroupName
)
Begin {

    $dfsrconfig=Get-FsrmSetting
    $totalremove=0
    $totalmove=0
    #$unknownusers=0
    #$firedusers=0
    $freespace=0
    $to=$dfsrconfig.AdminEmailAddress
    $from=$dfsrconfig.FromEmailAddress
    #$body=@()
    $htmlbody="<html><body><h3>$($env:COMPUTERNAME)</h3>"
    $smtp=$dfsrconfig.SmtpServer
    $subject="Clear fired employees from $($env:COMPUTERNAME)"

    if (-not $Log) { $Log = "{0}\{1}_{2:yyyyMMdd_HH_mm_ss}.{3}" -f (Get-Item -Path $Path\..).FullName, ($MyInvocation.MyCommand.Name -replace [regex]::Escape(".ps1")), (Get-Date), "log" }
    else { $Log = "{0}\{1}_{2:yyyyMMdd_HH_mm_ss}.{3}" -f (Get-Item -Path $Path\..).FullName, ($MyInvocation.MyCommand.Name -replace [regex]::Escape(".ps1")), (Get-Date), "log" }
    Write-Debug "Log Path: `"$($Log)`""
    if ($Log) { "Start: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date) | Out-File -FilePath $Log -Encoding utf8 -Force -Confirm:$false }

    Write-Debug "Path: `"$($Path)`""
    Write-Debug "Destination: `"$($Destination)`""
    Write-Debug "Days: `"$($Days)`""
    Write-Debug "Remove: `"$($Remove)`""

    function Get-ADSIUser {
        param (
        [Parameter(Mandatory=$true)]
        [string]
        $Filter
        )
        process {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]'LDAP://DC=lab,DC=local') #CHANGEME 'LDAP://DC=lab,DC=local'
            $searcher.filter = $filter
            $searcher.SizeLimit = 100
            try {
                return $searcher.findall()
            } catch [System.Management.Automation.MethodInvocationException] {
                Write-Error $_ -ea Continue
                return "SearchError"
            }
        }
    }

    $items = Get-ChildItem $Path -Force -Exclude $Exclude | Where-Object{$_.PSIsContainer}
    if ($Destination) {
        if ( -not (Test-Path $Destination) ) {
            Write-Verbose "Create new directory: $($Destination)"
            New-Item -Path $Destination -ItemType Directory -Force -Confirm:$false
        }
    }
    $blankPath = New-Item -Path "$($Path)\blank_folder" -ItemType Directory -Force -Confirm:$false

    if ($Force) { $ConfirmPreference = "None" }
}
Process {
    $items | ForEach-Object{ 
	    $fullPath = $_.FullName
        $folderName = $_.Name
        $cDestination = "{0}\{1}" -f $Destination, $folderName
        $username = $null
        $owner = (Get-Acl -Path $_.FullName).Owner -replace "\w+\\",""
    
        if ($folderName -notmatch $owner) {
            switch ($Pattern) {
                "UserName" { $username = $folderName }
                "UserName.Domain" { $username = $folderName -replace "\.\w+$", "" }
                "UserName.v#" { $username = $folderName -replace "\.v[0-9]{1}$", "" }
                default { $username = $folderName }
            }
        } else {
            switch ($Pattern) {
                "UserName" { $username = $folderName }
                "UserName.Domain" { $username = $folderName -replace "\.\w+$", "" }
                "UserName.v#" { $username = $folderName -replace "\.v[0-9]{1}$", "" }
                default { $username = $owner }
            }
        }

        if ($username) {
            #Write-Verbose ("Username is {0}" -f $username)
            $users = $null
            $filter = $null
            if ($HomeDirectory) {
                $filter = "(&(objectClass=user)(objectCategory=person)(|(sAMAccountName= $username)(homeDirectory= *\$username)))"
                #Write-Verbose $filter
            } else {
                $filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName= $username))"
            }

            $searcherResult = Get-ADSIUser -Filter $filter
            if ($searcherResult -eq "SearchError") {
                Write-Verbose ("AD search failed on user: {2}; Path: {1}" -f (Get-Date), $fullPath, $username)
                if ($Log) { "{0:HH:mm:ss} Error: AD search failed on user: {2}; Path: {1}" -f (Get-Date), $fullPath, $username | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
            } else {
                try {
                    if ($HomeDirectory) {
                        $users = @($searcherResult | Where-Object{ ($_.Properties.samaccountname[0] -eq $username) -or ($_.Properties.homedirectory[0] -match $username) })
                    } else {
                        $users = @($searcherResult | Where-Object{ $_.Properties.samaccountname[0] -eq $username })
                    }
                } catch [System.Management.Automation.RuntimeException] {
                    $users = @()
                }

                if ($users.Count -eq 1) {
                    $user = $users[0]
                    $userDescription = $user.Properties.description[0]

			        #Write-Verbose $userDescription

                    if ( $FRGroupName ) {
                        $isFRGroupMember = $false
                        foreach ($FRGroup in $FRGroupName) {
                            $memberOfGroups = $user.Properties.memberof
                            foreach ($memberOfGroup in $memberOfGroups) {
                                if ( $memberOfGroup -match "^$([regex]::Escape("CN=$($FRGroupName)"))," ) {
                                    $isFRGroupMember = $true
                                }
                            }
                        }
                    }
                    #CHANGEME - Поиск по полю в AD УВОЛЕН, если не уволен - то по наличию в АД
                    if (-not $?) { Write-Verbose "Empty description for $($user.Properties.samaccountname[0])" }
                    if ( ($userDescription -match "^Уволен,") -and [bool]($user.Properties.useraccountcontrol[0] -band 0x000002) ) {
                        $fairDate = $null
                        $fairDate = [datetime]::ParseExact( ($userDescription -replace "\s","" -replace "^Уволен,\((\d+\-\w+\-\d+)\),.+$", "`$1"), `
                            'dd-MMM-yy',[Globalization.CultureInfo]::InvariantCulture)
                        if ( $? -and ((Get-Date) - $fairDate).Days -gt $Days ) {
                            Write-Verbose ("Username is {0}; Fair date: {1}" -f $username, $fairDate)
                            if ($Remove) {
                                if ($PSCmdlet.ShouldProcess($fullPath, "Remove")) {
                                    #Remove
                                    Write-Verbose "Remove $($fullPath); Owner: $($username)"
                                    $totalremove += 1
                                    try {
                                        
                                        $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                                    }
                                    catch {
                                    }
                                    Remove-Item -Path $fullPath -Recurse -Force -Confirm:$false
                                    if ($Log -and $?) { "{0:HH:mm:ss} Remove: {1}" -f (Get-Date), $fullPath | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                                    if (-not $?) {
                                        Write-Verbose "Remove $($fullPath); Owner: $($owner); Option: LongPathFix"
                                        Start-Process robocopy -ArgumentList "$($blankPath) $($fullPath) /PURGE" -NoNewWindow -Wait
                                        Remove-Item -Path $fullPath -Recurse -Force -Confirm:$false
                                        if ($Log -and $?) { "{0:HH:mm:ss} Remove: {1}" -f (Get-Date), $fullPath | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                                    }
                                }
                                else {
                                    $totalremove += 1
                                     try {
                                         
                                         $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                                     }
                                     catch {
                                     }
                                 }
                             } elseif ($Destination) {
                                if ($PSCmdlet.ShouldProcess($fullPath, "Move")) {
                                    #Move
                                    $totalmove += 1
                                    try {
                                        
                                        $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                                    }
                                    catch {
                                    }
                                    Write-Verbose "Move $($fullPath) to $($cDestination); Owner: $($username)"
                                    Move-Item -Path $fullPath -Destination $cDestination -Force -Confirm:$false
                                    if ($Log -and $?) { "{0:HH:mm:ss} Move: {1} to {2}" -f (Get-Date), $fullPath, $cDestination | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                                }
                                else {
                                    $totalmove += 1
                                    try {
                                        
                                        $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                                    }
                                    catch {
                                    }
                                }
                            }
                        } elseif (-not $fairDate) {
                            Write-Verbose "Description for $($user.Properties.samaccountname[0]) - `"$($userDescription)`""
                        }
                    } elseif ( $FRGroupName -and (-not $isFRGroupMember) -and $Destination ) {
                        Write-Verbose "User: $($username) is not a member of $($FRGroupName -join ", ")"
                        if ($PSCmdlet.ShouldProcess($fullPath, "Move")) {
                            #Move
                            $totalmove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                            Write-Verbose "User: $($username) is not a member of $($FRGroupName -join ", ")"
                            Write-Verbose "Move $($fullPath) to $($cDestination); Owner: $($username)"
                            Move-Item -Path $fullPath -Destination $cDestination -Force -Confirm:$false
                            if ($Log -and $?) { "{0:HH:mm:ss} Move: {1} to {2}" -f (Get-Date), $fullPath, $cDestination | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                        }
                        else {
                            $totalmove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                        }
                    }
                } elseif ($users.Count -eq 0) {
                    Write-Verbose ("Username is {0}; Not found" -f $username)
                    if ($Remove) {
                        if ($PSCmdlet.ShouldProcess($fullPath, "Remove")) {
                            #Remove
                            $totalremove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                            Write-Verbose "Remove $($fullPath); Owner: $($owner)"
                            Remove-Item -Path $fullPath -Recurse -Force -Confirm:$false
                            if ($Log -and $?) { "{0:HH:mm:ss} Remove: {1}" -f (Get-Date), $fullPath | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                            if (-not $?) {
                                Write-Verbose "Remove $($fullPath); Owner: $($owner); Option: LongPathFix"
                                Start-Process robocopy -ArgumentList "$($blankPath) $($fullPath) /PURGE" -NoNewWindow -Wait
                                Remove-Item -Path $fullPath -Recurse -Force -Confirm:$false
                                if ($Log -and $?) { "{0:HH:mm:ss} Remove: {1}" -f (Get-Date), $fullPath | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                            }
                        }
                        else {
                            $totalremove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                        }
                    } elseif ($Destination) {
                        if ($PSCmdlet.ShouldProcess($fullPath, "Move")) {
                            #Move
                            $totalmove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                            Write-Verbose "Move $($fullPath) to $($cDestination)"
                            Move-Item -Path $fullPath -Destination $cDestination -Force -Confirm:$false
                            if ($Log -and $?) { "{0:HH:mm:ss} Move: {1} to {2}" -f (Get-Date), $fullPath, $cDestination | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false }
                        }
                        else {
                            $totalmove += 1
                            try {
                                        
                                $freespace += (Get-FSRMQuota -Path $fullPath -ErrorAction Stop).Usage
                            }
                            catch {
                            }
                        }
                    }
                } else {
                    Write-Verbose ("Users with name `"{0}`": {1:D}" -f $username, $users.Count)
                }
            }
        }
    }
}
End {
    if ( Test-Path -Path $blankPath ) {
        if ( @(Get-ChildItem -Path $blankPath -Force).Count -eq 0 ) {
            Write-Verbose "Remove blank directory for long path"
            Remove-Item -Path $blankPath -Force -Confirm:$false
        } else {
            Write-Verbose "Blank directory for long path not empty"
        }
    }

    $htmlbody = $htmlbody + "<b>"+(Get-Date).ToString()+"</b>"
    if ($Remove) {
        Write-Verbose "Remove $totalremove directories"

        $htmlbody = $htmlbody + "<p>Remove <b>$totalremove</b> directories</p>"
    }
    else {
        Write-Verbose "Move $totalmove directories"
        $htmlbody = $htmlbody + "<p>Move <b>$totalmove</b> directories</p>"
    }
    Write-Verbose "Release $($freespace / 1Gb) Gb"
    $htmlbody = $htmlbody + "<p>Release <b>$($freespace / 1Gb)</b> Gb</p>"

    $htmlbody = $htmlbody + "</body></html>"

    if ($Log) {
        "End: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date) | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false 
        if ($Remove) {
            "Remove $totalremove directories: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date) | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false
        }
        else {
            "Move $totalmove directories: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date) | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false
        }
        "Release $($freespace / 1Gb) Gb: {0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date) | Out-File -FilePath $Log -Encoding utf8 -Append -Confirm:$false
        
        if ($PSCmdlet.ShouldProcess($log, "Send log to email")) {
            foreach ($item in $to) {
                Send-MailMessage -Attachments $Log -Body $htmlbody -From $from -To $item -Subject $subject -BodyAsHtml -Encoding UTF8 -SmtpServer $smtp
            }
        }
        else {
            foreach ($item in $to) {
                Send-MailMessage -Body $htmlbody -From $from -To $item -Subject $subject -BodyAsHtml -Encoding UTF8 -SmtpServer $smtp
            }
        }
    }
    else {
        foreach ($item in $to) {
            Send-MailMessage -Body $htmlbody -From $from -To $item -Subject $subject -BodyAsHtml -Encoding UTF8 -SmtpServer $smtp
        }
    }
}
<#
    .SYNOPSIS
        Очищает FolderRedirection и Citrix Profile Manager профили от уволенных сотрудников.

    .DESCRIPTION
        Перемещает FolderRedirection или удаляет Citrix Profile Manager профили уволенных сотрудников по количеству дней указанных в параметре "Days".
        Всегда использовать с параметром "-WhatIf" для первого запуска (режим логирования на экран, без реального выполнения действий).

    .PARAMETER Path
        Путь к folder redirection или citrix profile manager хранилищу.

    .PARAMETER Destination
        Путь для перемещения folder redirection профилей. Не используется совместно с параметром "Remove".

    .PARAMETER Days
        Количество дней после увольнения для выполнения перемещения FR или удаления UPM профилей.

    .PARAMETER Remove
        Switch параметр для UPM. Не используется совместно с параметром "Destination".

    .PARAMETER Pattern
        Шаблон именования для директории с профилем в случае, если обладатель директории не равен имени директории. Возможные значения: "UserName", "UserName.Domain", "UserName.v#".

    .PARAMETER Exclude
        Список для исключения директорий. Поддерживается использование подстановочных знаков (wildcard).

    .PARAMETER Log
        Путь до директории для сохранения лог файлов.

    .PARAMETER HomeDirectory
        Switch параметр для указания, что путь в параметре Path также используется для Home-профилей. Необязательный параметр, без него проверка проходит намного быстрее.

    .PARAMETER FRGroupName
        Список AD групп пользователей, которые размещаются в директории, указанной в параметре Path. В случае отсутствия членства профиль будет удален или перемещен. Необязательный параметр, без него членство в группах не проверяется.

    .PARAMETER Force
        Принудительное выполнения действий. Без подтверждения.

    .EXAMPLE
        C:PS> Remove-MegaProfileItem.ps1 -Path "D:\FR" -Destination "D:\FR_Bkp" -Days 90
        Перемещает профили уволенных сотрудников более 90 дней назад из "D:\FR" в "D:\FR_Bkp" с подтверждением действия.  

    .EXAMPLE
        C:PS> Remove-MegaProfileItem.ps1 -Path "D:\UPM" -Days 90 -Remove
        Удаляет профили уволенных сотрудников более 90 дней назад из "D:\UPM" с подтверждением действия.

    .EXAMPLE
        C:PS> Remove-MegaProfileItem.ps1 -Path "D:\FR" -Destination "D:\FR_Bkp" -Days 90 -Verbose -Force
        Перемещает профили уволенных сотрудников более 90 дней назад из "D:\FR" в "D:\FR_Bkp" без подтверждения и с выводом подробной информации.

    .EXAMPLE
        C:PS> Remove-MegaProfileItem.ps1 -Path "D:\FR" -Destination "D:\FR_Bkp" -Days 90 -HomeDirectory -Verbose -Force
        Перемещает профили уволенных сотрудников более 90 дней назад из "D:\FR" в "D:\FR_Bkp" без подтверждения и с выводом подробной информации c дополнительной проверкой на Home-путь.

    .EXAMPLE
        C:PS> Remove-MegaProfileItem.ps1 -Path "D:\FR" -Destination "D:\FR_Bkp" -Days 90 -FRGroupName FR-UserGroup1,FR-UserGroup2 -Verbose -Force
        Перемещает профили уволенных сотрудников более 90 дней назад, а также профили сотрудников не состоящие в группах FR-UserGroup1 и FR-UserGroup2, из "D:\FR" в "D:\FR_Bkp" без подтверждения и с выводом подробной информации.
#>
