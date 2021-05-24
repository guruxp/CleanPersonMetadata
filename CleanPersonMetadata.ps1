[cmdletbinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = "High"
)]
param(
    [parameter( Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "All")]
    [alias('Mailbox')]
    [string]$Identity,
    #[parameter( Mandatory = $false, ParameterSetName = "All")]
    #[switch]$Impersonation,
    [parameter( Mandatory = $false, ParameterSetName = "All")]
    [System.Management.Automation.PsCredential]$Credentials,
    [switch]$NoProgressBar,
    [parameter( Mandatory = $false, ParameterSetName = "All")]
    [switch]$Report
)

process {
    #HardDefinitions
    $DeleteMode = "HardDelete"
    $ScanAllFolders = $true
    $MessageClass = "IPM.AbchPerson*"
    $IncludeFolders = "*\PersonMetadata"
    $MailboxOnly = "$true"
    $Server = "outlook.office365.com"
    $Impersonation = $true


    $script:MaxFolderBatchSize = 100
    $script:MaxItemBatchSize = 1000
    $script:MaxDeleteBatchSize = 100

    #Avoid throttle by putting script asleep in ms
    $script:SleepTimerMax = 300000               
    $script:SleepTimerMin = 100                  
    $script:SleepAdjustmentFactor = 2.0          
    $script:SleepTimer = $script:SleepTimerMin   

    #Errors
    $ERR_EWSDLLNOTFOUND = 1000
    $ERR_EWSLOADING = 1001
    $ERR_MAILBOXNOTFOUND = 1002
    $ERR_AUTODISCOVERFAILED = 1003
    $ERR_CANTACCESSMAILBOXSTORE = 1004
    $ERR_PROCESSINGMAILBOX = 1005
    $ERR_PROCESSINGARCHIVE = 1006
    $ERR_INVALIDCREDENTIALS = 1007

    Function Get-EmailAddress( $Identity) {
        $address = [regex]::Match([string]$Identity, ".*@.*\..*", "IgnoreCase")
        if ( $address.Success ) {
            return $address.value.ToString()
        }
    }

    Function Load-EWSManagedAPIDLL {
        $EWSDLL = "Microsoft.Exchange.WebServices.dll"
        If ( Test-Path "$pwd\$EWSDLL") {
            $EWSDLLPath = "$pwd"
        }
        Else {
            $EWSDLLPath = (($(Get-ItemProperty -ErrorAction SilentlyContinue -Path Registry::$(Get-ChildItem -ErrorAction SilentlyContinue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Exchange\Web Services'|Sort-Object Name -Descending| Select-Object -First 1 -ExpandProperty Name)).'Install Directory'))
            if (!( Test-Path "$EWSDLLPath\$EWSDLL")) {
                Write-Error "EWS Managed API 1.2 or greater is needed"
                Write-Error "You can download and install EWS Managed API from http://www.microsoft.com/download/details.aspx?id=42951"
                Exit $ERR_EWSDLLNOTFOUND
            }
        }

        Write-Verbose "Loading $EWSDLLPath\$EWSDLL"
        try {
            # EX2010
            If (!( Get-Module Microsoft.Exchange.WebServices)) {
                Import-Module "$EWSDLLPATH\$EWSDLL"
            }
        }
        catch {
            #<= EX2010
            [void][Reflection.Assembly]::LoadFile( "$EWSDLLPath\$EWSDLL")
        }
        try {
            $Temp = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1
        }
        catch {
            Write-Error "Problem loading $EWSDLL"
            Exit $ERR_EWSLOADING
        }
        $DLLObj = Get-ChildItem -Path "$EWSDLLPATH\$EWSDLL" -ErrorAction SilentlyContinue
        If ( $DLLObj) {
            Write-Verbose ('Loaded EWS Managed API')
        }
    }

    
    Function set-TrustAllWeb() {
        Write-Verbose "Set to trust all certificates"
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $False
        $Params.GenerateInMemory = $True
        $Params.IncludeDebugInformation = $False
        $Params.ReferencedAssemblies.Add("System.DLL") | Out-Null

        $TASource = @'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy {
                public class TrustAll : System.Net.ICertificatePolicy {
                    public TrustAll() {
                    }
                    public bool CheckValidationResult(System.Net.ServicePoint sp, System.Security.Cryptography.X509Certificates.X509Certificate cert,   System.Net.WebRequest req, int problem) {
                        return true;
                    }
                }
            }
'@

        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }

    Function iif( $eval, $tv = '', $fv = '') {
        If ( $eval) { return $tv } else { return $fv}
    }

    Function Construct-FolderFilter {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            [string[]]$Folders,
            [string]$emailAddress
        )
        If ( $Folders) {
            $FolderFilterSet = @()
            ForEach ( $Folder in $Folders) {
                $Parts = $Folder -match '^(?<root>\\)?(?<keywords>.*?)?(?<sub>\\\*)?$'
                If ( !$Parts) {
                    Write-Error ('Invalid regular expression matching against {0}' -f $Folder)
                }
                Else {
                    $Keywords = Search-ReplaceWellKnownFolderNames $EwsService ($Matches.keywords) $emailAddress
                    $EscKeywords = [Regex]::Escape( $Keywords) -replace '\\\*', '.*'
                    $Pattern = iif -eval $Matches.Root -tv '^\\' -fv '^\\(.*\\)*'
                    $Pattern += iif -eval $EscKeywords -tv $EscKeywords -fv ''
                    $Pattern += iif -eval $Matches.sub -tv '(\\.*)?$' -fv '$'
                    $Obj = New-Object -TypeName PSObject -Prop @{
                        'Pattern'     = $Pattern;
                        'IncludeSubs' = -not [string]::IsNullOrEmpty( $Matches.Sub)
                        'OrigFilter'  = $Folder
                    }
                    $FolderFilterSet += $Obj
                    Write-Debug ($Obj -join ',')
                }
            }
        }
        Else {
            $FolderFilterSet = $null
        }
        return $FolderFilterSet
    }

    Function Search-ReplaceWellKnownFolderNames {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            [string]$criteria = '',
            [string]$emailAddress
        )
        $AllowedWKF = 'Inbox', 'Calendar', 'Contacts', 'Notes', 'SentItems', 'Tasks', 'JunkEmail', 'DeletedItems', 'Root'
        # Construct regexp to see if allowed WKF is part of criteria string
        ForEach ( $ThisWKF in $AllowedWKF) {
            If ( $criteria -match '#{0}#') {
                $criteria = $criteria -replace ('#{0}#' -f $ThisWKF), (myEWSBind-WellKnownFolder $EwsService $ThisWKF $emailAddress).DisplayName
            }
        }
        return $criteria
    }
    Function Tune-SleepTimer {
        param(
            [bool]$previousResultSuccess = $false
        )
        if ( $previousResultSuccess) {
            If ( $script:SleepTimer -gt $script:SleepTimerMin) {
                $script:SleepTimer = [int]([math]::Max( [int]($script:SleepTimer / $script:SleepAdjustmentFactor), $script:SleepTimerMin))
                Write-Warning ('Previous EWS operation successful, adjusted sleep timer to {0}ms' -f $script:SleepTimer)
            }
        }
        Else {
            $script:SleepTimer = [int]([math]::Min( ($script:SleepTimer * $script:SleepAdjustmentFactor) + 100, $script:SleepTimerMax))
            If ( $script:SleepTimer -eq 0) {
                $script:SleepTimer = 5000
            }
            Write-Warning ('Previous EWS operation failed, adjusted sleep timer to {0}ms' -f $script:SleepTimer)
        }
        Start-Sleep -Milliseconds $script:SleepTimer
    }

    Function myEWSFind-Folders {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            [Microsoft.Exchange.WebServices.Data.FolderId]$FolderId,
            [Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection]$FolderSearchCollection,
            [Microsoft.Exchange.WebServices.Data.FolderView]$FolderView
        )
        $OpSuccess = $false
        $CritErr = $false
        Do {
            Try {
                $res = $EwsService.FindFolders( $FolderId, $FolderSearchCollection, $FolderView)
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Error performing operation FindFolders with Search options in {0}. Error: {1}' -f $FolderId.FolderName, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    Function myEWSFind-FoldersNoSearch {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            [Microsoft.Exchange.WebServices.Data.FolderId]$FolderId,
            [Microsoft.Exchange.WebServices.Data.FolderView]$FolderView
        )
        $OpSuccess = $false
        $CritErr = $false
        Do {
            Try {
                $res = $EwsService.FindFolders( $FolderId, $FolderView)
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Error performing operation FindFolders without Search options in {0}. Error: {1}' -f $FolderId.FolderName, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    Function myEWSFind-Items {
        param(
            [Microsoft.Exchange.WebServices.Data.Folder]$Folder,
            [Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection]$ItemSearchFilterCollection,
            [Microsoft.Exchange.WebServices.Data.ItemView]$ItemView
        )
        $OpSuccess = $false
        $CritErr = $false
        Do {
            Try {
                $res = $Folder.FindItems( $ItemSearchFilterCollection, $ItemView)
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Error performing operation FindItems with Search options in {0}. Error: {1}' -f $Folder.DisplayName, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    Function myEWSFind-ItemsNoSearch {
        param(
            [Microsoft.Exchange.WebServices.Data.Folder]$Folder,
            [Microsoft.Exchange.WebServices.Data.ItemView]$ItemView
        )
        $OpSuccess = $false
        $CritErr = $false
        Do {
            Try {
                $res = $Folder.FindItems( $ItemView)
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Error performing operation FindItems without Search options in {0}. Error {1}' -f $Folder.DisplayName, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    
    Function myEWSRemove-Items {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            $ItemIds,
            [Microsoft.Exchange.WebServices.Data.DeleteMode]$DeleteMode,
            [Microsoft.Exchange.WebServices.Data.SendCancellationsMode]$SendCancellationsMode,
            [Microsoft.Exchange.WebServices.Data.AffectedTaskOccurrence]$AffectedTaskOccurrences,
            [bool]$SuppressReadReceipt
        )
        $OpSuccess = $false
        $critErr = $false
        Do {
            Try {
                If ( @([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013, [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1) -contains $EwsService.RequestedServerVersion) {
                    $res = $EwsService.DeleteItems( $ItemIds, $DeleteMode, $SendCancellationsMode, $AffectedTaskOccurrences, $SuppressReadReceipt)
                }
                Else {
                    $res = $EwsService.DeleteItems( $ItemIds, $DeleteMode, $SendCancellationsMode, $AffectedTaskOccurrences)
                }
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Error performing operation RemoveItems with {0}. Error: {1}' -f $RemoveItems, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    Function myEWSBind-WellKnownFolder {
        param(
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$EwsService,
            [string]$WellKnownFolderName,
            [string]$emailAddress
        )
        $OpSuccess = $false
        $critErr = $false
        Do {
            Try {
                $explicitFolder= New-Object -TypeName Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Root, $emailAddress)  
                $res = [Microsoft.Exchange.WebServices.Data.Folder]::Bind( $EwsService, $explicitFolder)
                $OpSuccess = $true
            }
            catch [Microsoft.Exchange.WebServices.Data.ServerBusyException] {
                $OpSuccess = $false
                Write-Warning 'EWS operation failed, server busy - Transient failure'
            }
            catch {
                $OpSuccess = $false
                $critErr = $true
                Write-Warning ('Cannot bind to {0} - skipping. Error: {1}' -f $WellKnownFolderName, $Error[0])
            }
            finally {
                If ( !$critErr) { Tune-SleepTimer $OpSuccess }
            }
        } while ( !$OpSuccess -and !$critErr)
        Write-Output -NoEnumerate $res
    }

    Function Get-SubFolders {
        param(
            $Folder,
            $CurrentPath,
            $IncludeFilter,
            $ExcludeFilter,
            $ScanAllFolders
        )
        $FoldersToProcess = [System.Collections.ArrayList]@()
        $FolderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView( $MaxFolderBatchSize)
        $FolderView.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Shallow
        $FolderView.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet(
            [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
            [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,
            [Microsoft.Exchange.WebServices.Data.FolderSchema]::FolderClass)
        $FolderSearchCollection = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection( [Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)
        If ( -not $ScanAllFolders) {
            $FolderSearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo( [Microsoft.Exchange.WebServices.Data.FolderSchema]::FolderClass, "IPF.Note")
            $FolderSearchCollection.Add( $FolderSearchFilter)
        }

        Do {
            If ( $FolderSearchCollection.Count -ge 1) {
                $FolderSearchResults = myEWSFind-Folders $EwsService $Folder.Id $FolderSearchCollection $FolderView
            }
            Else {
                $FolderSearchResults = myEWSFind-FoldersNoSearch $EwsService $Folder.Id $FolderView
            }
            ForEach ( $Folder in $FolderSearchResults) {
                $FolderPath = '{0}\{1}' -f $CurrentPath, $Folder.DisplayName
                If ( $IncludeFilter) {
                    $Add = $false
                    $Subs = $true
                    ForEach ( $Filter in $IncludeFilter) {
                        If ( $FolderPath -match $Filter.Pattern) {
                            $Add = $true
                            $Subs = $Filter.IncludeSubs
                        }
                    }
                }
                Else {
                    $Add = $true
                    $Subs = $true
                }
                If ( $ExcludeFilter) {                    
                    ForEach ( $Filter in $ExcludeFilter) {
                        If ( $FolderPath -match $Filter.Pattern) {
                            $Add = $false                           
                            $Subs = $Filter.IncludeSubs
                        }
                    }
                }
                If ( $Add) {
                    Write-Verbose ( 'Adding folder {0}' -f $FolderPath, $Prio)

                    $Obj = New-Object -TypeName PSObject -Property @{
                        'Name'   = $FolderPath;
                        'Folder' = $Folder
                    }
                    $FoldersToProcess.Add( $Obj) | Out-Null
                }
                If ( $Subs) {                    
                    $SubFolders = Get-SubFolders -Folder $Folder -CurrentPath $FolderPath -IncludeFilter $IncludeFilter -ExcludeFilter $ExcludeFilter -PriorityFilter $PriorityFilter -ScanAllFolders $ScanAllFolders
                    ForEach ( $AddFolder in $Subfolders) {
                        $FoldersToProcess.Add( $AddFolder)  | Out-Null
                    }
                }
            }
            $FolderView.Offset += $FolderSearchResults.Folders.Count
        } While ($FolderSearchResults.MoreAvailable)
        Write-Output -NoEnumerate $FoldersToProcess
    }

    Function Process-Mailbox {
        param(
            [string]$Identity,
            $Folder,
            $IncludeFilter,
            $ExcludeFilter,
            $emailAddress
        )

        $ProcessingOK = $True
        $TotalMatch = 0
        $TotalRemoved = 0
        $FoldersFound = 0
        $FoldersProcessed = 0
        $TimeProcessingStart = Get-Date
        $DeletedItemsFolder = myEWSBind-WellKnownFolder $EwsService 'DeletedItems' $emailAddress

        Write-Verbose (iif $ScanAllFolders -fv 'Collecting folders containing e-mail items to process' -tv 'Collecting folders to process')
        $FoldersToProcess = Get-SubFolders -Folder $Folder -CurrentPath '\' -IncludeFilter $IncludeFilter -ExcludeFilter $ExcludeFilter -ScanAllFolders $ScanAllFolders

        $FoldersFound = $FoldersToProcess.Count
        Write-Verbose ('Found {0} folders matching folder search criteria' -f $FoldersFound)

        ForEach ( $SubFolder in $FoldersToProcess) {
            If (!$NoProgressBar) {
                Write-Progress -Id 1 -Activity "Processing $Identity" -Status "Processed folder $FoldersProcessed of $FoldersFound" -PercentComplete ( $FoldersProcessed / $FoldersFound * 100)
            }
            If ( ! ( $DeleteMode -eq 'MoveToDeletedItems' -and $SubFolder.Id -eq $DeletedItemsFolder.Id)) {
                If ( $Report.IsPresent) {
                    Write-Host ('Processing folder {0}' -f $SubFolder.Name)
                }
                Else {
                    Write-Verbose ('Processing folder {0}' -f $SubFolder.Name)
                }
                $ItemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView( $script:MaxItemBatchSize, 0, [Microsoft.Exchange.WebServices.Data.OffsetBasePoint]::Beginning)
                $ItemView.Traversal = [Microsoft.Exchange.WebServices.Data.ItemTraversal]::Shallow
                $ItemView.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet(
                    [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
                    [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived,
                    [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
                    [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass)

                $ItemSearchFilterCollection = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection([Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)
                If ($MessageClass -match '^\*(?<substring>.*?)\*$') {
                    $ItemSearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring( [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass,
                        $matches['substring'], [Microsoft.Exchange.WebServices.Data.ContainmentMode]::Substring, [Microsoft.Exchange.WebServices.Data.ComparisonMode]::IgnoreCase)
                }
                Else {
                    If ($MessageClass -match '^(?<prefix>.*?)\*$') {
                        $ItemSearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring( [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass,
                            $matches['prefix'], [Microsoft.Exchange.WebServices.Data.ContainmentMode]::Prefixed, [Microsoft.Exchange.WebServices.Data.ComparisonMode]::IgnoreCase)
                    }
                    Else {
                        $ItemSearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo( [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass, $MessageClass)
                    }
                }
                $ItemSearchFilterCollection.add( $ItemSearchFilter)

                If ( $Before) {
                    $ItemSearchFilterCollection.add( (New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThan( [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived, $Before)))
                }

                $ProcessList = [System.Collections.ArrayList]@()
                If ( $psversiontable.psversion.major -lt 3) {
                    $ItemIds = [activator]::createinstance(([type]'System.Collections.Generic.List`1').makegenerictype([Microsoft.Exchange.WebServices.Data.ItemId]))
                }
                Else {
                    $type = ("System.Collections.Generic.List" + '`' + "1") -as 'Type'
                    $type = $type.MakeGenericType([Microsoft.Exchange.WebServices.Data.ItemId] -as 'Type')
                    $ItemIds = [Activator]::CreateInstance($type)
                }

                Do {
                    $ItemSearchResults = MyEWSFind-Items $SubFolder.Folder $ItemSearchFilterCollection $ItemView
                    If (!$NoProgressBar) {
                        Write-Progress -Id 2 -Activity ('Processing folder {0}' -f $SubFolder.Name) -Status ('Found {0} matching items' -f $ProcessList.Count)
                    }
                    If ( $ItemSearchResults.Items.Count -gt 0) {
                        ForEach ( $Item in $ItemSearchResults.Items) {
                            If ( $Report.IsPresent) {
                                Write-Host ('Item: {0} of {1} ({2})' -f $Item.Subject, $Item.DateTimeReceived, $Item.ItemClass)
                            }
                            $ProcessList.Add( $Item.Id)
                        }
                    }
                    Else {
                        Write-Debug "No matching items found"
                    }
                    $ItemView.Offset += $ItemSearchResults.Items.Count
                } While ( $ItemSearchResults.MoreAvailable)
            }
            Else {
                Write-Debug "Skipping DeletedItems folder"
            }
            $TotalMatch += $ItemSearchResults.TotalCount
            If ( ($ProcessList.Count -gt 0) -and $PSCmdlet.ShouldProcess( ('{0} item(s) from {1}' -f $ProcessList.Count, $SubFolder.Name))) {
                If ( $ReplaceClass) {
                    Write-Verbose ('Modifying {0} items from {1}' -f $ProcessList.Count, $SubFolder.Name)
                    $ItemsChanged = 0
                    $ItemsRemaining = $ProcessList.Count
                    ForEach ( $ItemID in $ProcessList) {
                        If (!$NoProgressBar) {
                            Write-Progress -Id 2 -Activity "Processing folder $($SubFolder.DisplayName)" -Status "Items processed $ItemsChanged - remaining $ItemsRemaining" -PercentComplete ( $ItemsRemoved / $ProcessList.Count * 100)
                        }
                        Try {
                            $ItemObj = [Microsoft.Exchange.WebServices.Data.Item]::Bind( $EwsService, $ItemID)
                            $ItemObj.ItemClass = $ReplaceClass
                            $ItemObj.Update( [Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
                        }
                        Catch {
                            Write-Error ('Problem modifying item: {0}' -f $error[0])
                            $ProcessingOK = $False
                        }
                        $ItemsChanged++
                        $ItemsRemaining--
                    }
                }
                Else {
                    Write-Verbose ('Removing {0} items from {1}' -f $ProcessList.Count, $SubFolder.Name)

                    $SendCancellationsMode = [Microsoft.Exchange.WebServices.Data.SendCancellationsMode]::SendToNone
                    $AffectedTaskOccurrences = [Microsoft.Exchange.WebServices.Data.AffectedTaskOccurrence]::SpecifiedOccurrenceOnly
                    $SuppressReadReceipt = $true

                    $ItemsRemoved = 0
                    $ItemsRemaining = $ProcessList.Count

                   
                    ForEach ( $ItemID in $ProcessList) {
                        $ItemIds.Add( $ItemID)
                        If ( $ItemIds.Count -eq $script:MaxDeleteBatchSize) {
                            $ItemsRemoved += $ItemIds.Count
                            $ItemsRemaining -= $ItemIds.Count
                            If (!$NoProgressBar) {
                                Write-Progress -Id 2 -Activity "Processing folder $($SubFolder.DisplayName)" -Status "Items processed $ItemsRemoved - remaining $ItemsRemaining" -PercentComplete ( $ItemsRemoved / $ProcessList.Count * 100)
                            }
                            $res = myEWSRemove-Items $EwsService $ItemIds $DeleteMode $SendCancellationsMode $AffectedTaskOccurrences $SuppressReadReceipt
                            $ItemIds.Clear()
                        }
                    }
                   
                    If ( $ItemIds.Count -gt 0) {
                        $ItemsRemoved += $ItemIds.Count
                        $ItemsRemaining = 0
                        $res = myEWSRemove-Items $EwsService $ItemIds $DeleteMode $SendCancellationsMode $AffectedTaskOccurrences $SuppressReadReceipt
                        $ItemIds.Clear()
                    }
                }
                If (!$NoProgressBar) {
                    Write-Progress -Id 2 -Activity "Processing folder $($SubFolder.DisplayName)" -Status 'Finished processing.' -Completed
                }
            }
            Else {
               
            }
            $FoldersProcessed++
        }
        If (!$NoProgressBar) {
            Write-Progress -Id 1 -Activity "Processing $Identity" -Status "Finished processing." -Completed
        }
        If ( $ProcessingOK) {
            $TimeProcessingDiff = (Get-Date) - $TimeProcessingStart
            $Speed = [int]( $TotalMatch / $TimeProcessingDiff.TotalSeconds * 60)
            Write-Verbose ('{0} item(s) processed in {1:hh}:{1:mm}:{1:ss} - average {2} items/min' -f $TotalMatch, $TimeProcessingDiff, $Speed)
        }
        Return $ProcessingOK
    }


    Load-EWSManagedAPIDLL
    set-TrustAllWeb

    If ( $MailboxOnly) {
        $ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1
    }
    Else {
        $ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2
    }

    $EwsService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService( $ExchangeVersion)
    $Credentials = Get-Credential

    $ExchangeManagementModuleVersion = (Get-InstalledModule ExchangeOnlineManagement).Version
    $dllLocation = (Get-InstalledModule ExchangeOnlineManagement).InstalledLocation

    if ($ExchangeManagementModuleVersion -le "2.0.3") {
        $EMMInstallLocation = $dllLocation
    }
    ElseIf ($ExchangeManagementModuleVersion -ge '2.0.4') {
        $EMMInstallLocation = "$($dllLocation)\netFramework"
    }

    If ( $Credentials) {
        try {
            #ModernAuth
            $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            Import-Module "$($EMMInstallLocation)\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -force
			$Context = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.microsoftonline.com/common")
            $AADcredential = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential" -ArgumentList  $Credentials.UserName.ToString(), $Credentials.GetNetworkCredential().password.ToString()
			$token = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($Context,"https://outlook.office365.com",$ClientId,$AADcredential).result
            Write-Verbose ('Using ModernAuth Token')
            $EwsService.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($token.AccessToken)
            #$EwsService.Credentials = New-Object System.Net.NetworkCredential( $Credentials.UserName, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( $Credentials.Password )))
        }
        catch {
            Write-Error ('Invalid credentials provided, error: {0}' -f $error[0])
            Exit $ERR_INVALIDCREDENTIALS
        }
    }
    Else {
        Write-Error ('You need to specify credentials to connect to EXO')
        Exit 
    }

    ForEach ( $CurrentIdentity in $Identity) {

        $EmailAddress = get-EmailAddress $CurrentIdentity
        If ( !$EmailAddress) {
            Write-Error ('Specified mailbox {0} not found' -f $CurrentIdentity)
            Exit $ERR_MAILBOXNOTFOUND
        }

        Write-Host ('Processing mailbox {0} ({1})' -f $CurrentIdentity, $EmailAddress)

        If ( $Impersonation) {
            Write-Verbose ('Impersonating using {0}' -f $Credentials.UserName)
            $EwsService.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $EmailAddress)
            $EwsService.HttpHeaders.Add("X-AnchorMailbox", $EmailAddress)
        }

        If ($Server) {
            $EwsUrl = ('https://{0}/EWS/Exchange.asmx' -f $Server)
            Write-Verbose ('Using Exchange Web Services URL {0}' -f $EwsUrl)
            $EwsService.Url = $EwsUrl
        }
        Else {
            Write-Verbose ('Looking up EWS URL using Autodiscover for {0}' -f $EmailAddress)
            try {                
                $ErrorActionPreference = 'Stop'
                $EwsService.autodiscoverUrl( $EmailAddress, {$true})
            }
            catch {
                Write-Error ('Autodiscover failed, error: {0}' -f $_.Exception.Message)
                Exit $ERR_AUTODISCOVERFAILED
            }
            $ErrorActionPreference = 'Continue'
            Write-Verbose ('Using EWS on CAS {0}' -f $EwsService.Url)
        }

        If ( $ReplaceClass) {
            Write-Verbose ('Changing messages of class {0} to {1}' -f $MessageClass, $ReplaceClass)
        }
        Else {
            Write-Verbose ('DeleteMode is {0}' -f $DeleteMode)
            Write-Verbose ('Removing messages of class {0}' -f $MessageClass)
        }
        If ( $Before) {
            Write-Verbose "Removing messages older than $Before"
        }

        
        Write-Verbose 'Applying specified filters'
        $IncludeFilter = Construct-FolderFilter $EwsService $IncludeFolders
        $ExcludeFilter = Construct-FolderFilter $EwsService $ExcludeFolders

        If ( -not $ArchiveOnly.IsPresent) {
            try {
                $RootFolder = myEWSBind-WellKnownFolder $EwsService 'MsgFolderRoot' $emailAddress
                If ( $RootFolder) {
                    Write-Verbose ('Processing primary mailbox of {0}' -f $Identity)
                    If (! ( Process-Mailbox -Identity $Identity -Folder $RootFolder -IncludeFilter $IncludeFilter -ExcludeFilter $ExcludeFilter -emailAddress $emailAddress)) {
                        Write-Error ('Could not process primary mailbox of {0} ({1})' -f $CurrentIdentity, $EmailAddress)
                        Exit $ERR_PROCESSINGMAILBOX
                    }
                }
            }
            catch {
                Write-Error ('Cannot access {0}' -f $Error[0])
                Exit $ERR_CANTACCESSMAILBOXSTORE
            }
        }

        If ( -not $MailboxOnly.IsPresent) {
            try {
                $ArchiveRootFolder = myEWSBind-WellKnownFolder $EwsService 'ArchiveMsgFolderRoot' $emailAddress
                If ( $ArchiveRootFolder) {
                    Write-Verbose ('Processing archive mailbox of {0}' -f $Identity)
                    If (! ( Process-Mailbox -Identity $Identity -Folder $ArchiveRootFolder -IncludeFilter $IncludeFilter -ExcludeFilter $ExcludeFilter -emailAddress $emailAddress)) {
                        Write-Error ('Could not process archive mailbox of {0} ({1})' -f $CurrentIdentity, $EmailAddress)
                        Exit $ERR_PROCESSINGARCHIVE
                    }
                }
            }
            catch {
                Write-Debug 'No archive mailbox present or cannot access it'
            }
        }
        Write-Verbose ('Processing {0} finished' -f $CurrentIdentity)
    }
}
