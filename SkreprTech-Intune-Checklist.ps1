#Requires -Version 5.1
<#
.SYNOPSIS
    SkreprTech Intune MDM Checklist - Windows PowerShell 5.1 + WPF
.DESCRIPTION
    Voor bestaande, uitsluitend Microsoft Entra-joined Windows 10/11-apparaten.
    - Wijzigt GEEN lokale administratorrechten; dit wordt via organisatiebeleid beheerd.
    - Maakt een inschrijfknop op basis van dsregcmd MdmUrl.
    - Hervat automatisch bij volgende aanmelding van precies die gebruiker.
    - Controleert op een NIEUWE Windows-MDM-registratie voor opruiming.
    - Ruimt tijdelijke inschrijfbestanden na maximaal 2 uur op, ook bij mislukte inschrijving.
    - Alleen interactief met eindgebruiker; geen wachtwoorden worden opgeslagen.

    Test eerst op een testapparaat. Ongetest in de doeltenant.
    Windows-profiel, Entra join en bestaande enrollmentgegevens worden niet verwijderd.
#>
[CmdletBinding()]
param(
    [switch]$Resume,
    [switch]$Cleanup,
    [switch]$TimeoutCleanup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Root         = Join-Path $env:ProgramData 'SkreprTech\IntuneChecklist'
$script:InstalledPs1 = Join-Path $script:Root 'SkreprTech-Intune-Checklist.ps1'
$script:StatePath    = Join-Path $script:Root 'state.json'
$script:ResultPath   = Join-Path $script:Root 'resultaat.txt'
$script:EnrollmentCmd = Join-Path $env:SystemDrive 'Temp\script.cmd'
$script:RunKey       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$script:RunName      = 'SkreprTechIntuneChecklist'
$script:TaskName     = 'SkreprTech-IntuneChecklist-Veiligheidsopruiming'
$script:RunExe       = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:CleanupInvoked = $false
$script:OldStateNotice = $false

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-State {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { return $null }
    return (Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Save-State($state) {
    $tempFile = "$($script:StatePath).tmp"
    $state | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $tempFile -Encoding UTF8 -Force
    Move-Item -LiteralPath $tempFile -Destination $script:StatePath -Force
}

function Assert-DeviceAndGetMdmUrl {
    $output = (& (Join-Path $env:WINDIR 'System32\dsregcmd.exe') /status | Out-String)
    if ($output -notmatch '(?im)^\s*AzureAdJoined\s*:\s*YES\s*$') {
        throw 'Dit apparaat is niet Microsoft Entra-joined (AzureAdJoined is geen YES).'
    }
    if ($output -notmatch '(?im)^\s*DomainJoined\s*:\s*NO\s*$') {
        throw 'Dit programma is uitsluitend voor cloud-only Entra-joined apparaten.'
    }
    $match = [regex]::Match($output, '(?im)^\s*MdmUrl\s*:\s*(https://\S+)\s*$')
    if (-not $match.Success) { throw 'MdmUrl ontbreekt in dsregcmd /status.' }
    $value = $match.Groups[1].Value.Trim()
    $uri = $null
    if (-not [uri]::TryCreate($value,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https') {
        throw 'De gevonden MdmUrl is geen geldige HTTPS-URL.'
    }
    return $value
}

function Resolve-EntraSid([string]$upn) {
    try {
        return ([Security.Principal.NTAccount]::new("AzureAD\$upn")).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Windows kan AzureAD\$upn niet omzetten naar een SID. Laat deze gebruiker eerst een keer aanmelden op dit apparaat. Details: $($_.Exception.Message)"
    }
}

function Get-MdmEnrollmentIds {
    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    $ids = @()
    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        if ($key.PSChildName -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
            $ids += $key.PSChildName.ToLowerInvariant()
        }
    }
    return @($ids)
}

function Test-NewMdmEnrollment($state) {
    # Geen controle op MdmUrl alleen: die staat ook op niet-ingeschreven apparaten.
    # Event 75 is bedoeld voor auto-enrollment en is niet verplicht bij handmatige MDM-only inschrijving.
    $oldIds = @($state.BaselineEnrollmentIds)
    foreach ($guid in @(Get-MdmEnrollmentIds)) {
        if ($oldIds -contains $guid) { continue }
        $path = "HKLM:\SOFTWARE\Microsoft\Enrollments\$guid"
        $properties = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $properties) { continue }
        $providerId = ''
        $discovery  = ''
        $upn        = ''
        $stateValue = $null
        if ($properties.PSObject.Properties.Name -contains 'ProviderID') {
            $providerId = [string]$properties.ProviderID
        }
        if ($properties.PSObject.Properties.Name -contains 'DiscoveryServiceFullURL') {
            $discovery = [string]$properties.DiscoveryServiceFullURL
        }
        if ($properties.PSObject.Properties.Name -contains 'UPN') {
            $upn = [string]$properties.UPN
        }
        if ($properties.PSObject.Properties.Name -contains 'EnrollmentState') {
            $stateValue = $properties.EnrollmentState
        }
        $accountPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$guid"
        if (-not (Test-Path -LiteralPath $accountPath)) { continue }
        if ([string]::IsNullOrWhiteSpace($providerId)) { continue }
        if ($null -ne $stateValue -and [string]$stateValue -ne '1') { continue }
        if (-not [string]::IsNullOrWhiteSpace($upn) -and $upn -ine [string]$state.UPN) { continue }
        $isExpectedService = ($providerId -match '(?i)MS DM Server|Intune') -or
                             ($discovery -match '(?i)manage\.microsoft\.com') -or
                             ($discovery -eq [string]$state.MdmUrl)
        if (-not $isExpectedService) { continue }
        return $true
    }
    return $false
}

function Set-SecureFolderAcl {
    # Bescherm de ingestelde PS1, state en config tegen wijzigingen door standaardgebruikers.
    $dirSecurity = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSecurity.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $prop = [Security.AccessControl.PropagationFlags]::None
    foreach ($pair in @(
        @('S-1-5-18', 'FullControl'),       # SYSTEM
        @('S-1-5-32-544', 'FullControl'),   # Administrators
        @('S-1-5-32-545', 'ReadAndExecute') # Users
    )) {
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$pair[0])
        $rights = [Security.AccessControl.FileSystemRights]$pair[1]
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,$inherit,$prop,[Security.AccessControl.AccessControlType]::Allow)
        $dirSecurity.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $script:Root -AclObject $dirSecurity
}

function Register-ExpiryTask {
    $action = New-ScheduledTaskAction -Execute $script:RunExe -Argument ('-NoProfile -ExecutionPolicy Bypass -Sta -File "{0}" -TimeoutCleanup' -f $script:InstalledPs1)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(2)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Set-ResumeRunKey {
    $command = '"{0}" -NoProfile -ExecutionPolicy Bypass -Sta -WindowStyle Hidden -File "{1}" -Resume' -f $script:RunExe,$script:InstalledPs1
    New-ItemProperty -Path $script:RunKey -Name $script:RunName -Value $command -PropertyType String -Force | Out-Null
}

function Write-EnrollmentCommand([string]$upn,[string]$url) {
    $folder = Split-Path -Path $script:EnrollmentCmd -Parent
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    if (Test-Path -LiteralPath $script:EnrollmentCmd) {
        $existing = Get-Content -LiteralPath $script:EnrollmentCmd -TotalCount 1 -ErrorAction Stop
        if ($existing -ne '@echo off & rem SKREPRTECH INTUNE MDM') {
            throw "C:\Temp\script.cmd bestaat al en is niet van SkreprTech. Afgebroken om overschrijven te voorkomen."
        }
    }
    $deepLink = 'ms-device-enrollment:?mode=mdm&username={0}&servername={1}' -f $upn,$url
    $content = @(
        '@echo off & rem SKREPRTECH INTUNE MDM',
        'rem Alleen uitvoeren binnen de aangemelde Windows-sessie van de eindgebruiker.',
        ('start "" "{0}"' -f $deepLink),
        'exit /b 0'
    )
    [IO.File]::WriteAllLines($script:EnrollmentCmd, $content,[Text.Encoding]::ASCII)
}

function Remove-ExpiryTask {
    if (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction Stop
    }
}

function Remove-RunKey {
    Remove-ItemProperty -Path $script:RunKey -Name $script:RunName -ErrorAction SilentlyContinue
}

function Invoke-EnrollmentCleanup([string]$reason) {
    if (-not (Test-IsAdmin)) { throw 'Voor het opruimen zijn administratorrechten nodig.' }
    $state = Get-State
    if ($null -eq $state) { return }
    if ([string]$state.Computer -ne $env:COMPUTERNAME) { throw 'State hoort bij een ander apparaat.' }
    # Geen wijzigingen aan de lokale Administrators-groep.
    # Bij eerdere versies kan het account wel door de oude helper toegevoegd zijn.
    # De nieuwe helper verwijdert geen via beleid beheerde rechten.
    Remove-RunKey
    if (Test-Path -LiteralPath $script:EnrollmentCmd) {
        $firstLine = Get-Content -LiteralPath $script:EnrollmentCmd -TotalCount 1 -ErrorAction SilentlyContinue
        if ($firstLine -eq '@echo off & rem SKREPRTECH INTUNE MDM') {
            Remove-Item -LiteralPath $script:EnrollmentCmd -Force -ErrorAction Stop
        }
    }
    Remove-ExpiryTask
    $text = @(
        'SkreprTech Intune MDM checklist - resultaat',
        ('Computer: {0}' -f $env:COMPUTERNAME),
        ('Gebruiker: {0}' -f [string]$state.UPN),
        ('Tijdstip: {0}' -f (Get-Date).ToString('s')),
        ('Afsluitreden: {0}' -f $reason),
        'Het tijdelijke inschrijfbestand en de autostart zijn opgeruimd.',
        'Deze versie heeft geen administratorrechten gewijzigd. Controleer bij oude uitrolsessies of nog rechten uit v1.0.4 zijn achtergebleven.'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $script:ResultPath -Value $text -Encoding UTF8 -Force
    Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction Stop
}

# Speciale niet-interactieve routes voordat WPF geladen wordt.
if ($TimeoutCleanup) {
    try {
        $existing = Get-State
        if ($existing -and (Get-Date) -ge ([datetime]::Parse([string]$existing.CreatedAt)).AddMinutes(118)) {
            Invoke-EnrollmentCleanup 'Automatische opruiming van tijdelijke bestanden na 2 uur'
        }
    } catch {
        try { Add-Content -LiteralPath (Join-Path $script:Root 'fouten.log') -Value ((Get-Date).ToString('s') + ' Timeout: ' + $_.Exception.Message) } catch {}
        exit 1
    }
    exit 0
}

if ($Cleanup) {
    try { Invoke-EnrollmentCleanup 'Inschrijving bevestigd of handmatig opgeruimd' }
    catch {
        try { Add-Content -LiteralPath (Join-Path $script:Root 'fouten.log') -Value ((Get-Date).ToString('s') + ' Cleanup: ' + $_.Exception.Message) } catch {}
        exit 1
    }
    exit 0
}

# Alleen de administrator kan de voorbereiding starten. Tijdens hervatten start WPF normaal.
if (-not $Resume -and -not (Test-IsAdmin)) {
    try {
        Start-Process -FilePath $script:RunExe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -Sta -File "{0}"' -f $PSCommandPath) -Verb RunAs -WindowStyle Hidden | Out-Null
    } catch { Write-Warning "Administratorbevestiging mislukt: $($_.Exception.Message)" }
    exit
}

if ($Resume) {
    $resumeState = Get-State
    if (-not $resumeState -or (Get-CurrentSid) -ne [string]$resumeState.SID) { exit }
}


function Hide-ConsoleWindow {
    try {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
"@ -ErrorAction SilentlyContinue | Out-Null
        $consoleHandle = [Win32.NativeMethods]::GetConsoleWindow()
        if ($consoleHandle -ne [IntPtr]::Zero) {
            [Win32.NativeMethods]::ShowWindow($consoleHandle, 0) | Out-Null
        }
    } catch {}
}

Hide-ConsoleWindow

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SkreprTech | Intune MDM Checklist" Height="760" Width="1100"
        MinHeight="600" MinWidth="900" WindowStartupLocation="CenterScreen"
        WindowState="Maximized"
        Background="#FFF7F2" FontFamily="Segoe UI" Foreground="#27272A">
  <Window.Resources>
    <SolidColorBrush x:Key="Orange" Color="#EF6C00"/>
    <SolidColorBrush x:Key="OrangeLight" Color="#FFF0E3"/>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#EF6C00"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="17,10"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,10,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="9" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.86"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.4"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="FontSize" Value="15"/>
      <Setter Property="Padding" Value="12,10"/>
      <Setter Property="BorderBrush" Value="#F1C6AB"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="150"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="47"/>
    </Grid.RowDefinitions>
    <Border Grid.Row="0" Background="#EF6C00" Padding="35,18,35,24">
      <StackPanel>
        <TextBlock Text="SKREPRTECH   /   IT-BEHEER" FontSize="13" Foreground="#FFF3E6" FontWeight="Bold"/>
        <TextBlock Text="Intune MDM - Uitrolassistent" FontSize="31" FontWeight="Bold" Foreground="White" Margin="0,6,0,0"/>
        <TextBlock Text="Bestaande Entra-apparaten - zonder opnieuw instellen" FontSize="15" Foreground="#FFF3E6" Margin="0,8,0,0"/>
      </StackPanel>
    </Border>
    <Grid Grid.Row="1" Margin="24,22,24,15">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="315"/>
        <ColumnDefinition Width="18"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.Column="0" Background="White" BorderBrush="#F1E2D8" BorderThickness="1" CornerRadius="14" Padding="18">
        <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
          <StackPanel>
          <TextBlock Text="UITROLCHECKLIST" FontWeight="Bold" FontSize="13" Foreground="#9A4E17" Margin="0,0,0,18"/>
          <TextBlock x:Name="S1" FontSize="14" TextWrapping="Wrap" Margin="0,0,0,18"/>
          <TextBlock x:Name="S2" FontSize="14" TextWrapping="Wrap" Margin="0,0,0,18"/>
          <TextBlock x:Name="S3" FontSize="14" TextWrapping="Wrap" Margin="0,0,0,18"/>
          <TextBlock x:Name="S4" FontSize="14" TextWrapping="Wrap" Margin="0,0,0,18"/>
          <TextBlock x:Name="S5" FontSize="14" TextWrapping="Wrap" Margin="0,0,0,18"/>
          <Border Background="#FFF5E9" CornerRadius="9" Padding="12" Margin="0,18,0,0">
            <StackPanel>
              <TextBlock Text="BEHEERRECHTEN" Foreground="#A74B08" FontWeight="Bold" FontSize="11"/>
              <TextBlock Text="Lokale administratorrechten worden beheerd door jullie beleid. Deze app wijzigt geen rechten. Tijdelijke inschrijfbestanden worden na 2 uur opgeruimd als Windows de taak kan uitvoeren." FontSize="12" Foreground="#674B3C" TextWrapping="Wrap" Margin="0,6,0,0"/>
            </StackPanel>
          </Border>
          </StackPanel>
        </ScrollViewer>
      </Border>
      <Border Grid.Column="2" Background="White" BorderBrush="#F1E2D8" BorderThickness="1" CornerRadius="14" Padding="24">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel>
            <TextBlock Text="Apparaat voorbereiden" FontSize="23" FontWeight="Bold" Margin="0,0,0,6"/>
            <TextBlock x:Name="DeviceText" Text="Computer: onbekend" FontSize="13" Foreground="#666666" Margin="0,0,0,17"/>
            <TextBlock Text="Microsoft 365-account van de eindgebruiker" FontSize="13" FontWeight="SemiBold"/>
            <TextBox x:Name="UpnBox" Margin="0,7,0,14" Height="43"/>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
              <Button x:Name="PrepareButton" Content="1  Voorbereiden"/>
              <Button x:Name="LogoffButton" Content="2  Afmelden" Background="#D65B06" IsEnabled="False"/>
            </StackPanel>
            <Border BorderBrush="#F2E1D6" BorderThickness="0,1,0,0" Margin="0,7,0,17"/>
            <TextBlock Text="Inschrijving" FontSize="20" FontWeight="Bold" Margin="0,0,0,7"/>
            <TextBlock Text="Na het aanmelden als eindgebruiker komt dit venster automatisch terug. Start dan de Windows MDM-inschrijving; account en server zijn vooraf ingevuld." TextWrapping="Wrap" Foreground="#52525B" FontSize="13" Margin="0,0,0,12"/>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
              <Button x:Name="EnrollButton" Content="4  Inschrijving starten" IsEnabled="False"/>
              <Button x:Name="CheckButton" Content="Status controleren" Background="#424242" IsEnabled="False"/>
            </StackPanel>
            <Border BorderBrush="#F2E1D6" BorderThickness="0,1,0,0" Margin="0,4,0,15"/>
            <TextBlock Text="Afronden" FontSize="20" FontWeight="Bold" Margin="0,0,0,8"/>
            <TextBlock Text="Opruiming volgt na detectie van een nieuwe Windows MDM-registratie. Als Intune de inschrijving bevestigt maar de lokale controle niets ziet, kun je dit handmatig bevestigen." FontSize="13" Foreground="#52525B" TextWrapping="Wrap" Margin="0,0,0,13"/>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
              <Button x:Name="ConfirmButton" Content="5  Bevestigd in Intune - opruimen" Background="#B4540A" IsEnabled="False"/>
              <Button x:Name="CancelButton" Content="Noodopruiming" Background="#6B7280" IsEnabled="False"/>
            </StackPanel>
            <Border Background="#FFF6ED" CornerRadius="10" Padding="12" Margin="0,7,0,0">
              <StackPanel>
                <TextBlock Text="ACTUELE STATUS" FontSize="11" Foreground="#A64C09" FontWeight="Bold"/>
                <TextBlock x:Name="StatusText" Text="Gereed voor voorbereiding." TextWrapping="Wrap" FontSize="13" Margin="0,6,0,0"/>
              </StackPanel>
            </Border>
          </StackPanel>
        </ScrollViewer>
      </Border>
    </Grid>
    <Border Grid.Row="2" Background="#291E17" Padding="25,12">
      <Grid>
        <TextBlock Text="SkreprTech  |  Intune MDM Checklist  |  v1.0.5" Foreground="#FFDFCA" FontSize="12"/>
        <TextBlock Text="Geen wachtwoorden opgeslagen" Foreground="#FFDFCA" FontSize="12" HorizontalAlignment="Right"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@
$reader = [xml.xmlreader]::Create([IO.StringReader]::new($Xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)
$ctrl = @{}
foreach ($id in @('S1','S2','S3','S4','S5','DeviceText','UpnBox','PrepareButton','LogoffButton','EnrollButton','CheckButton','ConfirmButton','CancelButton','StatusText')) {
    $ctrl[$id] = $window.FindName($id)
}

function Set-Status([string]$text) { $ctrl.StatusText.Text = $text }
function Show-Error([string]$message) {
    Set-Status ("Fout: " + $message)
    [System.Windows.MessageBox]::Show($window,$message,'SkreprTech - fout','OK','Error') | Out-Null
}
function Ask-Confirm([string]$message) {
    return ([System.Windows.MessageBox]::Show($window,$message,'SkreprTech - bevestiging','YesNo','Question') -eq 'Yes')
}
function Set-Step($num,[string]$label,[string]$status) {
    $prefix = switch ($status) { 'done' { '[OK]' } 'active' { '[ > ]' } 'waiting' { '[  ]' } 'warning' { '[ ! ]' } default { '[  ]' } }
    $target = $ctrl["S$num"]
    $target.Text = "$prefix   $num. $label"
    $target.FontWeight = if ($status -eq 'active') { [System.Windows.FontWeights]::Bold } else { [System.Windows.FontWeights]::Normal }
    $colorHex = if ($status -eq 'done') { '#208454' } elseif ($status -eq 'active') { '#EF6C00' } elseif ($status -eq 'warning') { '#BA3712' } else { '#676767' }
    $target.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colorHex)
}

function Refresh-View {
    $state = Get-State
    $isAdmin = Test-IsAdmin
    $ctrl.DeviceText.Text = "Computer: $env:COMPUTERNAME  |  Windows: $env:USERNAME"
    $isTargetUser = $false
    $script:OldStateNotice = $false
    if ($state) { $isTargetUser = ((Get-CurrentSid) -eq [string]$state.SID) }
    if ($state -and ($state.PSObject.Properties.Name -contains 'AddedByTool')) {
        # Een eerdere versie kon rechten toegevoegd hebben. Deze versie raakt die niet aan.
        # Meld expliciet dat de adminrechten via beleid of vanuit de oude helper gecontroleerd moeten worden.
        $script:OldStateNotice = $true
    }
    $ctrl.PrepareButton.IsEnabled = ($null -eq $state -and $isAdmin -and -not $Resume)
    $ctrl.LogoffButton.IsEnabled = ($null -ne $state -and $isAdmin -and -not $isTargetUser)
    $ctrl.EnrollButton.IsEnabled = ($null -ne $state -and $isTargetUser)
    $ctrl.CheckButton.IsEnabled = ($null -ne $state -and $isTargetUser)
    $ctrl.ConfirmButton.IsEnabled = ($null -ne $state -and $isTargetUser)
    $ctrl.CancelButton.IsEnabled = ($null -ne $state)
    $ctrl.UpnBox.IsReadOnly = ($null -ne $state)
    if ($null -eq $state) {
        Set-Step 1 'Apparaat voorbereiden' 'active'
        Set-Step 2 'Opnieuw aanmelden in Windows' 'waiting'
        Set-Step 3 'Automatisch verdergaan' 'waiting'
        Set-Step 4 'MDM-inschrijving starten' 'waiting'
        Set-Step 5 'Inschrijfbestanden opruimen' 'waiting'
        if (Test-Path -LiteralPath $script:ResultPath) {
            Set-Status ('Laatste run: ' + ((Get-Content -LiteralPath $script:ResultPath -Tail 3) -join ' | '))
        } else {
            Set-Status 'Vul het UPN in en klik op Voorbereiden. Lokale beheerrechten worden niet gewijzigd; controleer of de gebruiker via beleid bevoegd is.'
        }
        return
    }
    $ctrl.UpnBox.Text = [string]$state.UPN
    Set-Step 1 'Apparaat voorbereiden' 'done'
    if (-not $isTargetUser) {
        Set-Step 2 'Opnieuw aanmelden in Windows' 'active'
        Set-Step 3 'Automatisch verdergaan' 'waiting'
        Set-Step 4 'MDM-inschrijving starten' 'waiting'
        Set-Step 5 'Inschrijfbestanden opruimen' 'waiting'
        Set-Status "De voorbereiding is klaar voor $($state.UPN). Sla werk op, klik op Afmelden en meld daarna aan als eindgebruiker."
    } else {
        Set-Step 2 'Opnieuw aanmelden in Windows' 'done'
        Set-Step 3 'Automatisch verdergaan' 'done'
        Set-Step 4 'MDM-inschrijving starten' 'active'
        Set-Step 5 'Inschrijfbestanden opruimen' 'waiting'
        if (Test-NewMdmEnrollment $state) {
            Set-Step 4 'MDM-inschrijving starten' 'done'
            Set-Step 5 'Inschrijfbestanden opruimen' 'active'
            Set-Status 'Windows toont een nieuwe MDM-registratie. Tijdelijke inschrijfbestanden worden nu opgeruimd (Windows UAC kan om bevestiging vragen).'
            Request-Cleanup 'automatic'
        } else {
            Set-Status 'Ingelogd als juiste gebruiker. Start de inschrijving en rond de Microsoft-aanmelding af. Dit venster controleert daarna elke 10 seconden.'
        }
    }
    if ($script:OldStateNotice) {
        Set-Status ('LET OP: eerdere uitrolstatus gevonden. De vorige versie heeft mogelijk adminrechten toegevoegd; ' +
                    'deze versie wijzigt die niet. Controleer na afloop of het beleid de rechten correct beheert.')
    }
}

function Request-Cleanup([string]$mode) {
    if ($script:CleanupInvoked) { return }
    $script:CleanupInvoked = $true
    try {
        $args = '-NoProfile -ExecutionPolicy Bypass -Sta -File "{0}" -Cleanup' -f $script:InstalledPs1
        if (Test-IsAdmin) {
            Start-Process -FilePath $script:RunExe -ArgumentList $args -WindowStyle Hidden -Wait | Out-Null
        } else {
            # Voor centrale instellingen kunnen bestaande beheerrechten / UAC nodig zijn.
            Start-Process -FilePath $script:RunExe -ArgumentList $args -Verb RunAs -WindowStyle Hidden -Wait | Out-Null
        }
        if (-not (Test-Path -LiteralPath $script:StatePath)) {
            Set-Status 'Tijdelijke inschrijfbestanden zijn opgeruimd. Lokale administratorrechten zijn niet gewijzigd.'
            foreach ($id in @('EnrollButton','CheckButton','ConfirmButton','CancelButton','LogoffButton','PrepareButton')) { $ctrl[$id].IsEnabled = $false }
            Set-Step 5 'Inschrijfbestanden opruimen' 'done'
            [System.Windows.MessageBox]::Show($window,'C:\Temp\script.cmd en de automatische opstart zijn opgeruimd. Lokale administratorrechten zijn niet gewijzigd.','Gereed','OK','Information') | Out-Null
        } else {
            $script:CleanupInvoked = $false
            Set-Status 'Opruiming is nog niet bevestigd. Controleer UAC en probeer Noodopruiming. De veiligheidstaak blijft actief.'
        }
    } catch {
        $script:CleanupInvoked = $false
        Show-Error "Opruiming mislukte. De opruimtaak blijft actief. Details: $($_.Exception.Message)"
    }
}

$ctrl.PrepareButton.Add_Click({
    try {
        $upn = $ctrl.UpnBox.Text.Trim()
        if ($upn -notmatch '^[a-zA-Z0-9._+\-]+@[a-zA-Z0-9.\-]+$') {
            throw 'Vul een geldig Microsoft 365-aanmeldadres (UPN) in.'
        }
        if (Get-State) { throw 'Er staat al een openstaande inschrijving op dit apparaat. Rond deze eerst af voordat je opnieuw begint.' }
        $mdmUrl = Assert-DeviceAndGetMdmUrl
        $sid = Resolve-EntraSid $upn
        $baseline = @(Get-MdmEnrollmentIds)
        if (-not (Ask-Confirm "Apparaat: $env:COMPUTERNAME`nGebruiker: $upn`nMDM URL: $mdmUrl`n`nDeze app wijzigt geen lokale administratorrechten. De ingelogde eindgebruiker moet deze rechten zelf via jullie beleid krijgen als Windows ze vereist. Doorgaan?")) { return }
        $runCreated = $false; $taskCreated = $false; $fileCreated = $false
        try {
            New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
            Set-SecureFolderAcl
            if ($PSCommandPath -ne $script:InstalledPs1) { Copy-Item -LiteralPath $PSCommandPath -Destination $script:InstalledPs1 -Force }
            elseif (-not (Test-Path $script:InstalledPs1)) { throw 'Het PowerShell-bestand is niet beschikbaar.' }
            Write-EnrollmentCommand $upn $mdmUrl
            $fileCreated = $true
            $state = [pscustomobject]@{
                Computer = $env:COMPUTERNAME; UPN = $upn; SID = $sid
                Account = "AzureAD\$upn"; MdmUrl = $mdmUrl
                HelperVersion = '1.0.5'; CreatedAt = (Get-Date).ToString('o')
                BaselineEnrollmentIds = @($baseline)
            }
            Save-State $state
            Set-ResumeRunKey
            $runCreated = $true
            Register-ExpiryTask
            $taskCreated = $true
        } catch {
            $originalError = $_.Exception.Message
            if ($taskCreated) { try { Remove-ExpiryTask } catch {} }
            if ($runCreated) { try { Remove-RunKey } catch {} }
            if ($fileCreated) { try { Remove-Item -LiteralPath $script:EnrollmentCmd -Force } catch {} }
            if (Test-Path -LiteralPath $script:StatePath) { try { Remove-Item -LiteralPath $script:StatePath -Force } catch {} }
            throw "Voorbereiding is niet afgerond: $originalError"
        }
        Refresh-View
    } catch { Show-Error $_.Exception.Message }
})

$ctrl.LogoffButton.Add_Click({
    if (Ask-Confirm 'Sla eerst alle geopende bestanden op. Windows meldt het huidige account direct af. Daarna aanmelden met het account van de eindgebruiker. Doorgaan?') {
        Start-Process -FilePath (Join-Path $env:WINDIR 'System32\shutdown.exe') -ArgumentList '/l' | Out-Null
    }
})

$ctrl.EnrollButton.Add_Click({
    try {
        $state = Get-State
        if (-not $state -or (Get-CurrentSid) -ne [string]$state.SID) { throw 'Je bent niet aangemeld als de voorbereide eindgebruiker.' }
        if (-not (Test-Path -LiteralPath $script:EnrollmentCmd)) { throw 'C:\Temp\script.cmd ontbreekt.' }
        Start-Process -FilePath $env:ComSpec -ArgumentList ('/c "{0}"' -f $script:EnrollmentCmd) -WindowStyle Hidden | Out-Null
        Set-Status 'De Windows MDM-inschrijving is geopend. Volg de Microsoft-aanmelding. De controle op nieuwe MDM-registratie blijft lopen.'
    } catch { Show-Error $_.Exception.Message }
})

$ctrl.CheckButton.Add_Click({
    try {
        $state = Get-State
        if (-not $state) { throw 'Geen actieve voorbereiding.' }
        if (Test-NewMdmEnrollment $state) { Set-Status 'Nieuwe MDM-registratie gevonden; opruiming wordt gestart.'; Request-Cleanup 'checked' }
        else { Set-Status 'Nog geen nieuwe, actieve MDM-inschrijving gedetecteerd. Controleer of het apparaat in Intune staat en of Info zichtbaar is onder Toegang tot werk of school.' }
    } catch { Show-Error $_.Exception.Message }
})

$ctrl.ConfirmButton.Add_Click({
    if (Ask-Confirm "Heb je dit apparaat ZELF in het Intune-beheercentrum gecontroleerd en bevestigd dat de inschrijving is geslaagd?`n`nKies JA alleen bij een geslaagde inschrijving. Daarna worden C:\Temp\script.cmd, de automatische opstartinstelling en de opruimtaak verwijderd. Lokale administratorrechten blijven ongewijzigd.") {
        Request-Cleanup 'manual-confirmed'
    }
})

$ctrl.CancelButton.Add_Click({
    if (Ask-Confirm 'NOODOPRUIMING: het tijdelijke inschrijfbestand en de autostart worden verwijderd, ook als de inschrijving nog niet gelukt is. Lokale administratorrechten blijven ongewijzigd. Doorgaan?') {
        Request-Cleanup 'emergency'
    }
})

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(10)
$timer.Add_Tick({
    if ($script:CleanupInvoked) { return }
    try {
        $state = Get-State
        if ($state -and (Get-CurrentSid) -eq [string]$state.SID -and (Test-NewMdmEnrollment $state)) {
            Set-Status 'Nieuwe MDM-registratie gevonden. Tijdelijke bestanden opruimen...'
            Set-Step 4 'MDM-inschrijving starten' 'done'
            Request-Cleanup 'detected'
        } elseif (-not $state -and $Resume) {
            $timer.Stop()
            Set-Step 5 'Inschrijfbestanden opruimen' 'done'
            Set-Status 'Er is geen actieve inschrijving meer. Mogelijk heeft de automatische opruimtaak tijdelijke bestanden al verwijderd.'
        }
    } catch { Set-Status ('Statuscontrole mislukt: ' + $_.Exception.Message) }
})
$window.Add_Loaded({ Refresh-View; $timer.Start() })
$window.Add_Closed({ $timer.Stop() })
[void]$window.ShowDialog()
