# Ordinary, local WinForms view. No backend command, compiler, runas or socket.
# UTF-8 BOM is intentional for Windows PowerShell 5.1 -File localization.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false, $true)
[Console]::OutputEncoding = $utf8
[Console]::InputEncoding = $utf8
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ORDINARY_WINDOW_REQUIRED' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$script:state = 'Connecting'
$script:html = $null
$script:allowClose = $false
$script:closeAfterDiscard = $false
$script:pending = ''
$script:reader = New-Object IO.StreamReader([Console]::OpenStandardInput(), $utf8, $false, 4096)
$script:buffer = New-Object char[] 4096
$script:readTask = $script:reader.ReadAsync($script:buffer, 0, $script:buffer.Length)

function Send-Command([string]$Action, [string]$Answer) {
    $command = @{ action = $Action }
    if ($Action -eq 'confirm') { $command.answer = $Answer }
    [Console]::Out.WriteLine(($command | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
}

# Read-only prerequisite: the UI never registers/repairs an EventLog source.
function Test-ExistingEventSource {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\EventLog\Application\Velociraptor', $false)
    if ($null -eq $key) { return $false }
    try {
        return ($key.GetValue('CustomSource', $null) -eq 1 -and $key.GetValue('TypesSupported', $null) -eq 7 -and
            [string]::Equals([string]$key.GetValue('EventMessageFile', $null), 'C:\Windows\System32\EventCreate.exe', [StringComparison]::OrdinalIgnoreCase))
    } finally { $key.Dispose() }
}

$form = New-Object Windows.Forms.Form
$form.Text = 'SecApp — проверка Defender'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object Drawing.Size(940, 820)
$form.MinimumSize = New-Object Drawing.Size(740, 650)
$form.Font = New-Object Drawing.Font('Segoe UI', 10)
$form.BackColor = [Drawing.Color]::FromArgb(242, 246, 250)
$form.AutoScaleMode = [Windows.Forms.AutoScaleMode]::Dpi

$layout = New-Object Windows.Forms.TableLayoutPanel
$layout.Dock = 'Fill'
$layout.Padding = New-Object Windows.Forms.Padding(22)
$layout.ColumnCount = 1
$layout.RowCount = 7
foreach ($height in @(46, 35, 0, 30, 38, 52, 48)) {
    if ($height -eq 0) { $style = New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100) }
    else { $style = New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $height) }
    [void]$layout.RowStyles.Add($style)
}
$form.Controls.Add($layout)
$title = New-Object Windows.Forms.Label
$title.Text = 'SecApp / Microsoft Defender'
$title.Font = New-Object Drawing.Font('Segoe UI', 19, [Drawing.FontStyle]::Bold)
$title.Dock = 'Fill'
$layout.Controls.Add($title, 0, 0)
$status = New-Object Windows.Forms.Label
$status.Text = 'Подключение к локальному контроллеру…'
$status.Dock = 'Fill'
$layout.Controls.Add($status, 0, 1)
$tabs = New-Object Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$progressPage = New-Object Windows.Forms.TabPage('Ход проверки')
$reportPage = New-Object Windows.Forms.TabPage('Отчёт')
$tabs.TabPages.Add($progressPage)
$tabs.TabPages.Add($reportPage)
$layout.Controls.Add($tabs, 0, 2)
$details = New-Object Windows.Forms.TextBox
$details.Multiline = $true
$details.ReadOnly = $true
$details.ScrollBars = 'Vertical'
$details.Dock = 'Fill'
$details.BackColor = [Drawing.Color]::White
$details.BorderStyle = 'FixedSingle'
$details.MaxLength = 30000
$progressPage.Controls.Add($details)
$reportView = New-Object Windows.Forms.TextBox
$reportView.Multiline = $true
$reportView.ReadOnly = $true
$reportView.ScrollBars = 'Vertical'
$reportView.Dock = 'Fill'
$reportView.BackColor = [Drawing.Color]::White
$reportView.Text = 'Отчёта пока нет. Открытие окна не выполняет проверку.'
$reportPage.Controls.Add($reportView)
$confirmationLabel = New-Object Windows.Forms.Label
$confirmationLabel.Text = 'Одноразовая фраза появится после подготовки. UAC подтверждается отдельно.'
$confirmationLabel.Dock = 'Fill'
$layout.Controls.Add($confirmationLabel, 0, 3)
$answer = New-Object Windows.Forms.TextBox
$answer.MaxLength = 64
$answer.Dock = 'Fill'
$answer.Enabled = $false
$layout.Controls.Add($answer, 0, 4)
$buttons = New-Object Windows.Forms.FlowLayoutPanel
$buttons.Dock = 'Fill'
$buttons.WrapContents = $false
$layout.Controls.Add($buttons, 0, 5)
function Make-Button([string]$Text, [int]$Width) {
    $button = New-Object Windows.Forms.Button
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 36
    $button.Enabled = $false
    $buttons.Controls.Add($button)
    return $button
}
$primary = Make-Button 'Подготовить проверку' 205
$cancel = Make-Button 'Отменить сбор' 155
$save = Make-Button 'Сохранить HTML…' 170
$close = Make-Button 'Закрыть' 100
$footer = New-Object Windows.Forms.Label
$footer.Text = 'Локально • Только два показателя • Без исправления настроек' + "`r`n" + 'Отчёт частный. Достоверность зависит от работающей Windows.'
$footer.ForeColor = [Drawing.Color]::FromArgb(65, 86, 104)
$footer.Dock = 'Fill'
$layout.Controls.Add($footer, 0, 6)

function Show-Failure {
    $script:state = 'Failed'
    $script:html = $null
    $reportView.Text = 'Результат не подтверждён: связь с контроллером потеряна. Не считайте компьютер безопасным по отсутствию отчёта.'
    $primary.Enabled = $false; $cancel.Enabled = $false; $answer.Enabled = $false; $save.Enabled = $false
    $close.Enabled = $true
    $status.Text = 'Связь с контроллером потеряна — успешная проверка не подтверждена.'
    $details.AppendText("`r`nНе предполагайте завершение и очистку. Контроллер ожидает ограниченное завершение; не удаляйте рабочую папку вслепую.")
    $timer.Stop()
}

function Apply-State($Message) {
    if ($Message.kind -cne 'SecAppDesktopStateV1' -or $Message.state -cnotin @('Ready','Preparing','AwaitingConfirmation','Submitting','Running','Discarding','Finished','Failed') -or
        $Message.text -isnot [string] -or $Message.text.Length -gt 18000) { throw 'UI_MESSAGE' }
    $previous = $script:state
    $script:state = $Message.state
    $labels = @{ Ready='Готово к подготовке — сбор ещё не запускался'; Preparing='Подготовка закрытой рабочей папки…';
        AwaitingConfirmation='Прочитайте состав ниже и введите фразу'; Submitting='Ответ принят…';
        Running='Подтвердите UAC; затем дождитесь результата (до 180 с)'; Discarding='Отмена: удаление подготовленных данных…';
        Finished='Проверка завершена'; Failed='Успешное завершение или очистка не подтверждены' }
    $status.Text = $labels[$script:state]
    if ($script:state -eq 'Finished' -and $Message.code -eq 3) { $status.Text = 'Отменено — Velociraptor не запускался' }
    if ($script:state -eq 'Finished' -and $Message.code -eq 2) { $status.Text = 'Не проверено — недостаточно данных' }
    $details.Text = $Message.text.Replace("`n", "`r`n")
    $details.SelectionStart = 0
    $primary.Text = if ($script:state -eq 'AwaitingConfirmation') { 'Подтвердить и вызвать UAC' } else { 'Подготовить проверку' }
    $primary.Enabled = $script:state -in @('Ready','AwaitingConfirmation')
    $answer.Enabled = $script:state -eq 'AwaitingConfirmation'
    $cancel.Enabled = $answer.Enabled
    $close.Enabled = $script:state -in @('Ready','AwaitingConfirmation','Finished','Failed')
    $script:html = $null
    if ($null -ne $Message.reportHtml) {
        if ($Message.reportHtml -isnot [string] -or $Message.reportHtml.Length -gt 20000 -or $Message.reportText -isnot [string]) { throw 'UI_REPORT' }
        if ($script:state -in @('Finished','Failed')) {
            $script:html = $Message.reportHtml
            $reportView.Text = $Message.reportText.Replace("`n", "`r`n")
            if ($previous -ne $script:state) { $tabs.SelectedTab = $reportPage }
        }
    }
    $save.Enabled = $null -ne $script:html
    if ($null -eq $script:html -and $script:state -in @('Finished','Failed')) {
        $reportView.Text = 'Отчёт не сформирован. ' + $status.Text + '. Подробности — на вкладке «Ход проверки».'
    }
    if ($previous -ne $script:state -and $script:state -eq 'AwaitingConfirmation') { $answer.Clear(); [void]$answer.Focus() }
    if ($script:closeAfterDiscard -and $script:state -eq 'Finished' -and $Message.code -eq 3) { $script:allowClose = $true; $form.Close() }
}

$primary.Add_Click({
    try {
        if (!(Test-ExistingEventSource)) {
            [void][Windows.Forms.MessageBox]::Show($form, 'Источник журнала Velociraptor отсутствует или отличается от ожидаемого. Ничего не исправлено; запуск заблокирован.', 'SecApp', 'OK', 'Warning')
            return
        }
        if ($script:state -eq 'Ready') { $primary.Enabled = $false; Send-Command 'prepare' '' }
        elseif ($script:state -eq 'AwaitingConfirmation') {
            $primary.Enabled = $false; $cancel.Enabled = $false; $answer.Enabled = $false
            Send-Command 'confirm' $answer.Text
            $answer.Clear()
        }
    } catch { Show-Failure }
})
$cancel.Add_Click({ try { $cancel.Enabled = $false; $primary.Enabled = $false; Send-Command 'cancel' '' } catch { Show-Failure } })
$close.Add_Click({ $form.Close() })
$form.Add_FormClosing({
    param($sender, $event)
    if ($script:allowClose -or $script:state -in @('Ready','Finished','Failed','Connecting')) { return }
    $event.Cancel = $true
    if ($script:state -eq 'AwaitingConfirmation') {
        $script:closeAfterDiscard = $true
        try { Send-Command 'cancel' '' } catch { Show-Failure }
    } else {
        [void][Windows.Forms.MessageBox]::Show($form, 'Дождитесь завершения текущего этапа. Закрытие окна не является подтверждением остановки повышенного процесса.', 'SecApp', 'OK', 'Information')
    }
})
$save.Add_Click({
    if ($null -eq $script:html) { return }
    $dialog = New-Object Windows.Forms.SaveFileDialog
    $dialog.Title = 'Частный незашифрованный отчёт — выберите новый файл'
    $dialog.Filter = 'HTML report (*.html)|*.html'
    $dialog.DefaultExt = 'html'
    $dialog.AddExtension = $true
    $dialog.FileName = 'SecApp-Defender.html'
    $dialog.OverwritePrompt = $true
    try {
        if ($dialog.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK) { return }
        $destination = [IO.Path]::GetFullPath($dialog.FileName)
        if ($destination -notmatch '^[A-Za-z]:\\' -or $destination.Substring(2).Contains(':') -or [IO.Path]::GetExtension($destination) -ine '.html') { throw 'LOCAL_HTML_REQUIRED' }
        $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($destination))
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) { throw 'LOCAL_DRIVE_REQUIRED' }
        # No overwrite, auto-open, directory creation, ACL change or raw-data save.
        $stream = New-Object IO.FileStream($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $bytes = $utf8.GetBytes($script:html); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() }
        finally { $stream.Dispose() }
        [void][Windows.Forms.MessageBox]::Show($form, 'Частный HTML-отчёт сохранён без шифрования. Перед передачей другому человеку проверьте его содержание.', 'SecApp', 'OK', 'Information')
    } catch {
        [void][Windows.Forms.MessageBox]::Show($form, 'Сохранение не подтверждено. Существующие файлы не перезаписываются. При ошибке записи новый файл мог остаться неполным.', 'SecApp', 'OK', 'Warning')
    } finally { $dialog.Dispose() }
})

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 100
$timer.Add_Tick({
    try {
        if (!$script:readTask.IsCompleted) { return }
        $count = $script:readTask.GetAwaiter().GetResult()
        if ($count -eq 0) { Show-Failure; return }
        $script:pending += [string]::new($script:buffer, 0, $count)
        if ($script:pending.Length -gt 65536) { throw 'UI_MESSAGE_LIMIT' }
        while (($index = $script:pending.IndexOf("`n")) -ge 0) {
            $line = $script:pending.Substring(0, $index)
            $script:pending = $script:pending.Substring($index + 1)
            Apply-State (ConvertFrom-Json -InputObject $line)
        }
        $script:readTask = $script:reader.ReadAsync($script:buffer, 0, $script:buffer.Length)
    } catch { Show-Failure }
})
$form.Add_Shown({ try { Send-Command 'ready' ''; $timer.Start() } catch { Show-Failure } })
try { [void]$form.ShowDialog() }
finally { $timer.Stop(); $timer.Dispose(); $form.Dispose() }
