# Toast text arrives via environment variables to avoid any argument
# parsing problems (parentheses in args were crashing PowerShell).
$Title = $env:AIM_TOAST_TITLE
$Body = $env:AIM_TOAST_BODY

if (-not $Title) { $Title = "AIMaligator" }
if (-not $Body) { $Body = "" }

# Windows toast notification (transient, no extra modules needed).
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
    [Windows.UI.Notifications.ToastTemplateType]::ToastText02
)
$textNodes = $template.GetElementsByTagName("text")
$null = $textNodes.Item(0).AppendChild($template.CreateTextNode($Title))
$null = $textNodes.Item(1).AppendChild($template.CreateTextNode($Body))

$toast = New-Object Windows.UI.Notifications.ToastNotification $template
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AIMaligator").Show($toast)
