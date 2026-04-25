using System.Diagnostics;
using System.Drawing;
using System.Net.Http;
using System.Net.Sockets;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Oops.Win;

internal enum GuardState
{
    Safe,
    Check,
    Warning
}

internal sealed record GuardPolicy(
    string TargetIp,
    string ProxyHost,
    int ProxyPort,
    string ProxyProcess,
    TimeSpan LocalInterval,
    TimeSpan PublicInterval)
{
    public static GuardPolicy FromEnvironment()
    {
        return new GuardPolicy(
            Env("OOPS_TARGET_IP", "203.0.113.10"),
            Env("OOPS_PROXY_HOST", "127.0.0.1"),
            int.TryParse(Env("OOPS_PROXY_PORT", "7897"), out var port) ? port : 7897,
            Env("OOPS_PROXY_PROCESS", "clash-verge"),
            TimeSpan.FromSeconds(2),
            TimeSpan.FromHours(6));
    }

    private static string Env(string key, string fallback)
    {
        var value = Environment.GetEnvironmentVariable(key);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }
}

internal sealed class CheckResult
{
    public GuardState State { get; init; }
    public string Detail { get; init; } = "";
}

internal static class GuardChecks
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(12)
    };

    public static async Task<CheckResult> LocalAsync(GuardPolicy policy)
    {
        var notes = new List<string>();
        var warning = false;

        if (await IsPortOpenAsync(policy.ProxyHost, policy.ProxyPort))
        {
            notes.Add($"proxy port ok: {policy.ProxyHost}:{policy.ProxyPort}");
        }
        else
        {
            warning = true;
            notes.Add($"proxy port closed: {policy.ProxyHost}:{policy.ProxyPort}");
        }

        if (Process.GetProcessesByName(policy.ProxyProcess).Length > 0)
        {
            notes.Add($"process ok: {policy.ProxyProcess}");
        }
        else
        {
            warning = true;
            notes.Add($"process missing: {policy.ProxyProcess}");
        }

        var proxy = ReadUserProxy();
        if (proxy.Contains(policy.ProxyHost, StringComparison.OrdinalIgnoreCase)
            && proxy.Contains(policy.ProxyPort.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            notes.Add($"windows proxy ok: {proxy}");
        }
        else
        {
            warning = true;
            notes.Add($"windows proxy mismatch: {proxy}");
        }

        return new CheckResult
        {
            State = warning ? GuardState.Check : GuardState.Safe,
            Detail = string.Join(Environment.NewLine, notes)
        };
    }

    public static async Task<CheckResult> PublicIpAsync(GuardPolicy policy)
    {
        var local = await LocalAsync(policy);
        var notes = new List<string> { local.Detail };

        try
        {
            var ip = (await Http.GetStringAsync("https://api.ipify.org")).Trim();
            notes.Add($"public ip: {ip}");
            if (ip == policy.TargetIp)
            {
                return new CheckResult { State = local.State, Detail = string.Join(Environment.NewLine, notes) };
            }

            return new CheckResult
            {
                State = GuardState.Warning,
                Detail = string.Join(Environment.NewLine, notes.Append($"expected: {policy.TargetIp}"))
            };
        }
        catch (Exception ex)
        {
            notes.Add($"public ip check failed: {ex.Message}");
            return new CheckResult { State = GuardState.Check, Detail = string.Join(Environment.NewLine, notes) };
        }
    }

    private static async Task<bool> IsPortOpenAsync(string host, int port)
    {
        using var client = new TcpClient();
        try
        {
            var connectTask = client.ConnectAsync(host, port);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(3));
            return await Task.WhenAny(connectTask, timeoutTask) == connectTask && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static string ReadUserProxy()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
        var enabled = key?.GetValue("ProxyEnable")?.ToString() ?? "0";
        var server = key?.GetValue("ProxyServer")?.ToString() ?? "";
        return enabled == "1" ? server : "disabled";
    }
}

internal sealed class StatusForm : Form
{
    private readonly GuardPolicy _policy = GuardPolicy.FromEnvironment();
    private readonly Label _label = new();
    private readonly TextBox _info = new();
    private readonly System.Windows.Forms.Timer _localTimer = new();
    private readonly System.Windows.Forms.Timer _publicTimer = new();
    private bool _checking;

    public StatusForm()
    {
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = Color.Black;
        TransparencyKey = Color.Black;
        Size = new Size(120, 34);
        StartPosition = FormStartPosition.Manual;

        _label.AutoSize = true;
        _label.Font = new Font(FontFamily.GenericMonospace, 18, FontStyle.Bold);
        _label.ContextMenuStrip = BuildMenu();
        Controls.Add(_label);

        _info.Multiline = true;
        _info.ReadOnly = true;
        _info.Visible = false;

        _localTimer.Interval = (int)_policy.LocalInterval.TotalMilliseconds;
        _localTimer.Tick += async (_, _) => await RunCheckAsync(publicCheck: false);
        _publicTimer.Interval = (int)_policy.PublicInterval.TotalMilliseconds;
        _publicTimer.Tick += async (_, _) => await RunCheckAsync(publicCheck: true);

        Load += async (_, _) =>
        {
            PositionBottomRight();
            SetState(GuardState.Check, "starting");
            _localTimer.Start();
            _publicTimer.Start();
            await RunCheckAsync(publicCheck: true);
        };
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("info", null, (_, _) => MessageBox.Show(_info.Text, "oops! info", MessageBoxButtons.OK));
        menu.Items.Add("check now", null, async (_, _) => await RunCheckAsync(publicCheck: true));
        menu.Items.Add("quit", null, (_, _) => Close());
        return menu;
    }

    private async Task RunCheckAsync(bool publicCheck)
    {
        if (_checking) return;
        _checking = true;
        try
        {
            var result = publicCheck
                ? await GuardChecks.PublicIpAsync(_policy)
                : await GuardChecks.LocalAsync(_policy);
            SetState(result.State, result.Detail);
        }
        finally
        {
            _checking = false;
        }
    }

    private void SetState(GuardState state, string detail)
    {
        _label.Text = state switch
        {
            GuardState.Safe => "safe",
            GuardState.Check => "check",
            _ => "warning"
        };
        _label.ForeColor = state switch
        {
            GuardState.Safe => Color.LimeGreen,
            GuardState.Check => Color.Gold,
            _ => Color.Red
        };
        _info.Text = detail;
        Size = new Size(_label.Width + 16, 34);
        PositionBottomRight();
        if (state == GuardState.Warning)
        {
            Activate();
        }
    }

    private void PositionBottomRight()
    {
        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        Location = new Point(area.Right - Width - 18, area.Bottom - Height - 12);
    }
}

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new StatusForm());
    }
}
