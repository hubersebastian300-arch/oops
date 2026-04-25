import Cocoa
import Darwin
import Foundation
import Network

enum Severity: Int {
    case ok = 0
    case warning = 1
    case hardFail = 2
}

enum GuardState {
    case safe
    case check
    case warning

    var text: String {
        switch self {
        case .safe: return "safe"
        case .check: return "check"
        case .warning: return "warning"
        }
    }

    var color: NSColor {
        switch self {
        case .safe: return NSColor.systemGreen
        case .check: return NSColor.systemYellow
        case .warning: return NSColor.systemRed
        }
    }
}

enum CheckMode {
    case local
    case publicExit
    case full

    var label: String {
        switch self {
        case .local: return "local"
        case .publicExit: return "exit"
        case .full: return "full"
        }
    }
}

struct CheckLine {
    let name: String
    let severity: Severity
    let detail: String
    let localPrerequisite: Bool
    let wrongExit: Bool
    let affectsState: Bool

    init(name: String,
         severity: Severity,
         detail: String,
         localPrerequisite: Bool = false,
         wrongExit: Bool = false,
         affectsState: Bool = false) {
        self.name = name
        self.severity = severity
        self.detail = detail
        self.localPrerequisite = localPrerequisite
        self.wrongExit = wrongExit
        self.affectsState = affectsState
    }
}

struct CommandResult {
    let output: String
    let status: Int32
}

final class Shell {
    static func run(_ launchPath: String, _ arguments: [String], timeout: TimeInterval = 12) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return CommandResult(output: "launch failed: \(error.localizedDescription)", status: 127)
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        if process.isRunning {
            process.terminate()
            return CommandResult(output: "timeout after \(Int(timeout))s", status: 124)
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return CommandResult(output: output.trimmingCharacters(in: .whitespacesAndNewlines),
                             status: process.terminationStatus)
    }
}

final class ReferencePolicy {
    let targetIP = ReferencePolicy.env("OOPS_TARGET_IP", fallback: "203.0.113.10")
    let proxyEndpoint = ReferencePolicy.env("OOPS_PROXY_ENDPOINT", fallback: "127.0.0.1:7897")
    let tunDevice = ReferencePolicy.env("OOPS_TUN_DEVICE", fallback: "utun1024")
    let tunIPv4 = ReferencePolicy.env("OOPS_TUN_IPV4", fallback: "28.0.0.1")
    let fallbackNetworkService = ReferencePolicy.env("OOPS_FALLBACK_NETWORK_SERVICE", fallback: "Wi-Fi")
    let proxyURL = ReferencePolicy.env("OOPS_PROXY_URL", fallback: "http://127.0.0.1:7897")
    let riskCIDR = ReferencePolicy.env("OOPS_RISK_CIDR", fallback: "203.0.113.0/24")
    let asn = Int(ReferencePolicy.env("OOPS_ASN", fallback: "0")) ?? 0
    let pixelScanSipURL = "https://mtu.pixelscan.net/sip"

    private static func env(_ key: String, fallback: String) -> String {
        let value = ProcessInfo.processInfo.environment[key] ?? ""
        return value.isEmpty ? fallback : value
    }
}

final class StatusBadgeView: NSView {
    var onRightClick: (() -> Void)?
    private var state: GuardState = .check
    private let font = NSFont.monospacedSystemFont(ofSize: 18, weight: .semibold)

    override var intrinsicContentSize: NSSize {
        let size = attributedText().size()
        return NSSize(width: ceil(size.width) + 16, height: 32)
    }

    func setState(_ newState: GuardState) {
        state = newState
        invalidateIntrinsicContentSize()
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.clear.setFill()
        dirtyRect.fill()

        let text = attributedText()
        let size = text.size()
        let point = NSPoint(x: (bounds.width - size.width) / 2,
                            y: (bounds.height - size.height) / 2)
        text.draw(at: point)
    }

    override func rightMouseDown(with event: NSEvent) {
        onRightClick?()
    }

    private func attributedText() -> NSAttributedString {
        NSAttributedString(
            string: state.text,
            attributes: [
                .font: font,
                .foregroundColor: state.color,
                .shadow: textShadow()
            ]
        )
    }

    private func textShadow() -> NSShadow {
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
        shadow.shadowBlurRadius = 3
        shadow.shadowOffset = NSSize(width: 0, height: -1)
        return shadow
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let policy = ReferencePolicy()
    private var statusPanel: NSPanel!
    private var statusView: StatusBadgeView!
    private var infoPanel: NSPanel?
    private var outputView: NSTextView?
    private var launchToggleButton: NSButton?
    private var localTimer: Timer?
    private var publicTimer: Timer?
    private var localCheckInProgress = false
    private var publicCheckInProgress = false
    private var fullCheckInProgress = false
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "oops.path")
    private var lastPathStatus: NWPath.Status?
    private var publicCheckWorkItem: DispatchWorkItem?
    private var lastLinesByName: [String: CheckLine] = [:]
    private var lastAlertAt = Date.distantPast
    private var lastProblemLogAt = Date.distantPast
    private var graceUntil = Date().addingTimeInterval(90)
    private var hasReachedSafe = false
    private var logLines: [String] = []
    private var currentState: GuardState = .check
    private let stateFile = "/tmp/oops.guard.state"
    private let logFile = "/tmp/oops.guard.log"
    private let launchAgentLabel = "com.morgan.oops"
    private let requiredBaselineChecks = ["system public IP"]

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        try? FileManager.default.removeItem(atPath: logFile)
        buildStatusPanel()
        appendOutput("oops! started.")
        appendOutput("Target exit: \(policy.targetIP)")
        appendOutput("Read-only mode: this app never changes network services or firewall rules.")
        appendOutput("Ultra-light cadence: local 2s, exit on startup/network/6h, full check manual.")
        setState(.check, force: true)
        runCheck(reason: "startup", mode: .publicExit, forceLog: true)
        startTimers()
        startPathMonitor()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    private func buildStatusPanel() {
        statusView = StatusBadgeView(frame: NSRect(x: 0, y: 0, width: 86, height: 32))
        statusView.onRightClick = { [weak self] in
            self?.toggleInfoPanel()
        }

        statusPanel = NSPanel(contentRect: statusView.frame,
                              styleMask: [.borderless, .nonactivatingPanel],
                              backing: .buffered,
                              defer: false)
        statusPanel.contentView = statusView
        statusPanel.isOpaque = false
        statusPanel.backgroundColor = .clear
        statusPanel.hasShadow = false
        statusPanel.level = .statusBar
        statusPanel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        statusPanel.ignoresMouseEvents = false
        statusPanel.isReleasedWhenClosed = false
        statusPanel.orderFrontRegardless()
        positionStatusPanel()
    }

    private func positionStatusPanel() {
        guard let screen = NSScreen.main else { return }
        let frame = screen.visibleFrame
        let targetSize = statusView.intrinsicContentSize
        statusPanel.setContentSize(targetSize)
        let x = frame.maxX - targetSize.width - 18
        let y = frame.minY + 12
        statusPanel.setFrameOrigin(NSPoint(x: x, y: y))
    }

    private func buildInfoPanel() -> NSPanel {
        let panelSize = NSSize(width: 680, height: 480)
        let content = NSView(frame: NSRect(origin: .zero, size: panelSize))
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor.windowBackgroundColor.withAlphaComponent(0.86).cgColor

        let title = NSTextField(labelWithString: "info")
        title.font = NSFont.systemFont(ofSize: 20, weight: .semibold)
        title.textColor = .labelColor
        title.frame = NSRect(x: 18, y: panelSize.height - 42, width: 220, height: 24)
        content.addSubview(title)

        let quitButton = NSButton(title: "quit", target: self, action: #selector(quitApp))
        quitButton.frame = NSRect(x: panelSize.width - 440, y: panelSize.height - 46, width: 52, height: 28)
        content.addSubview(quitButton)

        let launchButton = NSButton(title: "●", target: self, action: #selector(toggleLaunchAtLogin))
        launchButton.frame = NSRect(x: panelSize.width - 472, y: panelSize.height - 46, width: 26, height: 28)
        launchButton.isBordered = false
        launchButton.focusRingType = .none
        launchToggleButton = launchButton
        content.addSubview(launchButton)
        updateLaunchToggleButton()

        let checkButton = NSButton(title: "check now", target: self, action: #selector(checkNow))
        checkButton.frame = NSRect(x: panelSize.width - 382, y: panelSize.height - 46, width: 92, height: 28)
        content.addSubview(checkButton)

        let fullButton = NSButton(title: "full check", target: self, action: #selector(fullCheckNow))
        fullButton.frame = NSRect(x: panelSize.width - 284, y: panelSize.height - 46, width: 80, height: 28)
        content.addSubview(fullButton)

        let hideButton = NSButton(title: "hide", target: self, action: #selector(hideInfo))
        hideButton.frame = NSRect(x: panelSize.width - 62, y: panelSize.height - 46, width: 44, height: 28)
        content.addSubview(hideButton)

        let scroll = NSScrollView(frame: NSRect(x: 18, y: 18, width: panelSize.width - 36, height: panelSize.height - 76))
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder
        outputView = NSTextView(frame: scroll.bounds)
        outputView?.isEditable = false
        outputView?.isSelectable = true
        outputView?.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        outputView?.textColor = .labelColor
        outputView?.backgroundColor = NSColor.textBackgroundColor.withAlphaComponent(0.72)
        outputView?.string = logLines.joined(separator: "\n")
        scroll.documentView = outputView
        content.addSubview(scroll)

        let panel = NSPanel(contentRect: NSRect(origin: .zero, size: panelSize),
                            styleMask: [.titled, .closable, .utilityWindow, .resizable],
                            backing: .buffered,
                            defer: false)
        panel.title = "oops! info"
        panel.contentView = content
        panel.isReleasedWhenClosed = false
        panel.alphaValue = 0.9
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces]
        positionInfoPanel(panel)
        return panel
    }

    private func positionInfoPanel(_ panel: NSPanel) {
        guard let screen = NSScreen.main else {
            panel.center()
            return
        }
        let frame = screen.visibleFrame
        let size = panel.frame.size
        let x = frame.maxX - size.width - 18
        let y = frame.minY + 52
        panel.setFrameOrigin(NSPoint(x: x, y: y))
    }

    private func toggleInfoPanel() {
        if let panel = infoPanel, panel.isVisible {
            panel.orderOut(nil)
            return
        }
        if infoPanel == nil {
            infoPanel = buildInfoPanel()
        }
        updateLaunchToggleButton()
        outputView?.string = logLines.joined(separator: "\n")
        outputView?.scrollToEndOfDocument(nil)
        if let panel = infoPanel {
            positionInfoPanel(panel)
            panel.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    @objc private func hideInfo() {
        infoPanel?.orderOut(nil)
    }

    @objc private func checkNow() {
        runCheck(reason: "manual", mode: .publicExit, forceLog: true)
    }

    @objc private func fullCheckNow() {
        runCheck(reason: "manual", mode: .full, forceLog: true)
    }

    @objc private func toggleLaunchAtLogin() {
        let nextValue = !isLaunchAtLoginEnabled()
        let result = setLaunchAtLogin(enabled: nextValue)
        if result.status == 0 {
            appendOutput("Launch at login: \(nextValue ? "enabled" : "disabled").")
        } else {
            appendOutput("Launch at login toggle failed: \(short(result.output))")
        }
        updateLaunchToggleButton()
    }

    private func updateLaunchToggleButton() {
        guard let button = launchToggleButton else { return }
        let enabled = isLaunchAtLoginEnabled()
        button.attributedTitle = NSAttributedString(
            string: "●",
            attributes: [
                .font: NSFont.systemFont(ofSize: 19, weight: .bold),
                .foregroundColor: enabled ? NSColor.systemGreen : NSColor.systemGray
            ]
        )
        button.toolTip = enabled ? "launch at login: on" : "launch at login: off"
    }

    private func isLaunchAtLoginEnabled() -> Bool {
        let target = "gui/\(getuid())"
        let result = Shell.run("/bin/launchctl", ["print-disabled", target], timeout: 5)
        guard result.status == 0 else { return false }
        for line in result.output.split(separator: "\n") {
            let text = String(line)
            if text.contains("\"\(launchAgentLabel)\"") {
                return text.contains("=> enabled")
            }
        }
        return FileManager.default.fileExists(atPath: "\(NSHomeDirectory())/Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    private func setLaunchAtLogin(enabled: Bool) -> CommandResult {
        let command = enabled ? "enable" : "disable"
        let target = "gui/\(getuid())/\(launchAgentLabel)"
        return Shell.run("/bin/launchctl", [command, target], timeout: 8)
    }

    @objc private func quitApp() {
        appendOutput("Quitting oops! by user request.")
        let text = [
            "state=quit",
            "target=\(policy.targetIP)",
            "updated_at=\(Self.timestamp())"
        ].joined(separator: "\n") + "\n"
        try? text.write(toFile: stateFile, atomically: true, encoding: .utf8)
        NSApp.terminate(nil)
    }

    private func startTimers() {
        localTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.runCheck(reason: "timer", mode: .local)
        }
        publicTimer = Timer.scheduledTimer(withTimeInterval: 21_600, repeats: true) { [weak self] _ in
            self?.runCheck(reason: "timer", mode: .publicExit, forceLog: true)
        }
    }

    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if self.lastPathStatus == nil {
                    self.lastPathStatus = path.status
                    self.appendOutput("Network path: \(self.label(forPath: path.status))")
                    return
                }
                if self.lastPathStatus == path.status { return }
                self.lastPathStatus = path.status
                self.appendOutput("Network path: \(self.label(forPath: path.status))")
                if path.status == .satisfied {
                    self.schedulePublicCheck(reason: "network", delay: 6)
                } else {
                    self.setState(.check)
                }
            }
        }
        pathMonitor.start(queue: pathQueue)
    }

    private func schedulePublicCheck(reason: String, delay: TimeInterval) {
        publicCheckWorkItem?.cancel()
        let item = DispatchWorkItem { [weak self] in
            self?.runCheck(reason: reason, mode: .publicExit, forceLog: true)
        }
        publicCheckWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: item)
    }

    private func runCheck(reason: String, mode: CheckMode, forceLog: Bool = false) {
        if isInProgress(mode) { return }
        setInProgress(mode, true)
        DispatchQueue.global(qos: .utility).async {
            let lines = self.collectChecks(mode: mode)
            DispatchQueue.main.async {
                self.setInProgress(mode, false)
                self.handle(lines: lines,
                            reason: "\(mode.label): \(reason)",
                            forceLog: forceLog || mode == .full)
            }
        }
    }

    private func isInProgress(_ mode: CheckMode) -> Bool {
        switch mode {
        case .local: return localCheckInProgress
        case .publicExit: return publicCheckInProgress
        case .full: return fullCheckInProgress
        }
    }

    private func setInProgress(_ mode: CheckMode, _ value: Bool) {
        switch mode {
        case .local: localCheckInProgress = value
        case .publicExit: publicCheckInProgress = value
        case .full: fullCheckInProgress = value
        }
    }

    private func collectChecks(mode: CheckMode) -> [CheckLine] {
        var lines = collectLocalChecks()
        if mode == .local { return lines }

        lines.append(checkDirectPublicIP())
        if mode == .publicExit { return lines }

        lines.append(checkIPInfo())
        lines.append(checkCloudflareTrace())
        lines.append(checkClaudeTrace())
        lines.append(checkNetCoffeePage())
        lines.append(contentsOf: checkNetCoffeeRisk())
        lines.append(checkNetCoffeeClaudeStatus())
        lines.append(checkPixelScanSip())
        lines.append(checkPixelScanBrowserHelper())
        return lines
    }

    private func collectLocalChecks() -> [CheckLine] {
        var lines: [CheckLine] = []
        lines.append(checkProxyPort())
        lines.append(checkMihomoProcess())
        lines.append(checkTun())
        lines.append(checkSystemProxy())
        return lines
    }

    private func checkProxyPort() -> CheckLine {
        let result = Shell.run("/usr/bin/nc", ["-z", "-G", "3", "127.0.0.1", "7897"], timeout: 5)
        if result.status == 0 {
            return CheckLine(name: "Clash mixed port", severity: .ok,
                             detail: "127.0.0.1:7897 open",
                             localPrerequisite: true)
        }
        return CheckLine(name: "Clash mixed port", severity: .hardFail,
                         detail: "127.0.0.1:7897 closed or unreachable",
                         localPrerequisite: true)
    }

    private func checkMihomoProcess() -> CheckLine {
        let result = Shell.run("/usr/bin/pgrep", ["-x", "verge-mihomo"], timeout: 5)
        if result.status == 0 {
            return CheckLine(name: "mihomo core", severity: .ok,
                             detail: "running pid(s): \(result.output)",
                             localPrerequisite: true)
        }
        return CheckLine(name: "mihomo core", severity: .hardFail,
                         detail: "verge-mihomo not running",
                         localPrerequisite: true)
    }

    private func checkTun() -> CheckLine {
        let result = Shell.run("/sbin/ifconfig", [policy.tunDevice], timeout: 5)
        if result.status == 0 && result.output.contains("inet \(policy.tunIPv4)") {
            return CheckLine(name: "TUN", severity: .ok,
                             detail: "\(policy.tunDevice) has \(policy.tunIPv4)",
                             localPrerequisite: true)
        }
        return CheckLine(name: "TUN", severity: .hardFail,
                         detail: "\(policy.tunDevice) missing or does not have \(policy.tunIPv4)",
                         localPrerequisite: true)
    }

    private func checkSystemProxy() -> CheckLine {
        let result = Shell.run("/usr/sbin/scutil", ["--proxy"], timeout: 5)
        let text = result.output
        let ok = text.contains("HTTPEnable : 1")
            && text.contains("HTTPProxy : 127.0.0.1")
            && text.contains("HTTPPort : 7897")
            && text.contains("HTTPSEnable : 1")
            && text.contains("HTTPSProxy : 127.0.0.1")
            && text.contains("HTTPSPort : 7897")
            && text.contains("SOCKSEnable : 1")
            && text.contains("SOCKSProxy : 127.0.0.1")
            && text.contains("SOCKSPort : 7897")
        if ok {
            return CheckLine(name: "macOS system proxy", severity: .ok,
                             detail: "HTTP/HTTPS/SOCKS => \(policy.proxyEndpoint)",
                             affectsState: true)
        }
        return CheckLine(name: "macOS system proxy", severity: .hardFail,
                         detail: "system proxy is not fully pinned to \(policy.proxyEndpoint)",
                         affectsState: true)
    }

    private func checkDirectPublicIP() -> CheckLine {
        let result = Shell.run("/usr/bin/curl", ["-sS", "--max-time", "12", "https://api.ipify.org"], timeout: 15)
        let ip = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if ip == policy.targetIP {
            return CheckLine(name: "system public IP", severity: .ok,
                             detail: ip,
                             affectsState: true)
        }
        if result.status == 0 && isIPv4(ip) {
            return CheckLine(name: "system public IP", severity: .hardFail,
                             detail: "expected \(policy.targetIP), got \(ip)",
                             wrongExit: true,
                             affectsState: true)
        }
        return CheckLine(name: "system public IP", severity: .warning,
                         detail: "unable to verify: \(result.output)",
                         affectsState: true)
    }

    private func checkIPInfo() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "--max-time", "15", "https://ipinfo.io/json"],
                               timeout: 18)
        guard let json = parseJSON(result.output) else {
            return CheckLine(name: "ipinfo", severity: .warning, detail: "unable to parse response: \(short(result.output))")
        }
        let ip = json["ip"] as? String ?? ""
        let org = json["org"] as? String ?? ""
        let country = json["country"] as? String ?? ""
        let tz = json["timezone"] as? String ?? ""
        if ip.isEmpty {
            return CheckLine(name: "ipinfo", severity: .warning,
                             detail: "response did not include an IP")
        }
        if ip != policy.targetIP {
            return CheckLine(name: "ipinfo", severity: .hardFail,
                             detail: "expected \(policy.targetIP), got \(ip); org=\(org), country=\(country)",
                             wrongExit: true)
        }
        if !org.contains("AS7018") || country != "US" {
            return CheckLine(name: "ipinfo", severity: .warning,
                             detail: "ip=\(ip), org=\(org), country=\(country), tz=\(tz)")
        }
        return CheckLine(name: "ipinfo", severity: .ok,
                         detail: "ip=\(ip), org=\(org), country=\(country), tz=\(tz)")
    }

    private func checkCloudflareTrace() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "--max-time", "12", "https://1.1.1.1/cdn-cgi/trace"],
                               timeout: 15)
        return traceLine(name: "Cloudflare trace", trace: parseTrace(result.output))
    }

    private func checkClaudeTrace() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "--max-time", "12", "https://claude.ai/cdn-cgi/trace"],
                               timeout: 15)
        return traceLine(name: "Claude trace", trace: parseTrace(result.output))
    }

    private func traceLine(name: String, trace: [String: String]) -> CheckLine {
        let ip = trace["ip"] ?? ""
        let colo = trace["colo"] ?? ""
        let loc = trace["loc"] ?? ""
        let warp = trace["warp"] ?? ""
        if ip.isEmpty {
            return CheckLine(name: name, severity: .warning,
                             detail: "unable to verify trace response")
        }
        if ip != policy.targetIP {
            return CheckLine(name: name, severity: .hardFail,
                             detail: "expected \(policy.targetIP), got \(ip); colo=\(colo), loc=\(loc)",
                             wrongExit: true)
        }
        if loc != "US" || warp != "off" {
            return CheckLine(name: name, severity: .warning,
                             detail: "ip=\(ip), colo=\(colo), loc=\(loc), warp=\(warp)")
        }
        return CheckLine(name: name, severity: .ok,
                         detail: "ip=\(ip), colo=\(colo), loc=\(loc), warp=\(warp)")
    }

    private func checkNetCoffeePage() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "20", "https://ip.net.coffee/claude/"],
                               timeout: 23)
        let code = result.output.split(separator: " ").first.map(String.init) ?? ""
        if code == "200" {
            return CheckLine(name: "Net.Coffee page", severity: .ok, detail: "https://ip.net.coffee/claude/ status \(result.output)")
        }
        return CheckLine(name: "Net.Coffee page", severity: .warning, detail: "unexpected status \(result.output)")
    }

    private func checkNetCoffeeRisk() -> [CheckLine] {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "--max-time", "15", "https://ip.net.coffee/api/iprisk/\(policy.targetIP)"],
                               timeout: 18)
        guard let json = parseJSON(result.output) else {
            return [CheckLine(name: "Net.Coffee risk", severity: .warning, detail: "unable to parse response: \(short(result.output))")]
        }

        var lines: [CheckLine] = []
        let cidr = json["cidr"] as? String ?? ""
        let asn = json["asn"] as? Int ?? -1
        let trust = json["trust_score"] as? Int ?? -1
        let isResidential = json["isResidential"] as? Bool ?? false
        let company = json["company_name"] as? String ?? ""
        let flags = ["is_datacenter", "is_vpn", "is_proxy", "is_tor", "is_crawler", "is_abuser"]
        let raisedFlags = flags.filter { (json[$0] as? Bool) == true }

        if cidr == policy.riskCIDR && asn == policy.asn && isResidential {
            lines.append(CheckLine(name: "Net.Coffee identity", severity: .ok,
                                   detail: "cidr=\(cidr), asn=\(asn), residential=true, company=\(company)"))
        } else {
            lines.append(CheckLine(name: "Net.Coffee identity", severity: .warning,
                                   detail: "cidr=\(cidr), asn=\(asn), residential=\(isResidential), company=\(company)"))
        }

        if raisedFlags.isEmpty && trust >= 80 {
            lines.append(CheckLine(name: "Net.Coffee risk", severity: .ok,
                                   detail: "trust_score=\(trust), no VPN/proxy/Tor/abuse flags"))
        } else {
            let flagsText = raisedFlags.joined(separator: ",")
            lines.append(CheckLine(name: "Net.Coffee risk", severity: .warning,
                                   detail: "trust_score=\(trust), flags=\(flagsText)"))
        }
        return lines
    }

    private func checkNetCoffeeClaudeStatus() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-sS", "--max-time", "12", "https://ip.net.coffee/claude/status.json"],
                               timeout: 15)
        guard let json = parseJSON(result.output) else {
            return CheckLine(name: "Claude service status", severity: .warning,
                             detail: "unable to parse response: \(short(result.output))")
        }
        let indicator = json["overall_indicator"] as? String ?? ""
        let overall = json["overall"] as? String ?? ""
        if indicator == "none" {
            return CheckLine(name: "Claude service status", severity: .ok, detail: "\(overall) (\(indicator))")
        }
        return CheckLine(name: "Claude service status", severity: .warning, detail: "\(overall) (\(indicator))")
    }

    private func checkPixelScanSip() -> CheckLine {
        let result = Shell.run("/usr/bin/curl",
                               ["-x", policy.proxyURL, "-k", "-sS", "--max-time", "12", policy.pixelScanSipURL],
                               timeout: 15)
        guard let json = parseJSON(result.output) else {
            return CheckLine(name: "PixelScan IP relay", severity: .warning,
                             detail: "unable to parse response: \(short(result.output))")
        }
        let sr = json["sr"] as? String ?? ""
        let r = json["r"] as? String ?? ""
        let ips = extractIPv4s(from: "\(sr) \(r)")
        if ips.contains(policy.targetIP) {
            return CheckLine(name: "PixelScan IP relay", severity: .ok,
                             detail: "sr=\(sr), r=\(r)")
        }
        if let got = ips.first {
            return CheckLine(name: "PixelScan IP relay", severity: .hardFail,
                             detail: "expected \(policy.targetIP), got \(got); sr=\(sr), r=\(r)",
                             wrongExit: true)
        }
        return CheckLine(name: "PixelScan IP relay", severity: .warning,
                         detail: "no public IPv4 in response: \(short(result.output))")
    }

    private func checkPixelScanBrowserHelper() -> CheckLine {
        let helperPath = pixelScanHelperPath()
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            return CheckLine(name: "PixelScan browser", severity: .warning,
                             detail: "helper missing at \(helperPath)")
        }

        let result = Shell.run(helperPath, [], timeout: 55)
        guard let line = result.output
            .split(separator: "\n")
            .map(String.init)
            .first(where: { $0.hasPrefix("OOPS_PIXELSCAN_RESULT\t") }) else {
            return CheckLine(name: "PixelScan browser", severity: .warning,
                             detail: "helper returned no result: \(short(result.output))")
        }

        let parts = line.split(separator: "\t", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            return CheckLine(name: "PixelScan browser", severity: .warning,
                             detail: "helper result was malformed: \(short(line))")
        }

        let severity: Severity = parts[1] == "ok" ? .ok : .warning
        return CheckLine(name: "PixelScan browser", severity: severity,
                         detail: parts[2])
    }

    private func pixelScanHelperPath() -> String {
        if let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent().path {
            return "\(executableDirectory)/oops-pixelscan-helper"
        }
        return "\(Bundle.main.bundlePath)/Contents/MacOS/oops-pixelscan-helper"
    }

    private func handle(lines: [CheckLine], reason: String, forceLog: Bool = false) {
        for line in lines {
            lastLinesByName[line.name] = line
        }

        let allLines = Array(lastLinesByName.values)
        let baselineVerified = requiredBaselineChecks.allSatisfy {
            lastLinesByName[$0]?.severity == .ok
        }
        let confirmedWrongExit = allLines.filter { $0.wrongExit }
        let stateLines = allLines.filter { $0.affectsState || $0.localPrerequisite || $0.wrongExit }
        let localPrerequisiteFailures = allLines.filter { $0.severity == .hardFail && $0.localPrerequisite }
        let systemProxyFailure = allLines.filter { $0.severity == .hardFail && $0.name == "macOS system proxy" }
        let hardFailures = confirmedWrongExit + (hasReachedSafe ? localPrerequisiteFailures : [])
        let warnings = stateLines.filter { $0.severity == .warning }
            + (!hasReachedSafe ? localPrerequisiteFailures : [])
            + systemProxyFailure
        let timestamp = Self.timestamp()
        let nextState: GuardState
        if !hardFailures.isEmpty {
            nextState = .warning
        } else if !warnings.isEmpty || !baselineVerified {
            nextState = .check
        } else {
            nextState = .safe
        }
        let stateChanged = nextState != currentState
        let hasProblem = !hardFailures.isEmpty || !warnings.isEmpty
        let shouldLog = forceLog
            || stateChanged
            || reason.contains("manual")
            || reason.contains("startup")
            || (hasProblem && Date().timeIntervalSince(lastProblemLogAt) > 25)

        if shouldLog {
            appendOutput("")
            appendOutput("=== \(timestamp) check: \(reason) ===")
            for line in lines {
                appendOutput("[\(label(for: line.severity))] \(line.name): \(line.detail)")
            }
            if hasProblem {
                lastProblemLogAt = Date()
            }
        }

        if !hardFailures.isEmpty {
            let reasonText = hardFailures.map { $0.name }.joined(separator: ", ")
            setState(.warning)
            if confirmedWrongExit.isEmpty && Date() < graceUntil {
                let seconds = Int(graceUntil.timeIntervalSinceNow.rounded(.up))
                if shouldLog {
                    appendOutput("Hard failure inside startup grace. Warning stays read-only for \(max(seconds, 0))s: \(reasonText)")
                }
                if stateChanged || Date().timeIntervalSince(lastAlertAt) > 30 {
                    raiseAndShake()
                }
                return
            }

            if shouldLog {
                appendOutput("Read-only warning: \(reasonText)")
            }
            if stateChanged || Date().timeIntervalSince(lastAlertAt) > 30 {
                raiseAndShake()
            }
            return
        }

        if !warnings.isEmpty || !baselineVerified {
            let reasonText = warnings.map { $0.name }.joined(separator: ", ")
            setState(.check)
            if shouldLog {
                appendOutput(reasonText.isEmpty ? "Waiting for baseline verification." : "Soft warning: \(reasonText)")
            }
            if stateChanged || Date().timeIntervalSince(lastAlertAt) > 60 {
                if !warnings.isEmpty {
                    raiseAndShake()
                }
            }
            return
        }

        hasReachedSafe = true
        setState(.safe)
    }

    private func setState(_ newState: GuardState, force: Bool = false) {
        if !force && currentState == newState {
            return
        }
        currentState = newState
        statusView.setState(newState)
        positionStatusPanel()
        statusPanel.orderFrontRegardless()
        writeStateFile()
    }

    private func appendOutput(_ line: String) {
        logLines.append(line)
        if logLines.count > 120 {
            logLines.removeFirst(logLines.count - 120)
        }
        outputView?.string = logLines.joined(separator: "\n")
        outputView?.scrollToEndOfDocument(nil)
        try? logLines.joined(separator: "\n").write(toFile: logFile,
                                                    atomically: true,
                                                    encoding: .utf8)
    }

    private func writeStateFile() {
        let text = [
            "state=\(currentState.text)",
            "target=\(policy.targetIP)",
            "updated_at=\(Self.timestamp())"
        ].joined(separator: "\n") + "\n"
        try? text.write(toFile: stateFile, atomically: true, encoding: .utf8)
    }

    private func raiseAndShake() {
        lastAlertAt = Date()
        statusPanel.orderFrontRegardless()
        if infoPanel?.isVisible == true {
            infoPanel?.makeKeyAndOrderFront(nil)
        }
        NSSound.beep()
        let original = statusPanel.frame
        let offsets: [CGFloat] = [-10, 10, -8, 8, -5, 5, -2, 2, 0]
        for (index, offset) in offsets.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + Double(index) * 0.045) {
                var frame = original
                frame.origin.x += offset
                self.statusPanel.setFrame(frame, display: true)
            }
        }
    }

    private func parseJSON(_ text: String) -> [String: Any]? {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any] else {
            return nil
        }
        return dictionary
    }

    private func parseTrace(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            if parts.count == 2 {
                result[parts[0]] = parts[1]
            }
        }
        return result
    }

    private func extractIPv4s(from text: String) -> [String] {
        let pattern = #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let nsRange = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: nsRange).compactMap { match in
            guard let range = Range(match.range, in: text) else { return nil }
            let ip = String(text[range])
            let parts = ip.split(separator: ".").compactMap { Int($0) }
            guard parts.count == 4, parts.allSatisfy({ $0 >= 0 && $0 <= 255 }) else { return nil }
            return ip
        }
    }

    private func isIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".").compactMap { Int($0) }
        return parts.count == 4 && parts.allSatisfy { $0 >= 0 && $0 <= 255 }
    }

    private func short(_ text: String) -> String {
        let compact = text.replacingOccurrences(of: "\n", with: " ")
        if compact.count <= 180 { return compact }
        return String(compact.prefix(180)) + "..."
    }

    private func label(for severity: Severity) -> String {
        switch severity {
        case .ok: return "OK"
        case .warning: return "WARN"
        case .hardFail: return "FAIL"
        }
    }

    private func label(forPath status: NWPath.Status) -> String {
        switch status {
        case .satisfied: return "satisfied"
        case .unsatisfied: return "unsatisfied"
        case .requiresConnection: return "requiresConnection"
        @unknown default: return "unknown"
        }
    }

    private static func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
