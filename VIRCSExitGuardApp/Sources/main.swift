import Cocoa
import Foundation

enum GuardState {
    case safe
    case check

    var text: String {
        switch self {
        case .safe: return "safe"
        case .check: return "check"
        }
    }

    var color: NSColor {
        switch self {
        case .safe: return .systemGreen
        case .check: return .systemYellow
        }
    }
}

final class Policy {
    let targetIP = env("OOPS_TARGET_IP", fallback: "107.207.96.138")
    let checkURL = env("OOPS_CHECK_URL", fallback: "https://api.ipify.org")
    let interval = TimeInterval(Int(env("OOPS_CHECK_INTERVAL_SECONDS", fallback: "1800")) ?? 1800)
}

private func env(_ key: String, fallback: String) -> String {
    let value = ProcessInfo.processInfo.environment[key] ?? ""
    return value.isEmpty ? fallback : value
}

final class BadgeView: NSView {
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
        text.draw(at: NSPoint(x: (bounds.width - size.width) / 2,
                              y: (bounds.height - size.height) / 2))
    }

    override func rightMouseDown(with event: NSEvent) {
        onRightClick?()
    }

    private func attributedText() -> NSAttributedString {
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
        shadow.shadowBlurRadius = 3
        shadow.shadowOffset = NSSize(width: 0, height: -1)
        return NSAttributedString(
            string: state.text,
            attributes: [
                .font: font,
                .foregroundColor: state.color,
                .shadow: shadow
            ]
        )
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let policy = Policy()
    private var panel: NSPanel!
    private var badge: BadgeView!
    private var timer: Timer?
    private var checking = false
    private var lastInfo = "starting"
    private var lastIP = ""
    private var lastCheckedAt = Date.distantPast
    private let stateFile = "/tmp/oops.guard.state"

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        buildPanel()
        setState(.check, detail: "starting")
        checkNow()
        timer = Timer.scheduledTimer(withTimeInterval: policy.interval, repeats: true) { [weak self] _ in
            self?.checkNow()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    private func buildPanel() {
        badge = BadgeView(frame: NSRect(x: 0, y: 0, width: 86, height: 32))
        badge.onRightClick = { [weak self] in self?.showMenu() }

        panel = NSPanel(contentRect: badge.frame,
                        styleMask: [.borderless, .nonactivatingPanel],
                        backing: .buffered,
                        defer: false)
        panel.contentView = badge
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        panel.ignoresMouseEvents = false
        panel.isReleasedWhenClosed = false
        panel.orderFrontRegardless()
        positionPanel()
    }

    private func positionPanel() {
        guard let screen = NSScreen.main else { return }
        let frame = screen.visibleFrame
        let size = badge.intrinsicContentSize
        panel.setContentSize(size)
        panel.setFrameOrigin(NSPoint(x: frame.maxX - size.width - 18,
                                     y: frame.minY + 12))
    }

    private func showMenu() {
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "info", action: #selector(showInfo), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "check now", action: #selector(checkNowFromMenu), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "quit", action: #selector(quit), keyEquivalent: ""))
        for item in menu.items {
            item.target = self
        }
        menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
    }

    @objc private func showInfo() {
        let alert = NSAlert()
        alert.messageText = "oops!"
        alert.informativeText = lastInfo
        alert.alertStyle = .informational
        alert.runModal()
    }

    @objc private func checkNowFromMenu() {
        checkNow()
    }

    @objc private func quit() {
        timer?.invalidate()
        writeState("quit", detail: "user quit")
        NSApp.terminate(nil)
    }

    private func checkNow() {
        if checking { return }
        checking = true
        let urlText = policy.checkURL
        DispatchQueue.global(qos: .utility).async {
            let result = Self.fetch(urlText)
            DispatchQueue.main.async {
                self.checking = false
                self.handle(result)
            }
        }
    }

    private func handle(_ result: Result<String, Error>) {
        lastCheckedAt = Date()
        switch result {
        case .success(let ip):
            lastIP = ip
            if ip == policy.targetIP {
                setState(.safe, detail: "exit=\(ip)\ntarget=\(policy.targetIP)\nchecked_at=\(timestamp())")
            } else {
                setState(.check, detail: "exit=\(ip)\ntarget=\(policy.targetIP)\nchecked_at=\(timestamp())")
            }
        case .failure(let error):
            setState(.check, detail: "exit=unknown\ntarget=\(policy.targetIP)\nerror=\(error.localizedDescription)\nchecked_at=\(timestamp())")
        }
    }

    private func setState(_ state: GuardState, detail: String) {
        lastInfo = detail
        badge.setState(state)
        positionPanel()
        panel.orderFrontRegardless()
        writeState(state.text, detail: detail)
    }

    private func writeState(_ state: String, detail: String) {
        let text = [
            "state=\(state)",
            "target=\(policy.targetIP)",
            "exit=\(lastIP.isEmpty ? "unknown" : lastIP)",
            "updated_at=\(timestamp())",
            "detail=\(detail.replacingOccurrences(of: "\n", with: "; "))"
        ].joined(separator: "\n") + "\n"
        try? text.write(toFile: stateFile, atomically: true, encoding: .utf8)
    }

    private static func fetch(_ urlText: String) -> Result<String, Error> {
        guard let url = URL(string: urlText) else {
            return .failure(NSError(domain: "oops", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid check URL"]))
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 12)
        request.setValue("oops/1.0", forHTTPHeaderField: "User-Agent")
        let semaphore = DispatchSemaphore(value: 0)
        var output: Result<String, Error> = .failure(NSError(domain: "oops", code: 2, userInfo: [NSLocalizedDescriptionKey: "no response"]))
        URLSession.shared.dataTask(with: request) { data, _, error in
            defer { semaphore.signal() }
            if let error = error {
                output = .failure(error)
                return
            }
            let text = String(data: data ?? Data(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if isIPv4(text) {
                output = .success(text)
            } else {
                output = .failure(NSError(domain: "oops", code: 3, userInfo: [NSLocalizedDescriptionKey: "unexpected response"]))
            }
        }.resume()
        _ = semaphore.wait(timeout: .now() + 15)
        return output
    }

    private static func isIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".").compactMap { Int($0) }
        return parts.count == 4 && parts.allSatisfy { $0 >= 0 && $0 <= 255 }
    }

    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: lastCheckedAt == .distantPast ? Date() : lastCheckedAt)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
