import Cocoa
import Darwin
import Foundation
import WebKit

private enum PixelSeverity: Int32 {
    case ok = 0
    case warning = 1

    var label: String {
        switch self {
        case .ok: return "ok"
        case .warning: return "warning"
        }
    }
}

private final class PixelScanHelper: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    private let targetIP = PixelScanHelper.env("OOPS_TARGET_IP", fallback: "203.0.113.10")
    private let timeZone = PixelScanHelper.env("OOPS_TIME_ZONE", fallback: TimeZone.current.identifier)
    private let scanURL = "https://pixelscan.net/fingerprint-check"
    private var webView: WKWebView?
    private var finished = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.prohibited)
        start()
    }

    private static func env(_ key: String, fallback: String) -> String {
        let value = ProcessInfo.processInfo.environment[key] ?? ""
        return value.isEmpty ? fallback : value
    }

    private func start() {
        guard let url = URL(string: scanURL) else {
            finish(.warning, "invalid URL \(scanURL)")
            return
        }

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 1200, height: 900),
                                configuration: configuration)
        webView.navigationDelegate = self
        self.webView = webView

        let window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: 1200, height: 900),
                              styleMask: [.borderless],
                              backing: .buffered,
                              defer: false)
        window.contentView = webView
        window.isOpaque = false
        window.alphaValue = 0.01
        window.orderFrontRegardless()

        let request = URLRequest(url: url,
                                 cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                                 timeoutInterval: 30)
        webView.load(request)

        DispatchQueue.main.asyncAfter(deadline: .now() + 40) { [weak self] in
            self?.finish(.warning, "scan timed out after 40s")
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self, weak webView] in
            guard let self = self, let webView = webView else { return }
            self.evaluate(webView)
        }
    }

    func webView(_ webView: WKWebView,
                 didFail navigation: WKNavigation!,
                 withError error: Error) {
        finish(.warning, "navigation failed: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView,
                 didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        finish(.warning, "navigation failed: \(error.localizedDescription)")
    }

    private func evaluate(_ webView: WKWebView) {
        let script = """
        (() => JSON.stringify({
          href: location.href,
          title: document.title || "",
          text: document.body ? document.body.innerText : "",
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
          language: navigator.language || "",
          userAgent: navigator.userAgent || "",
        }))()
        """
        webView.evaluateJavaScript(script) { [weak self] result, error in
            guard let self = self else { return }
            if let error = error {
                self.finish(.warning, "javascript failed: \(error.localizedDescription)")
                return
            }
            guard let text = result as? String,
                  let data = text.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data),
                  let payload = object as? [String: Any] else {
                self.finish(.warning, "unable to parse browser payload")
                return
            }
            let analysis = self.analyze(payload)
            self.finish(analysis.severity, analysis.detail)
        }
    }

    private func analyze(_ payload: [String: Any]) -> (severity: PixelSeverity, detail: String) {
        let href = payload["href"] as? String ?? ""
        let title = payload["title"] as? String ?? ""
        let browserTimeZone = payload["timezone"] as? String ?? ""
        let language = payload["language"] as? String ?? ""
        let userAgent = payload["userAgent"] as? String ?? ""
        let rawText = payload["text"] as? String ?? ""
        let text = primaryPixelScanText(rawText)
        let lower = text.lowercased()
        let pageIPs = Array(Set(extractIPv4s(from: text))).sorted()
        var notes: [String] = []
        var severity = PixelSeverity.ok

        if href.isEmpty || title.isEmpty {
            severity = .warning
            notes.append("page did not expose normal title/href")
        }

        if browserTimeZone == timeZone {
            notes.append("tz=\(browserTimeZone)")
        } else {
            severity = .warning
            notes.append("expected tz \(timeZone), got \(browserTimeZone)")
        }

        if text.contains(targetIP) {
            notes.append("page_ip=\(targetIP)")
        } else if pageIPs.isEmpty {
            notes.append("page_ip=not visible")
        } else if pageIPs.contains(targetIP) {
            notes.append("page_ip=\(targetIP)")
        } else {
            severity = .warning
            notes.append("page_ips=\(pageIPs.joined(separator: ","))")
        }

        let warningPhrases = [
            "ip mismatch",
            "location mismatch",
            "timezone mismatch",
            "time zone mismatch",
            "dns leak detected",
            "webrtc leak detected",
            "leak detected",
            "mismatch detected",
            "inconsistency detected",
            "fingerprint inconsistency",
            "browser fingerprint inconsistency",
            "fingerprint mismatch",
            "proxy detected",
            "vpn detected"
        ]
        let hits = warningPhrases.filter { lower.contains($0) }
        if !hits.isEmpty {
            severity = .warning
            notes.append("signals=\(hits.joined(separator: ","))")
        }

        notes.append("lang=\(language)")
        notes.append("ua=\(short(userAgent))")
        return (severity, notes.joined(separator: "; "))
    }

    private func primaryPixelScanText(_ text: String) -> String {
        if let range = text.range(of: "Frequently Asked Questions", options: .caseInsensitive) {
            return String(text[..<range.lowerBound])
        }
        return text
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

    private func short(_ text: String) -> String {
        let compact = text.replacingOccurrences(of: "\n", with: " ")
        if compact.count <= 180 { return compact }
        return String(compact.prefix(180)) + "..."
    }

    private func finish(_ severity: PixelSeverity, _ detail: String) {
        if finished { return }
        finished = true
        let compact = detail
            .replacingOccurrences(of: "\t", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        print("OOPS_PIXELSCAN_RESULT\t\(severity.label)\t\(compact)")
        fflush(stdout)
        exit(severity.rawValue)
    }
}

private let app = NSApplication.shared
private let delegate = PixelScanHelper()
app.delegate = delegate
app.run()
