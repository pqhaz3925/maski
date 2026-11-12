import NetworkExtension
import Combine
import SwiftUI

@main
struct MaskiApp: App {
    @StateObject private var ctl = Controller.shared
    @Environment(\.scenePhase) private var phase
    @State private var path: [Nav] = []
    @State private var importing = false
    private let tick = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some Scene {
        WindowGroup {
            NavigationStack(path: $path) {
                HomeView(path: $path)
                    .navigationDestination(for: Nav.self) { n in
                        switch n {
                        case .settings: SettingsView(path: $path)
                        case .journal: JournalView()
                        case .profile(let id): ProfileView(id: id)
                        case .bypass:
                            ListEditor(title: "Мимо маски", placeholder: "Адрес или подсеть", items: $ctl.bypass) { CIDR.parse($0)?.text }
                        case .ssids:
                            ListEditor(title: "Снимать в сетях", placeholder: "Имя сети Wi-Fi", items: $ctl.offSSIDs) {
                                let s = $0.trimmingCharacters(in: .whitespaces)
                                return s.isEmpty ? nil : s
                            }
                        }
                    }
            }
            .tint(Color.link)
            .environmentObject(ctl)
            .preferredColorScheme(UserDefaults.standard.string(forKey: "appearance") == "light" ? .light
                                  : UserDefaults.standard.string(forKey: "appearance") == "dark" ? .dark : nil)
            .sheet(isPresented: $importing) { ImportSheet().environmentObject(ctl) }
            .onChange(of: ctl.pendingImport) { _, p in if p != nil { importing = true } }
            .task {
                await ctl.load()
                // Launch arguments: -cmd "down?bytes=...&rate=..." (repeatable).
                let args = ProcessInfo.processInfo.arguments
                for (i, a) in args.enumerated() where a == "-cmd" && i + 1 < args.count {
                    if let u = URL(string: "maski://test/" + args[i + 1]) { Driver.shared.handle(u) }
                }
            }
            .onOpenURL { url in
                if ctl.handleLink(url) { return }
                Driver.shared.handle(url)
            }
            .onChange(of: phase) { _, p in
                appendLine("status.txt", "\(nowMs()) app \(p)")
                if p == .active {
                    Driver.shared.renewBg()
                    Task { await ctl.refresh() }
                }
            }
            .onReceive(tick) { _ in
                guard phase == .active || Driver.shared.isRunning else { return }
                Task {
                    await ctl.refresh()
                    if Driver.shared.isRunning && ctl.status == .connected { await ctl.drain() }
                }
            }
        }
    }
}
