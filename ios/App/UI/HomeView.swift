// Home (G-on / G-off): header with the mark and the round glass settings button, the big state
// title, the latency card of the current (or previous) session, Профиль / Маршруты, and the
// floating slide button.

import Combine
import SwiftUI

enum Nav: Hashable {
    case settings, journal, bypass, ssids
    case profile(String)
}

struct HomeView: View {
    @EnvironmentObject var ctl: Controller
    @Binding var path: [Nav]
    @State private var now = Date()
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var phase: SlideButton.Phase {
        if let i = ctl.intent {
            if i { return ctl.status == .connected || ctl.status == .reasserting ? .on : .turningOn }
            return ctl.status == .disconnected || ctl.status == .invalid ? .off : .turningOff
        }
        switch ctl.status {
        case .connected, .reasserting: return .on
        case .connecting: return .turningOn
        case .disconnecting: return .turningOff
        default: return .off
        }
    }

    private var title: String {
        switch phase {
        case .on: return "Надета"
        case .off: return "Снята"
        case .turningOn: return "Надеваю"
        case .turningOff: return "Снимаю"
        }
    }

    private var profileName: String { ctl.current?.name ?? "—" }

    private var subtitle: String {
        switch phase {
        case .on:
            let start = ctl.connectedDate ?? ctl.live.map { Date(timeIntervalSince1970: Double($0.start) / 1000) } ?? now
            let d = RU.duration(UInt64(max(0, now.timeIntervalSince(start)) * 1000))
            return (ctl.status == .reasserting ? "переподключение · " : "\(d) · ") + profileName
        default:
            return ctl.errorText.map { "\($0) · \(profileName)" } ?? profileName
        }
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    header
                    Text(title)
                        .font(.system(size: 60, weight: .heavy))
                        .tracking(-2.1)
                        .foregroundStyle(phase == .on ? Color.ink : Color.ink2)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .padding(.top, 14)
                        .padding(.horizontal, 4)
                        .contentTransition(.opacity)
                        .accessibilityIdentifier("state")
                    Text(subtitle)
                        .font(.system(size: 17))
                        .foregroundStyle(Color.ink2)
                        .lineLimit(1)
                        .padding(.top, 6)
                        .padding(.horizontal, 4)
                        .accessibilityIdentifier("subtitle")
                    latencyCard.padding(.top, 20)
                    Card {
                        Button { path.append(.settings) } label: { Row(title: "Профиль", value: profileName) }
                            .buttonStyle(.plain)
                        Hairline()
                        Button { path.append(.settings) } label: { Row(title: "Маршруты", value: routesValue) }
                            .buttonStyle(.plain)
                    }
                    .padding(.top, 20)
                    Color.clear.frame(height: 130)
                }
                .padding(.horizontal, 16)
                .padding(.top, 2)
            }
            .scrollIndicators(.hidden)
            .scrollBounceBehavior(.basedOnSize)

            SlideButton(phase: phase) { on in
                Task { if on { await ctl.turnOn() } else { await ctl.turnOff() } }
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 30)
        }
        .ignoresSafeArea(.container, edges: .bottom)
        .background(Color.page.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
        .onReceive(clock) { t in now = t }
    }

    private var routesValue: String {
        if ctl.routeRU && ctl.showRU { return "РФ напрямую" }
        switch (ctl.routeLocal, ctl.bypass.isEmpty) {
        case (false, true): return "Всё в маске"
        case (true, true): return "Локалка напрямую"
        case (false, false): return "\(ctl.bypass.count) мимо"
        case (true, false): return "Локалка, \(ctl.bypass.count) мимо"
        }
    }

    private var header: some View {
        HStack {
            HStack(spacing: 10) {
                MarkView(on: phase == .on || phase == .turningOn)
                    .opacity(phase == .turningOn || phase == .turningOff ? 0.5 : 1)
                    .animation(phase == .turningOn ? .easeInOut(duration: 0.6).repeatForever() : .default, value: phase)
                Text("maski").font(.system(size: 17, weight: .semibold)).foregroundStyle(Color.ink)
            }
            Spacer()
            Button { path.append(.settings) } label: {
                SlidersIcon()
                    .foregroundStyle(Color.ink)
                    .frame(width: 44, height: 44)
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .glassEffect(.regular.interactive(), in: .circle)
            .accessibilityLabel("Настройки")
        }
        .padding(.horizontal, 4)
    }

    @ViewBuilder private var latencyCard: some View {
        let on = phase == .on || phase == .turningOn
        let s = on ? (ctl.live ?? ctl.lastSession.flatMap { $0.end == nil ? $0 : nil }) : ctl.lastSession
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                Text(on ? "Задержка" : "Прошлый сеанс")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.ink2)
                Text(on ? (ctl.rttMs.map { "\(Int($0.rounded())) мс" } ?? "—") : (s.map { RU.duration($0.durationMs) } ?? "—"))
                    .font(.system(size: 28, weight: .semibold))
                    .tracking(-0.28)
                    .monospacedDigit()
                    .foregroundStyle(on ? Color.ink : Color.ink2)
                    .accessibilityIdentifier("latency")
            }
            LatencyChart(session: s, live: on, now: now)
                .padding(.top, 8)
            Hairline().padding(.top, 10)
            HStack(spacing: 12) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(s.map { RU.bytes($0.bytes) } ?? "0 МБ")
                        .font(.system(size: 22, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(on ? Color.ink : Color.ink2)
                    Text("за сеанс").font(.system(size: 13)).foregroundStyle(Color.ink2)
                }
                Spacer(minLength: 0)
                Text(counts(s))
                    .font(.system(size: 13))
                    .foregroundStyle(Color.ink2)
                    .lineLimit(1)
            }
            .frame(height: 52)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("counters")
        }
        .padding(.horizontal, 16)
        .padding(.top, 16)
        .background(Color.card, in: RoundedRectangle(cornerRadius: 26, style: .continuous))
    }

    private func counts(_ s: Session?) -> String {
        let c = s?.changes ?? 0, d = s?.drops ?? 0
        return "\(c) " + RU.plural(c, "смена", "смены", "смен") + " сети · \(d) " + RU.plural(d, "обрыв", "обрыва", "обрывов")
    }
}
