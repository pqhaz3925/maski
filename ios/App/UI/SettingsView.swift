// Settings (G-settings): Профиль, Маршруты, Автоматика, Отладка; and the screens behind them
// (profile, «Мимо маски» list, «Снимать в сетях» list).

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var ctl: Controller
    @Binding var path: [Nav]
    @State private var importing = false

    var body: some View {
        Screen(back: "maski", title: "Настройки") {
            SectionTitle(text: "Профиль")
            Card {
                ForEach(Array(ctl.profiles.enumerated()), id: \.element.id) { i, p in
                    if i > 0 { Hairline() }
                    Button { path.append(.profile(p.id)) } label: {
                        HStack(spacing: 8) {
                            if ctl.profiles.count > 1 {
                                Image(systemName: "checkmark").font(.system(size: 15, weight: .semibold))
                                    .foregroundStyle(Color.accent).opacity(p.id == ctl.current?.id ? 1 : 0)
                            }
                            Row(title: p.name, value: "MASQUE")
                        }
                    }
                    .buttonStyle(.plain)
                }
                if !ctl.profiles.isEmpty { Hairline() }
                Button { importing = true } label: {
                    Text("Добавить по ссылке или QR")
                        .font(.system(size: 17))
                        .foregroundStyle(Color.link)
                        .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }

            SectionTitle(text: "Маршруты")
            Card {
                if ctl.showRU {
                    ToggleRow(title: "Российские сайты напрямую", isOn: $ctl.routeRU)
                    Hairline()
                }
                ToggleRow(title: "Локальная сеть напрямую", isOn: $ctl.routeLocal)
                Hairline()
                Button { path.append(.bypass) } label: {
                    Row(title: "Мимо маски", value: ctl.bypass.isEmpty ? "Нет" : "\(ctl.bypass.count) " + RU.plural(ctl.bypass.count, "адрес", "адреса", "адресов"))
                }
                .buttonStyle(.plain)
            }

            SectionTitle(text: "Автоматика")
            Card {
                ToggleRow(title: "Держать надетой", isOn: $ctl.keepOn)
                Hairline()
                ToggleRow(title: "Сотовая при сбое Wi-Fi", isOn: $ctl.cellFallback)
                Hairline()
                Button { path.append(.ssids) } label: {
                    Row(title: "Снимать в сетях", value: ctl.offSSIDs.isEmpty ? "Нет" : "\(ctl.offSSIDs.count)")
                }
                .buttonStyle(.plain)
            }

            SectionTitle(text: "Отладка")
            Card {
                Button { path.append(.journal) } label: { Row(title: "Журнал и логи") }
                    .buttonStyle(.plain)
            }
        }
        .sheet(isPresented: $importing) { ImportSheet() }
    }
}

struct ProfileView: View {
    @EnvironmentObject var ctl: Controller
    @Environment(\.dismiss) private var dismiss
    var id: String
    @State private var confirmDelete = false

    var body: some View {
        let p = ctl.profiles.first { $0.id == id }
        Screen(back: "Настройки", title: p?.name ?? "") {
            if let p {
                Card {
                    Row(title: "Сервер", value: p.server, chevron: false)
                    Hairline()
                    Row(title: "Пользователь", value: p.user, chevron: false)
                    Hairline()
                    Row(title: "SNI", value: p.sni.isEmpty ? "—" : p.sni, chevron: false)
                    Hairline()
                    Row(title: "Протокол", value: "MASQUE", chevron: false)
                }
                .padding(.top, 20)
                Card {
                    if p.id != ctl.current?.id {
                        Button { ctl.select(p.id) } label: { linkRow("Использовать") }.buttonStyle(.plain)
                        Hairline()
                    }
                    ShareLink(item: p.link) { linkRow("Поделиться ссылкой") }.buttonStyle(.plain)
                    if ctl.profiles.count > 1 {
                        Hairline()
                        Button { confirmDelete = true } label: { linkRow("Удалить", color: .red) }.buttonStyle(.plain)
                    }
                }
                .padding(.top, 20)
            }
        }
        .confirmationDialog("Удалить «\(p?.name ?? "")»?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Удалить", role: .destructive) { ctl.remove(id); dismiss() }
        }
    }

    private func linkRow(_ t: String, color: Color = .link) -> some View {
        Text(t).font(.system(size: 17)).foregroundStyle(color)
            .frame(maxWidth: .infinity, minHeight: 52, alignment: .leading)
            .contentShape(Rectangle())
    }
}

/// An editable list of strings (addresses / CIDRs, or Wi-Fi names).
struct ListEditor: View {
    var title: String
    var placeholder: String
    @Binding var items: [String]
    /// Normalises an entry; nil = invalid.
    var validate: (String) -> String?
    @State private var text = ""
    @State private var bad = false

    var body: some View {
        Screen(back: "Настройки", title: title) {
            Card {
                ForEach(Array(items.enumerated()), id: \.offset) { i, item in
                    if i > 0 { Hairline() }
                    HStack(spacing: 12) {
                        Text(item).font(.system(size: 17)).foregroundStyle(Color.ink).lineLimit(1)
                        Spacer(minLength: 0)
                        Button { items.remove(at: i) } label: {
                            Image(systemName: "minus.circle.fill").font(.system(size: 20)).foregroundStyle(Color.ink2)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Убрать \(item)")
                    }
                    .frame(height: 52)
                }
                if !items.isEmpty { Hairline() }
                HStack(spacing: 12) {
                    TextField(placeholder, text: $text)
                        .font(.system(size: 17))
                        .foregroundStyle(bad ? Color.red : Color.ink)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.done)
                        .onSubmit(add)
                        .onChange(of: text) { bad = false }
                    Button("Добавить", action: add)
                        .font(.system(size: 17))
                        .foregroundStyle(Color.link)
                        .disabled(text.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .frame(height: 52)
            }
            .padding(.top, 20)
        }
    }

    private func add() {
        guard let v = validate(text) else { bad = true; return }
        if !items.contains(v) { items.append(v) }
        text = ""
    }
}
