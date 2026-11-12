// «Добавить по ссылке или QR»: camera scanner with a paste button; a link opened from outside
// (maski://add?...) lands on the same confirmation.

import AVFoundation
import SwiftUI
import UIKit

struct ImportSheet: View {
    @EnvironmentObject var ctl: Controller
    @Environment(\.dismiss) private var dismiss
    @State private var found: Profile?
    @State private var bad = false
    /// Set when the user answered: keeps the scanner from coming back while the sheet goes away.
    @State private var closing = false

    var body: some View {
        if closing {
            Color.page.ignoresSafeArea()
        } else if let p = found ?? ctl.pendingImport {
            ImportConfirm(profile: p) { ok in
                closing = true
                if ok { ctl.add(p) }
                ctl.pendingImport = nil
                dismiss()
            }
        } else {
            ZStack {
                QRScannerView { s in take(s) }.ignoresSafeArea()
                VStack {
                    HStack {
                        Button("Отмена") { dismiss() }
                            .font(.system(size: 17))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 16).frame(height: 44)
                            .glassEffect(.regular.interactive(), in: .capsule)
                        Spacer()
                    }
                    Spacer()
                    RoundedRectangle(cornerRadius: 26, style: .continuous)
                        .stroke(bad ? Color.red : Color.white.opacity(0.8), lineWidth: 3)
                        .frame(width: 250, height: 250)
                    Spacer()
                    PasteButton(payloadType: String.self) { strings in
                        if let s = strings.first { Task { @MainActor in take(s) } }
                    }
                    .buttonBorderShape(.capsule)
                    .tint(.white)
                    .labelStyle(.titleAndIcon)
                    .padding(.bottom, 24)
                }
                .padding(16)
            }
            .background(Color.black)
        }
    }

    private func take(_ s: String) {
        if let p = Profile.from(link: s) {
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            found = p
        } else {
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            bad = true
        }
    }
}

struct ImportConfirm: View {
    var profile: Profile
    var done: (Bool) -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            MarkView(on: true).padding(.top, 28)
            Text(profile.name)
                .font(.system(size: 34, weight: .bold)).tracking(-0.68)
                .foregroundStyle(Color.ink)
                .padding(.top, 14)
            Card {
                Row(title: "Сервер", value: profile.server, chevron: false)
                Hairline()
                Row(title: "Пользователь", value: profile.user, chevron: false)
                if !profile.sni.isEmpty {
                    Hairline()
                    Row(title: "SNI", value: profile.sni, chevron: false)
                }
            }
            .padding(.top, 20)
            Spacer()
            Button { done(true) } label: {
                Text("Добавить").font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(Color.dyn(0xFFFFFF, 0x1C1C1E))
                    .frame(maxWidth: .infinity, minHeight: 56)
                    .background(Color.ink, in: Capsule())
            }
            .buttonStyle(.plain)
            Button { done(false) } label: {
                Text("Отмена").font(.system(size: 17)).foregroundStyle(Color.link)
                    .frame(maxWidth: .infinity, minHeight: 52)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .background(Color.page.ignoresSafeArea())
    }
}

/// AVFoundation QR scanner (after personalvpn's QRScanner).
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerVC {
        let vc = ScannerVC()
        vc.onScan = onScan
        return vc
    }
    func updateUIViewController(_ vc: ScannerVC, context: Context) { vc.onScan = onScan }

    final class ScannerVC: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onScan: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var preview: AVCaptureVideoPreviewLayer?
        private var lastValue = ""

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            layer.frame = view.layer.bounds
            view.layer.addSublayer(layer)
            preview = layer
            DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.layer.bounds
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            if session.isRunning { DispatchQueue.global(qos: .userInitiated).async { [session] in session.stopRunning() } }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objs: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard let v = (objs.first as? AVMetadataMachineReadableCodeObject)?.stringValue, v != lastValue else { return }
            lastValue = v
            onScan?(v)
        }
    }
}
