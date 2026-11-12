// Session latency (Swift Charts): line with a soft fill, dashed rules where the network type
// changed with capsule labels above, grid at round values, times below. Greyed for a past session.

import Charts
import SwiftUI

struct LatencyChart: View {
    var session: Session?
    /// Live session: accent colours, capsules, change times, the current point.
    var live: Bool
    var now: Date = Date()

    private struct P: Identifiable {
        var id: Int
        var t: Date
        var r: Double
        var seg: Int
    }

    private static let hm: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "ru_RU")
        f.dateFormat = "HH:mm"
        return f
    }()

    var body: some View {
        GeometryReader { g in
            let w = g.size.width
            // The line stops short of the right edge: that gutter belongs to the grid values.
            let pw = max(w - 30, 10)
            let model = layout(pw)
            let plotTop: CGFloat = 22, plotH: CGFloat = 108
            let yOf = { (v: Double) -> CGFloat in plotTop + plotH * (1 - CGFloat(min(v, model.top) / model.top)) }
            let xOf = { (d: Date) -> CGFloat in
                let span = model.t1.timeIntervalSince(model.t0)
                return span > 0 ? min(max(pw * CGFloat(d.timeIntervalSince(model.t0) / span), 0), pw) : 0
            }
            ZStack(alignment: .topLeading) {
                // Grid lines and their values.
                ForEach(model.grid, id: \.self) { v in
                    Rectangle().fill(Color.grid).frame(width: w, height: 1).offset(y: yOf(v))
                    Text("\(Int(v))").font(.system(size: 11)).foregroundStyle(Color.ink2)
                        .frame(width: w, alignment: .trailing).offset(y: yOf(v) - 17)
                }
                Rectangle().fill(Color.hair).frame(width: w, height: 1).offset(y: plotTop + plotH)

                if !model.pts.isEmpty {
                    Chart {
                        ForEach(model.pts) { p in
                            if live {
                                AreaMark(x: .value("t", p.t), yStart: .value("0", 0), yEnd: .value("ms", min(p.r, model.top)),
                                         series: .value("s", p.seg))
                                    .foregroundStyle(Color.accent.opacity(0.10))
                                    .interpolationMethod(.linear)
                            }
                            LineMark(x: .value("t", p.t), y: .value("ms", min(p.r, model.top)), series: .value("s", p.seg))
                                .foregroundStyle(live ? Color.accent : Color.greyLine)
                                .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round, lineJoin: .round))
                                .interpolationMethod(.linear)
                        }
                    }
                    .chartXScale(domain: model.t0...model.t1)
                    .chartYScale(domain: 0...model.top)
                    .chartXAxis(.hidden)
                    .chartYAxis(.hidden)
                    .chartLegend(.hidden)
                    .frame(width: pw, height: plotH)
                    .clipped()
                    .offset(y: plotTop)
                }

                // Network changes: dashed rules (from the top of the plot down), capsules above.
                ForEach(Array(model.changes.enumerated()), id: \.offset) { _, c in
                    let cx = xOf(Date(timeIntervalSince1970: Double(c.t) / 1000))
                    Path { p in p.move(to: CGPoint(x: cx, y: plotTop)); p.addLine(to: CGPoint(x: cx, y: plotTop + plotH)) }
                        .stroke(live ? Color.rule : Color.hair, style: StrokeStyle(lineWidth: 1, dash: [2, 3]))
                }
                if live {
                    ForEach(Array(model.chips.enumerated()), id: \.offset) { _, c in
                        Text(c.n)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Color.ink)
                            .padding(.horizontal, 8)
                            .frame(height: 18)
                            .background(Color.chip, in: Capsule())
                            .fixedSize()
                            .offset(x: c.x, y: 2)
                    }
                    if let last = model.pts.last {
                        Circle().fill(Color.card).frame(width: 11, height: 11)
                            .overlay(Circle().fill(Color.accent).frame(width: 8, height: 8))
                            .offset(x: xOf(last.t) - 5.5, y: yOf(last.r) - 5.5)
                    }
                }

                // Times: start, (live) the change times, end.
                ForEach(Array(model.ticks.enumerated()), id: \.offset) { _, tk in
                    Text(Self.hm.string(from: tk.t))
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink2)
                        .monospacedDigit()
                        .fixedSize()
                        .frame(width: 60, alignment: tk.align == 0 ? .leading : tk.align == 2 ? .trailing : .center)
                        .offset(x: tk.align == 0 ? 0 : tk.align == 2 ? w - 60 : xOf(tk.t) - 30, y: 136)
                }
            }
            .frame(width: w, height: 150, alignment: .topLeading)
        }
        .frame(height: 150)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(live ? "Задержка за сеанс" : "Задержка прошлого сеанса")
    }

    private struct Model {
        var pts: [P] = []
        var t0 = Date()
        var t1 = Date()
        var top: Double = 120
        var grid: [Double] = [50, 100]
        var changes: [NetMark] = []
        var chips: [(n: String, x: CGFloat)] = []
        var ticks: [(t: Date, align: Int)] = []
    }

    private func layout(_ w: CGFloat) -> Model {
        var m = Model()
        guard let s = session else { return m }
        m.t0 = Date(timeIntervalSince1970: Double(s.start) / 1000)
        // `now` can be stale for a frame when the app comes back to the foreground: never let the
        // time axis end before the newest sample, or the line runs past the plot.
        let newest = s.pts.last.map { Date(timeIntervalSince1970: Double($0.t) / 1000) } ?? m.t0
        m.t1 = live ? max(now, newest, m.t0.addingTimeInterval(60)) : Date(timeIntervalSince1970: Double(max(s.endOrLast, s.start + 60_000)) / 1000)
        // Split the line where samples are missing (> 10 s apart: disconnected / outage).
        var seg = 0, prev: UInt64 = 0
        for (i, p) in s.pts.enumerated() {
            if prev != 0 && p.t > prev + 10_000 { seg += 1 }
            prev = p.t
            m.pts.append(P(id: i, t: Date(timeIntervalSince1970: Double(p.t) / 1000), r: Double(p.r), seg: seg))
        }
        // Scale: a round step so that the 98th percentile sits under the top grid line.
        let sorted = m.pts.map(\.r).sorted()
        let p98 = sorted.isEmpty ? 50 : sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.98))]
        let steps: [Double] = [50, 100, 200, 500, 1000, 2000]
        let step = steps.first { $0 * 2 >= p98 } ?? 5000
        m.grid = [step, step * 2]
        m.top = step * 2 * 1.2
        // Changes (all segments after the first).
        m.changes = Array(s.nets.dropFirst()).map { NetMark(t: $0.t, n: $0.n) }
        let span = m.t1.timeIntervalSince(m.t0)
        let x = { (t: UInt64) -> CGFloat in span > 0 ? w * CGFloat((Double(t) / 1000 - m.t0.timeIntervalSince1970) / span) : 0 }
        var lastX: CGFloat = -100
        for (i, n) in s.nets.enumerated() {
            let cx = i == 0 ? 0 : min(x(n.t), w - 44)
            if cx - lastX < 46 && i > 0 { continue }
            m.chips.append((n.n, cx))
            lastX = cx
        }
        if live && s.nets.count <= 1 { m.chips = s.nets.first.map { [($0.n, 0)] } ?? [] }
        m.ticks = [(m.t0, 0)]
        if live {
            var lx: CGFloat = 0
            for c in m.changes {
                let cx = x(c.t)
                let same = Self.hm.string(from: Date(timeIntervalSince1970: Double(c.t) / 1000)) == Self.hm.string(from: m.t1)
                if cx - lx >= 44 && w - cx >= 44 && !same { m.ticks.append((Date(timeIntervalSince1970: Double(c.t) / 1000), 1)); lx = cx }
            }
        }
        m.ticks.append((m.t1, 2))
        return m
    }
}
