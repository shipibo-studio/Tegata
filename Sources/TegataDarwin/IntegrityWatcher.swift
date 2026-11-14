import Foundation
import TegataCore

/// Wakes the monitor when an agent's configuration folder changes, and every two minutes for what folder events miss
/// (a script edited in place). Same mechanism as `DriftWatcher`: vnode sources on folders, a debounce, a timer.
public final class IntegrityWatcher: @unchecked Sendable {   // all state confined to `queue`
    private let monitor: IntegrityMonitor
    private let queue = DispatchQueue(label: "app.tegata.integrity")
    private var sources: [DispatchSourceFileSystemObject] = []
    private var timer: DispatchSourceTimer?
    private var debounce: DispatchWorkItem?
    private var watched: Set<String> = []

    public init(monitor: IntegrityMonitor) { self.monitor = monitor }

    public func start() {
        queue.async {
            self.arm()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + 120, repeating: 120)
            t.setEventHandler { [weak self] in self?.arm(); self?.run("poll") }   // also picks up folders created since
            t.resume()
            self.timer = t
            self.run("start")
        }
    }

    private func arm() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        for dir in IntegrityMonitor.watchedFolders(home: home) where !watched.contains(dir) {
            let fd = open(dir, O_EVTONLY)
            guard fd >= 0 else { continue }
            let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: [.write, .rename, .delete, .attrib], queue: queue)
            src.setEventHandler { [weak self] in self?.schedule("file event in \(dir)") }
            src.setCancelHandler { close(fd) }
            src.resume()
            sources.append(src)
            watched.insert(dir)
        }
    }

    private func schedule(_ reason: String) {
        debounce?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.run(reason) }
        debounce = w
        queue.asyncAfter(deadline: .now() + 3, execute: w)   // tools write in bursts; let them finish
    }

    private func run(_ reason: String) {
        let m = monitor
        Task { await m.check(reason: reason) }
    }
}
