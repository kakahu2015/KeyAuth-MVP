import SwiftUI
import VisionKit

struct QRScannerView: UIViewControllerRepresentable {
    @Environment(\.isSceneCaptured) private var isSceneCaptured

    let onCode: (String) -> Void
    let onError: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        context.coordinator.updateCaptureState(
            isSceneCaptured,
            scanner: scanner
        )

        DispatchQueue.main.async {
            context.coordinator.startScanningIfSafe(scanner)
        }

        return scanner
    }

    func updateUIViewController(
        _ uiViewController: DataScannerViewController,
        context: Context
    ) {
        context.coordinator.updateCaptureState(
            isSceneCaptured,
            scanner: uiViewController
        )
    }

    static func dismantleUIViewController(
        _ uiViewController: DataScannerViewController,
        coordinator: Coordinator
    ) {
        uiViewController.stopScanning()
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let parent: QRScannerView
        private var didReportCode = false
        private var hasBeenCaptured = false

        init(parent: QRScannerView) {
            self.parent = parent
        }

        func updateCaptureState(
            _ isCaptured: Bool,
            scanner: DataScannerViewController
        ) {
            if isCaptured {
                hasBeenCaptured = true
            }
            if hasBeenCaptured {
                scanner.stopScanning()
            }
        }

        func startScanningIfSafe(_ scanner: DataScannerViewController) {
            guard !hasBeenCaptured else {
                return
            }
            do {
                try scanner.startScanning()
            } catch {
                reportError(error.localizedDescription)
            }
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            for item in addedItems {
                guard case let .barcode(barcode) = item,
                      let payload = barcode.payloadStringValue else {
                    continue
                }
                reportCode(payload)
                return
            }
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didTapOn item: RecognizedItem
        ) {
            guard case let .barcode(barcode) = item,
                  let payload = barcode.payloadStringValue else {
                return
            }
            reportCode(payload)
        }

        func reportError(_ message: String) {
            guard !didReportCode else {
                return
            }
            parent.onError(message)
        }

        private func reportCode(_ code: String) {
            guard !didReportCode else {
                return
            }
            didReportCode = true
            parent.onCode(code)
        }
    }
}
