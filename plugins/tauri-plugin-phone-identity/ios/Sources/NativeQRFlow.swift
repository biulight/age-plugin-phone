import AVFoundation
import CoreImage
import PhoneIdentityCore
import UIKit

enum NativeQRFlowError: Error { case permissionDenied, cameraUnavailable, cancelled, lifecycle, malformed, timeout }

final class NativeQRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let captureSession = AVCaptureSession()
    private let reassembler = QRReassembler()
    private let completion: (Result<(Data, Int), Error>) -> Void
    private let progressLabel = UILabel()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var accepted = 0
    private var finished = false

    init(completion: @escaping (Result<(Data, Int), Error>) -> Void) {
        self.completion = completion
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .fullScreen
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureOverlay()
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: configureCamera()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async { granted ? self?.configureCamera() : self?.finish(.failure(NativeQRFlowError.permissionDenied)) }
            }
        default: finish(.failure(NativeQRFlowError.permissionDenied))
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews(); previewLayer?.frame = view.bounds
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if !finished { finish(.failure(NativeQRFlowError.lifecycle), dismiss: false) }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !finished else { return }
        let now = Int64(ProcessInfo.processInfo.systemUptime * 1_000)
        for object in metadataObjects {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                  code.type == .qr, let value = code.stringValue, QRFraming.isCandidate(value) else { continue }
            do {
                let status = try reassembler.push(value, nowMilliseconds: now)
                accepted += 1
                switch status {
                case .inProgress(let received, let total): progressLabel.text = "Authenticated message frames: \(received)/\(total)"
                case .complete(let message): finish(.success((message, accepted)))
                }
            } catch QRFramingError.differentTransfer { continue }
            catch { finish(.failure(error)) }
            return
        }
    }

    @objc private func cancel() { finish(.failure(NativeQRFlowError.cancelled)) }

    private func configureCamera() {
        guard !finished, let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), captureSession.canAddInput(input) else {
            finish(.failure(NativeQRFlowError.cameraUnavailable)); return
        }
        let output = AVCaptureMetadataOutput()
        captureSession.addInput(input)
        guard captureSession.canAddOutput(output) else { finish(.failure(NativeQRFlowError.cameraUnavailable)); return }
        captureSession.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: captureSession)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0); previewLayer = preview
        DispatchQueue.global(qos: .userInitiated).async { [captureSession] in captureSession.startRunning() }
    }

    private func configureOverlay() {
        progressLabel.text = "Point the camera at an age-plugin-phone QR"
        progressLabel.textColor = .white; progressLabel.numberOfLines = 2; progressLabel.textAlignment = .center
        progressLabel.backgroundColor = UIColor.black.withAlphaComponent(0.65)
        progressLabel.translatesAutoresizingMaskIntoConstraints = false
        let cancelButton = UIButton(type: .system)
        cancelButton.setTitle("Cancel", for: .normal); cancelButton.tintColor = .white
        cancelButton.backgroundColor = UIColor.black.withAlphaComponent(0.65)
        cancelButton.addTarget(self, action: #selector(cancel), for: .touchUpInside)
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(progressLabel); view.addSubview(cancelButton)
        NSLayoutConstraint.activate([
            progressLabel.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 20),
            progressLabel.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -20),
            progressLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            progressLabel.heightAnchor.constraint(greaterThanOrEqualToConstant: 56),
            cancelButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            cancelButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            cancelButton.widthAnchor.constraint(equalToConstant: 140), cancelButton.heightAnchor.constraint(equalToConstant: 50)
        ])
    }

    private func finish(_ result: Result<(Data, Int), Error>, dismiss: Bool = true) {
        guard !finished else { return }; finished = true; reassembler.reset()
        if captureSession.isRunning { DispatchQueue.global(qos: .userInitiated).async { [captureSession] in captureSession.stopRunning() } }
        let callback = { self.completion(result) }
        if dismiss, presentingViewController != nil { self.dismiss(animated: true, completion: callback) } else { callback() }
    }
}

final class NativeQRResponseViewController: UIViewController {
    private let frames: [String]
    private let titleText: String
    private let fingerprint: String
    private let confirmLabel: String?
    private let completion: (Bool) -> Void
    private let imageView = UIImageView()
    private var timer: Timer?
    private var index = 0
    private var finished = false

    init(frames: [String], title: String, fingerprint: String, confirmLabel: String?, completion: @escaping (Bool) -> Void) {
        self.frames = frames; titleText = title; self.fingerprint = fingerprint
        self.confirmLabel = confirmLabel; self.completion = completion
        super.init(nibName: nil, bundle: nil); modalPresentationStyle = .fullScreen
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .systemBackground
        let titleLabel = UILabel(); titleLabel.text = titleText; titleLabel.font = .preferredFont(forTextStyle: .title2); titleLabel.textAlignment = .center
        let fingerprintLabel = UILabel(); fingerprintLabel.text = fingerprint.groupedFingerprint; fingerprintLabel.font = .monospacedSystemFont(ofSize: 13, weight: .regular); fingerprintLabel.numberOfLines = 2; fingerprintLabel.textAlignment = .center
        imageView.contentMode = .scaleAspectFit
        let cancel = UIButton(type: .system); cancel.setTitle(confirmLabel == nil ? "Done" : "Cancel", for: .normal)
        cancel.addTarget(self, action: #selector(cancelOrDone), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [titleLabel, imageView, fingerprintLabel, cancel])
        stack.axis = .vertical; stack.spacing = 20; stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        if let confirmLabel {
            let confirm = UIButton(type: .system); confirm.setTitle(confirmLabel, for: .normal)
            confirm.backgroundColor = .systemBlue; confirm.tintColor = .white; confirm.layer.cornerRadius = 8
            confirm.addTarget(self, action: #selector(confirmResponse), for: .touchUpInside)
            stack.addArrangedSubview(confirm)
        }
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            imageView.heightAnchor.constraint(equalTo: imageView.widthAnchor)
        ])
        showFrame(); timer = Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { [weak self] _ in self?.advance() }
    }

    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); if !finished { finish(false, dismiss: false) } }

    private func advance() { guard frames.count > 1 else { return }; index = (index + 1) % frames.count; showFrame() }
    @objc private func cancelOrDone() { finish(confirmLabel == nil) }
    @objc private func confirmResponse() { finish(true) }
    private func showFrame() {
        guard !frames.isEmpty, let filter = CIFilter(name: "CIQRCodeGenerator") else { return }
        filter.setValue(Data(frames[index].utf8), forKey: "inputMessage"); filter.setValue("L", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        if let cg = CIContext().createCGImage(scaled, from: scaled.extent) { imageView.image = UIImage(cgImage: cg) }
    }

    private func finish(_ accepted: Bool?, dismiss: Bool = true) {
        guard !finished else { return }; finished = true; timer?.invalidate(); timer = nil
        let callback = { self.completion(accepted ?? false) }
        if dismiss, presentingViewController != nil { self.dismiss(animated: true, completion: callback) } else { callback() }
    }
}

private extension String {
    var groupedFingerprint: String {
        let clean = replacingOccurrences(of: " ", with: "")
        return stride(from: 0, to: clean.count, by: 16).map { offset in
            let start = clean.index(clean.startIndex, offsetBy: offset), end = clean.index(start, offsetBy: min(16, clean.count - offset))
            return String(clean[start..<end])
        }.joined(separator: " ")
    }
}
