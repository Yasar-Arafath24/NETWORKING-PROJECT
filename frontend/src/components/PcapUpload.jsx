
import { useRef, useState } from "react";
import { FileSearch, FileText, Upload, X, CheckCircle2 } from "lucide-react";

const MAX_FILE_SIZE = 20 * 1024 * 1024;

// Served from frontend/public so it is available in dev and in production builds.
const SAMPLE_PCAP_URL = "/samples/netsentry_sample.pcap";

export default function PcapUpload({
  onUpload,
  uploading = false,
}) {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [success, setSuccess] = useState(false);

  function validateFile(selectedFile) {
    setError("");
    setSuccess(false);

    if (!selectedFile) return;

    const validExtension = /\.(pcap|pcapng)$/i.test(selectedFile.name);

    if (!validExtension) {
      setFile(null);
      setError("Choose a .pcap or .pcapng file.");
      return;
    }

    if (selectedFile.size > MAX_FILE_SIZE) {
      setFile(null);
      setError("The file exceeds the 20 MB upload limit.");
      return;
    }

    setFile(selectedFile);
  }

  function handleFileChange(event) {
    validateFile(event.target.files?.[0] ?? null);
  }

  function handleDrop(event) {
    event.preventDefault();
    setDragging(false);
    validateFile(event.dataTransfer.files?.[0] ?? null);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setSuccess(false);

    if (!file) {
      setError("Select a PCAP file before starting analysis.");
      return;
    }

    try {
      await onUpload(file);
      setSuccess(true);
    } catch (uploadError) {
      setError(uploadError.message || "PCAP analysis failed.");
    }
  }

  function removeFile() {
    setFile(null);
    setError("");
    setSuccess(false);

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;

    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  return (
    <section className="pcap-upload-panel">
      <div className="pcap-heading">
        <div>
          <div className="eyebrow">PACKET INSPECTION</div>
          <h2>PCAP Analysis</h2>
          <p>Upload a network capture to inspect its traffic and flows.</p>
        </div>

        <div className="pcap-heading-icon">
          <FileSearch size={22} />
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <input
          ref={inputRef}
          className="pcap-hidden-input"
          type="file"
          accept=".pcap,.pcapng"
          onChange={handleFileChange}
          disabled={uploading}
          aria-label="Choose PCAP file"
        />

        <div
          className={`pcap-dropzone ${dragging ? "is-dragging" : ""}`}
          onDragEnter={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) {
              setDragging(false);
            }
          }}
          onDrop={handleDrop}
        >
          <div className="pcap-drop-icon">
            <Upload size={24} />
          </div>

          <h3>Drop your capture file here</h3>
          <p>Supported formats: PCAP and PCAPNG</p>

          <button
            type="button"
            className="secondary-button"
            onClick={() => inputRef.current?.click()}
            disabled={uploading}
          >
            Browse files
          </button>

          <span className="pcap-size-note">Maximum size: 20 MB</span>
        </div>

        <p className="pcap-sample-note">
          No capture handy?{" "}
          <a href={SAMPLE_PCAP_URL} download="netsentry_sample.pcap">
            Download a sample PCAP
          </a>
        </p>

        {file && (
          <div className="pcap-selected-file">
            <div className="pcap-file-icon">
              <FileText size={21} />
            </div>

            <div className="pcap-file-info">
              <strong title={file.name}>{file.name}</strong>
              <span>{formatSize(file.size)}</span>
            </div>

            {!uploading && (
              <button
                type="button"
                className="pcap-remove-button"
                onClick={removeFile}
                aria-label="Remove selected file"
              >
                <X size={18} />
              </button>
            )}
          </div>
        )}

        {error && (
          <div className="pcap-message pcap-error" role="alert">
            {error}
          </div>
        )}

        {success && (
          <div className="pcap-message pcap-success" role="status">
            <CheckCircle2 size={17} />
            Analysis completed successfully.
          </div>
        )}

        <div className="pcap-submit-row">
          <button
            type="submit"
            className="primary-button"
            disabled={!file || uploading}
          >
            <Upload size={17} />
            {uploading ? "Analyzing capture..." : "Upload and Analyze"}
          </button>
        </div>

        <p className="pcap-security-note">
          File extension checks are not a security validation. The backend
          must validate file contents, file size, and access permissions.
        </p>
      </form>
    </section>
  );
}
