
import { useState } from "react";
import { Upload, FileText, X } from "lucide-react";

export default function PcapUpload({
  onUpload,
  uploading = false,
}) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [error, setError] = useState("");
  const [analysis, setAnalysis] = useState(null);

  function handleFileChange(event) {
    const file = event.target.files?.[0];

    setError("");
    setAnalysis(null);
    setSelectedFile(null);

    if (!file) return;

    const validExtension = /\.(pcap|pcapng)$/i.test(file.name);

    if (!validExtension) {
      setError("Select a .pcap or .pcapng file.");
      event.target.value = "";
      return;
    }

    if (file.size === 0) {
      setError("The selected file is empty.");
      event.target.value = "";
      return;
    }

    setSelectedFile(file);
  }

  async function handleUpload() {
    if (!selectedFile || uploading) return;

    setError("");

    try {
      const result = await onUpload(selectedFile);
      setAnalysis(result);
      setSelectedFile(null);

      const input = document.getElementById("pcap-file-input");
      if (input) input.value = "";
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Upload failed. Check the backend and try again."
      );
    }
  }

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6">
      <div className="mb-5">
        <h2 className="text-lg font-semibold text-slate-900">
          PCAP Analysis
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Upload a network capture to begin analysis.
        </p>
      </div>

      <label
        htmlFor="pcap-file-input"
        className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 px-5 py-10 text-center transition hover:border-blue-500 hover:bg-blue-50/40"
      >
        <Upload className="mb-3 h-8 w-8 text-blue-600" />

        <span className="font-medium text-slate-800">
          Choose a PCAP file
        </span>

        <span className="mt-1 text-sm text-slate-500">
          .pcap or .pcapng
        </span>

        <input
          id="pcap-file-input"
          type="file"
          accept=".pcap,.pcapng"
          className="sr-only"
          onChange={handleFileChange}
          disabled={uploading}
        />
      </label>

      {selectedFile && (
        <div className="mt-4 flex items-center gap-3 rounded-lg bg-slate-50 p-3">
          <FileText className="h-5 w-5 shrink-0 text-blue-600" />

          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-slate-800">
              {selectedFile.name}
            </p>
            <p className="text-xs text-slate-500">
              {(selectedFile.size / 1024).toFixed(1)} KB
            </p>
          </div>

          <button
            type="button"
            aria-label="Remove selected file"
            disabled={uploading}
            onClick={() => {
              setSelectedFile(null);
              const input = document.getElementById("pcap-file-input");
              if (input) input.value = "";
            }}
            className="rounded-md p-2 text-slate-500 hover:bg-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {error && (
        <p role="alert" className="mt-3 text-sm text-red-600">
          {String(error)}
        </p>
      )}

      {analysis && (
        <p role="status" className="mt-3 text-sm text-green-700">
          Analysis complete: {analysis.total_packets} packets across{" "}
          {analysis.total_flows} flows.
        </p>
      )}

      <button
        type="button"
        onClick={handleUpload}
        disabled={!selectedFile || uploading}
        className="mt-5 w-full rounded-lg bg-blue-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {uploading ? "Uploading..." : "Upload and Analyze"}
      </button>

      <p className="mt-3 text-xs text-slate-500">
        File extension checks are not a security validation.
        The backend must validate file contents, size, and access permissions.
      </p>
    </section>
  );
}
