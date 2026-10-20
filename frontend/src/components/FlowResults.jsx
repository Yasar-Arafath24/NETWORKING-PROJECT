
export default function FlowResults({ flows = [] }) {
  const safeFlows = Array.isArray(flows) ? flows : [];

  if (safeFlows.length === 0) {
    return (
      <section className="rounded-xl border border-slate-200 bg-white p-6">
        <h2 className="text-lg font-semibold text-slate-900">
          Extracted Network Flows
        </h2>
        <p className="mt-3 text-sm text-slate-500">
          No flow records are available for this analysis.
        </p>
      </section>
    );
  }

  return (
    <section className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      <div className="border-b border-slate-200 p-5">
        <h2 className="text-lg font-semibold text-slate-900">
          Extracted Network Flows
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          {safeFlows.length} flow records returned by the backend
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Destination IP</th>
              <th className="px-4 py-3">Packets</th>
              <th className="px-4 py-3">Bytes</th>
              <th className="px-4 py-3">Duration</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-100">
            {safeFlows.map((flow, index) => (
              <tr key={flow.id ?? flow.flow_id ?? index}>
                <td className="px-4 py-3 font-medium text-slate-800">
                  {flow.protocol ?? "—"}
                </td>
                <td className="px-4 py-3 font-mono text-slate-600">
                  {flow.src_ip ?? flow.source_ip ?? "—"}
                </td>
                <td className="px-4 py-3 font-mono text-slate-600">
                  {flow.dst_ip ?? flow.destination_ip ?? "—"}
                </td>
                <td className="px-4 py-3 text-slate-700">
                  {flow.packet_count ?? "—"}
                </td>
                <td className="px-4 py-3 text-slate-700">
                  {flow.total_bytes ?? flow.bytes ?? "—"}
                </td>
                <td className="px-4 py-3 text-slate-700">
                  {flow.duration ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
