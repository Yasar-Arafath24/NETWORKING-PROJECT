
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

export default function TrafficChart({ data = [] }) {
  return (
    <section className="panel traffic-panel">
      <div className="panel-heading">
        <div>
          <h2>Network Traffic</h2>
          <p>Packet activity over time</p>
        </div>
        <span className="panel-label">Traffic overview</span>
      </div>

      <div className="traffic-chart">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={data}
              margin={{ top: 10, right: 12, left: -16, bottom: 0 }}
            >
              <defs>
                <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2563EB" stopOpacity={0.2} />
                  <stop offset="100%" stopColor="#2563EB" stopOpacity={0} />
                </linearGradient>
              </defs>

              <CartesianGrid stroke="#E2E8F0" strokeDasharray="4 4" />
              <XAxis
                dataKey="time"
                tick={{ fill: "#64748B", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#64748B", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip />
              <Area
                type="monotone"
                dataKey="packets"
                name="Packets"
                stroke="#2563EB"
                strokeWidth={2}
                fill="url(#trafficFill)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="chart-empty">
            <p>No traffic data available yet.</p>
            <span>Upload a PCAP file to begin analysis.</span>
          </div>
        )}
      </div>
    </section>
  );
}
