interface DataPoint {
  label: string
  value: number
}

interface TrendChartProps {
  data: DataPoint[]
  height?: number
  color?: string
}

const DEFAULT_COLOR = '#6d63ff'
const PADDING = { top: 4, right: 2, bottom: 20, left: 4 }

export function TrendChart({ data, height = 56, color = DEFAULT_COLOR }: TrendChartProps) {
  if (!data || data.length === 0) {
    return (
      <svg width="100%" height={height} viewBox={`0 0 200 ${height}`} preserveAspectRatio="none">
        <line
          x1="0" y1={height / 2}
          x2="200" y2={height / 2}
          stroke="#252b3d"
          strokeWidth="1"
        />
      </svg>
    )
  }

  const maxVal = Math.max(...data.map(d => d.value), 1)
  const allZero = data.every(d => d.value === 0)

  const viewW = 200
  const viewH = height
  const chartW = viewW - PADDING.left - PADDING.right
  const chartH = viewH - PADDING.top - PADDING.bottom
  const n = data.length
  const barWidth = Math.max(2, (chartW / n) - 2)
  const gap = chartW / n

  const showLabels = n <= 7

  return (
    <svg
      width="100%"
      height={height}
      viewBox={`0 0 ${viewW} ${viewH}`}
      preserveAspectRatio="none"
    >
      {allZero ? (
        <line
          x1={PADDING.left}
          y1={PADDING.top + chartH}
          x2={PADDING.left + chartW}
          y2={PADDING.top + chartH}
          stroke="#252b3d"
          strokeWidth="1"
        />
      ) : (
        data.map((point, i) => {
          const barH = Math.max(2, (point.value / maxVal) * chartH)
          const x = PADDING.left + i * gap + (gap - barWidth) / 2
          const y = PADDING.top + chartH - barH
          const isLast = i === n - 1
          const barColor = isLast ? color : `${color}88`

          return (
            <g key={i}>
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={barH}
                rx="2"
                fill={barColor}
              />
              {showLabels && (
                <text
                  x={x + barWidth / 2}
                  y={viewH - 4}
                  textAnchor="middle"
                  fontSize="8"
                  fill="#404d66"
                  fontFamily="Inter, sans-serif"
                >
                  {point.label.length > 4 ? point.label.slice(0, 4) : point.label}
                </text>
              )}
            </g>
          )
        })
      )}
    </svg>
  )
}
