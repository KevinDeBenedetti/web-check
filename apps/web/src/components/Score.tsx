import { SCORE_BAND_LABELS, scoreBand } from "../lib/labels";

export function ScoreValue({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) return <span className="muted">—</span>;
  return <span className={`score score--${scoreBand(score)}`}>{score}</span>;
}

export function ScoreRing({ score, size = 132 }: { score: number; size?: number }) {
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const band = scoreBand(score);
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={`Score ${score} sur 100, ${SCORE_BAND_LABELS[band].toLowerCase()}`}
      className={`ring ring--${band}`}
    >
      <circle className="ring__track" cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} />
      <circle
        className="ring__value"
        cx={size / 2}
        cy={size / 2}
        r={radius}
        strokeWidth={stroke}
        strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="ring__score">
        {score}
      </text>
      <text x="50%" y={size / 2 + 28} textAnchor="middle" className="ring__max">
        / 100
      </text>
    </svg>
  );
}

interface SparklineProps {
  values: number[];
  label: string;
  width?: number;
  height?: number;
}

/** Score history on a fixed 0–100 scale. */
export function Sparkline({ values, label, width = 120, height = 28 }: SparklineProps) {
  if (values.length < 2) {
    return <span className="muted small">{values.length === 1 ? "1 scan" : "—"}</span>;
  }
  const step = (width - 4) / (values.length - 1);
  const points = values
    .map((value, index) => `${2 + index * step},${2 + (1 - value / 100) * (height - 4)}`)
    .join(" ");
  const last = values[values.length - 1] ?? 0;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <polyline className={`spark spark--${scoreBand(last)}`} points={points} />
    </svg>
  );
}
