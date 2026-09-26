import React from 'react';
import { ShieldCheck, TrendingUp, TrendingDown } from 'lucide-react';

interface SecurityScoreProps {
  score: number;
  previousScore?: number;
  size?: 'sm' | 'md' | 'lg';
}

export const SecurityScore: React.FC<SecurityScoreProps> = ({
  score,
  previousScore = 62,
  size = 'lg',
}) => {
  const delta = score - previousScore;
  const radius = size === 'lg' ? 70 : size === 'md' ? 50 : 35;
  const strokeWidth = size === 'lg' ? 12 : size === 'md' ? 9 : 6;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let color = '#22C55E'; // green
  let glow = 'rgba(34, 197, 94, 0.25)';
  if (score < 50) {
    color = '#EF4444'; // critical red
    glow = 'rgba(239, 68, 68, 0.25)';
  } else if (score < 75) {
    color = '#F59E0B'; // warning amber
    glow = 'rgba(245, 158, 11, 0.25)';
  }

  const svgDimensions = (radius + strokeWidth) * 2;

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative flex items-center justify-center">
        {/* SVG Circular Gauge */}
        <svg
          width={svgDimensions}
          height={svgDimensions}
          className="rotate-[-90deg] transition-all duration-700 ease-out"
        >
          {/* Background circle */}
          <circle
            cx={svgDimensions / 2}
            cy={svgDimensions / 2}
            r={radius}
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active score circle */}
          <circle
            cx={svgDimensions / 2}
            cy={svgDimensions / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 10px ${glow})`,
              transition: 'stroke-dashoffset 1s ease-in-out',
            }}
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span
            className={`font-black tracking-tight text-[#F8FAFC] ${
              size === 'lg' ? 'text-4xl' : size === 'md' ? 'text-2xl' : 'text-xl'
            }`}
          >
            {score}
          </span>
          <span className="text-[10px] uppercase font-bold tracking-wider text-[#94A3B8]">
            / 100
          </span>
        </div>
      </div>

      {/* Delta indicator */}
      {delta !== 0 && (
        <div
          className={`mt-3 flex items-center gap-1 text-xs font-semibold ${
            delta > 0 ? 'text-[#22C55E]' : 'text-[#EF4444]'
          }`}
        >
          {delta > 0 ? (
            <TrendingUp className="h-3.5 w-3.5" />
          ) : (
            <TrendingDown className="h-3.5 w-3.5" />
          )}
          <span>
            {delta > 0 ? `+${delta}` : delta} from previous scan
          </span>
        </div>
      )}

      {/* Explicit attribution label */}
      <div className="mt-2 text-center">
        <p className="text-xs font-semibold tracking-wide text-[#F8FAFC] flex items-center justify-center gap-1.5">
          <ShieldCheck className="h-3.5 w-3.5 text-[#00D4FF]" />
          <span>RBAC Guardian Security Score</span>
        </p>
        <p className="text-[10px] text-[#64748B]">
          Deterministic posture metric (0–100)
        </p>
      </div>
    </div>
  );
};
