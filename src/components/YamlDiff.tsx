import React, { useState } from 'react';
import { Copy, Check, AlertOctagon, CheckCircle2 } from 'lucide-react';

interface YamlDiffProps {
  currentYaml: string;
  suggestedYaml: string;
}

export const YamlDiff: React.FC<YamlDiffProps> = ({ currentYaml, suggestedYaml }) => {
  const [copiedCurrent, setCopiedCurrent] = useState(false);
  const [copiedSuggested, setCopiedSuggested] = useState(false);

  const handleCopy = (text: string, type: 'current' | 'suggested') => {
    navigator.clipboard.writeText(text);
    if (type === 'current') {
      setCopiedCurrent(true);
      setTimeout(() => setCopiedCurrent(false), 2000);
    } else {
      setCopiedSuggested(true);
      setTimeout(() => setCopiedSuggested(false), 2000);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* Current Configuration (Vulnerable) */}
      <div className="flex flex-col rounded-lg border border-[#EF4444]/40 bg-[#070B14] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#EF4444]/30 bg-[#EF4444]/10 px-4 py-2 text-xs font-semibold text-[#EF4444]">
          <div className="flex items-center gap-1.5">
            <AlertOctagon className="h-4 w-4" />
            <span>CURRENT CONFIGURATION (Vulnerable)</span>
          </div>
          <button
            onClick={() => handleCopy(currentYaml, 'current')}
            className="flex items-center gap-1 rounded bg-[#111827] px-2 py-0.5 text-[10px] text-[#94A3B8] hover:text-[#F8FAFC]"
          >
            {copiedCurrent ? <Check className="h-3 w-3 text-[#22C55E]" /> : <Copy className="h-3 w-3" />}
            {copiedCurrent ? 'Copied' : 'Copy'}
          </button>
        </div>
        <pre className="flex-1 p-4 font-mono text-xs text-[#F8FAFC] overflow-x-auto leading-relaxed bg-[#0D1320]/60">
          <code>{currentYaml}</code>
        </pre>
      </div>

      {/* Recommended Configuration (Remediated) */}
      <div className="flex flex-col rounded-lg border border-[#22C55E]/40 bg-[#070B14] overflow-hidden">
        <div className="flex items-center justify-between border-b border-[#22C55E]/30 bg-[#22C55E]/10 px-4 py-2 text-xs font-semibold text-[#22C55E]">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="h-4 w-4" />
            <span>RECOMMENDED CONFIGURATION (Least Privilege)</span>
          </div>
          <button
            onClick={() => handleCopy(suggestedYaml, 'suggested')}
            className="flex items-center gap-1 rounded bg-[#111827] px-2 py-0.5 text-[10px] text-[#94A3B8] hover:text-[#F8FAFC]"
          >
            {copiedSuggested ? <Check className="h-3 w-3 text-[#22C55E]" /> : <Copy className="h-3 w-3" />}
            {copiedSuggested ? 'Copied' : 'Copy'}
          </button>
        </div>
        <pre className="flex-1 p-4 font-mono text-xs text-[#22C55E] overflow-x-auto leading-relaxed bg-[#0D1320]/60">
          <code>{suggestedYaml}</code>
        </pre>
      </div>
    </div>
  );
};
