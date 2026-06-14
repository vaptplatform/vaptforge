import React from 'react';
import { formatExact, formatRelative, safeParse } from '../../utils/dateUtils';

interface Props {
  value: string | Date | null | undefined;
  showRelative?: boolean;
  exactStyle?: React.CSSProperties;
  relativeStyle?: React.CSSProperties;
  inline?: boolean;
}

/**
 * DateDisplay — shows BOTH exact date/time AND relative time
 * Example output:
 *   04 May 2026, 12:45 PM
 *   (2 minutes ago)
 */
export default function DateDisplay({
  value,
  showRelative = true,
  exactStyle,
  relativeStyle,
  inline = false,
}: Props) {
  const exact    = formatExact(value);
  const relative = formatRelative(value);
  const valid    = !!safeParse(value);

  if (!valid) return <span style={{ color: 'var(--text3)' }}>—</span>;

  if (inline) {
    return (
      <span title={exact}>
        <span style={{ color: 'var(--text)', ...exactStyle }}>{exact}</span>
        {showRelative && relative && (
          <span style={{ color: 'var(--text3)', fontSize: '0.85em', marginLeft: 6, ...relativeStyle }}>
            ({relative})
          </span>
        )}
      </span>
    );
  }

  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500, ...exactStyle }}>
        {exact}
      </div>
      {showRelative && relative && (
        <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 1, ...relativeStyle }}>
          {relative}
        </div>
      )}
    </div>
  );
}
