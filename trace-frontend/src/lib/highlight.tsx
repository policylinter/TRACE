import type { ReactNode } from 'react';

const TOKEN_RE =
  /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?)|([{}[\],:])/g;

/** Colourises a JSON string into spans for display inside a <pre>. */
export function highlightJson(source: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let match: RegExpExecArray | null;

  TOKEN_RE.lastIndex = 0;
  while ((match = TOKEN_RE.exec(source)) !== null) {
    if (match.index > last) out.push(source.slice(last, match.index));

    const g = match as unknown as {
      1?: string;
      2?: string;
      3?: string;
      4?: string;
      5?: string;
    };
    const full = match[0];

    if (g[1] !== undefined) {
      const isKey = g[2] !== undefined;
      out.push(
        <span key={key++} className={isKey ? 'syntax-key' : 'syntax-string'}>
          {g[1]}
        </span>,
      );
      if (g[2] !== undefined) {
        out.push(
          <span key={key++} className="syntax-punctuation">
            {g[2]}
          </span>,
        );
      }
    } else if (g[3] !== undefined) {
      out.push(
        <span key={key++} className="syntax-literal">
          {g[3]}
        </span>,
      );
    } else if (g[4] !== undefined) {
      out.push(
        <span key={key++} className="syntax-number">
          {g[4]}
        </span>,
      );
    } else if (g[5] !== undefined) {
      out.push(
        <span key={key++} className="syntax-punctuation">
          {g[5]}
        </span>,
      );
    }

    last = match.index + full.length;
  }

  if (last < source.length) out.push(source.slice(last));
  return out;
}
