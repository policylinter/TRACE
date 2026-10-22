import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement>;

const base = {
  width: 14,
  height: 14,
  viewBox: '0 0 16 16',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.4,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
};

export function IconSearch(p: P) {
  return (
    <svg {...base} {...p}>
      <circle cx="7" cy="7" r="4.25" />
      <path d="M10.2 10.2 13.5 13.5" />
    </svg>
  );
}

export function IconChevronRight(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M6 3.5 10.5 8 6 12.5" />
    </svg>
  );
}

export function IconChevronLeft(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M10 3.5 5.5 8 10 12.5" />
    </svg>
  );
}

export function IconMenu(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
    </svg>
  );
}

export function IconClose(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M4 4l8 8M12 4l-8 8" />
    </svg>
  );
}

export function IconCopy(p: P) {
  return (
    <svg {...base} {...p}>
      <rect x="5.5" y="5.5" width="7" height="7" rx="1.5" />
      <path d="M10.5 3.5h-6a1 1 0 0 0-1 1v6" />
    </svg>
  );
}

export function IconDownload(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M8 2.5v7.5" />
      <path d="M5 7.5 8 10.5l3-3" />
      <path d="M2.75 12.5h10.5" />
    </svg>
  );
}

export function IconCheck(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M3 8.5 6.5 12 13 4.5" />
    </svg>
  );
}

export function IconShield(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z" />
      <path d="M5.75 8 7.25 9.5l3-3.5" />
    </svg>
  );
}

export function IconSparkle(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M6 2.25 7 5.5l3.25 1L7 7.5 6 10.75 5 7.5 1.75 6.5 5 5.5Z" />
      <path d="M12 9.5l.5 1.75 1.75.5-1.75.5-.5 1.75-.5-1.75L9.75 11.75l1.75-.5Z" />
    </svg>
  );
}

export function IconGraph(p: P) {
  return (
    <svg {...base} {...p}>
      <circle cx="8" cy="3" r="1.6" />
      <circle cx="3.25" cy="12" r="1.6" />
      <circle cx="12.75" cy="12" r="1.6" />
      <path d="M7.1 4.5 4.1 10.6M8.9 4.5l3 6.1M4.9 12h6.2" />
    </svg>
  );
}

export function IconList(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M5.5 4h8M5.5 8h8M5.5 12h8" />
      <path d="M2.5 4h.01M2.5 8h.01M2.5 12h.01" strokeWidth="1.8" />
    </svg>
  );
}

export function IconGrid(p: P) {
  return (
    <svg {...base} {...p}>
      <rect x="2.25" y="2.25" width="5" height="5" rx="1" />
      <rect x="8.75" y="2.25" width="5" height="5" rx="1" />
      <rect x="2.25" y="8.75" width="5" height="5" rx="1" />
      <rect x="8.75" y="8.75" width="5" height="5" rx="1" />
    </svg>
  );
}

export function IconLayers(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M8 1.75 14.25 5 8 8.25 1.75 5Z" />
      <path d="m1.75 8.5 6.25 3.25 6.25-3.25" />
      <path d="m1.75 11.5 6.25 3.25 6.25-3.25" />
    </svg>
  );
}

export function IconDoc(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M9 1.75H4.5a1 1 0 0 0-1 1v10.5a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1V5.25Z" />
      <path d="M9 1.75V5.25h3.5" />
      <path d="M6 8.5h4M6 11h2.5" />
    </svg>
  );
}

export function IconAlert(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M7.05 2.4 1.6 12a1 1 0 0 0 .85 1.5h11.1a1 1 0 0 0 .85-1.5L8.95 2.4a1 1 0 0 0-1.9 0Z" />
      <path d="M8 6.25v3M8 11.6h.01" strokeWidth="1.6" />
    </svg>
  );
}

export function IconCpu(p: P) {
  return (
    <svg {...base} {...p}>
      <rect x="4.25" y="4.25" width="7.5" height="7.5" rx="1.25" />
      <rect x="6.5" y="6.5" width="3" height="3" rx="0.5" />
      <path d="M6.25 1.75v2.5M9.75 1.75v2.5M6.25 11.75v2.5M9.75 11.75v2.5M1.75 6.25h2.5M1.75 9.75h2.5M11.75 6.25h2.5M11.75 9.75h2.5" />
    </svg>
  );
}

export function IconLock(p: P) {
  return (
    <svg {...base} {...p}>
      <rect x="2.75" y="7" width="10.5" height="6.5" rx="1.5" />
      <path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" />
    </svg>
  );
}

export function IconTarget(p: P) {
  return (
    <svg {...base} {...p}>
      <circle cx="8" cy="8" r="5.75" />
      <circle cx="8" cy="8" r="2.5" />
      <path d="M8 1v1.75M8 13.25V15M1 8h1.75M13.25 8H15" />
    </svg>
  );
}

export function IconCompare(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M4 4.5h5.5M4 4.5 6.5 2M4 4.5 6.5 7" />
      <path d="M12 11.5H6.5M12 11.5 9.5 9M12 11.5 9.5 14" />
    </svg>
  );
}

export function IconBell(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M4 6.75a4 4 0 0 1 8 0c0 2.5.75 3.75 1.25 4.25H2.75C3.25 10.5 4 9.25 4 6.75Z" />
      <path d="M6.5 13.25a1.6 1.6 0 0 0 3 0" />
    </svg>
  );
}

export function IconChevronDown(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M4 6.25 8 10.25 12 6.25" />
    </svg>
  );
}

export function IconUser(p: P) {
  return (
    <svg {...base} {...p}>
      <circle cx="8" cy="5.75" r="2.5" />
      <path d="M3.25 13.25a4.75 4.75 0 0 1 9.5 0" />
    </svg>
  );
}

export function IconLogout(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M9.5 3.25H4.25a1 1 0 0 0-1 1v7.5a1 1 0 0 0 1 1H9.5" />
      <path d="M7.25 8h6.25M11.5 5.75 13.75 8l-2.25 2.25" />
    </svg>
  );
}

export function IconFolder(p: P) {
  return (
    <svg {...base} {...p}>
      <path d="M2.25 4.75a1 1 0 0 1 1-1h2.4l1.2 1.5h5.9a1 1 0 0 1 1 1v5.5a1 1 0 0 1-1 1h-9.5a1 1 0 0 1-1-1Z" />
    </svg>
  );
}
