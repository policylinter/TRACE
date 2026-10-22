/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#05070C',
          925: '#070A11',
          900: '#0A0E17',
          875: '#0D1220',
          850: '#101627',
          800: '#151D30',
          750: '#1B2437',
        },
        jade: {
          200: '#9ff2cf',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
        },
        hairline: 'rgba(110, 231, 183, 0.07)',
        'hairline-strong': 'rgba(110, 231, 183, 0.14)',
      },
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'sans-serif',
        ],
        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
      },
      letterSpacing: {
        micro: '0.14em',
      },
      boxShadow: {
        panel:
          '0 1px 0 0 rgba(110,231,183,0.05) inset, 0 1px 2px rgba(0,0,0,0.55), 0 24px 52px -26px rgba(0,0,0,0.95)',
        float:
          '0 0 0 1px rgba(110,231,183,0.06) inset, 0 12px 32px rgba(0,0,0,0.55), 0 0 54px -18px rgba(52,211,153,0.22)',
        glow: '0 0 24px -6px rgba(52,211,153,0.4)',
        drawer: '-24px 0 48px -24px rgba(0,0,0,0.9)',
        sink: '0 0 0 1px rgba(244,63,94,0.35), 0 0 22px -4px rgba(244,63,94,0.45)',
        inset: 'inset 0 1px 0 rgba(255,255,255,0.05)',
      },
      transitionTimingFunction: {
        swift: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        'fade-rise': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'pulse-ring': {
          '0%, 100%': { opacity: '0.35' },
          '50%': { opacity: '0.85' },
        },
        'sweep': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        'logo-pulse': {
          '0%, 100%': { opacity: '0.25', transform: 'scale(1)' },
          '50%': { opacity: '0.85', transform: 'scale(1.15)' },
        },
        'orb-a': {
          '0%, 100%': { transform: 'translate3d(0, 0, 0) scale(1)' },
          '50%': { transform: 'translate3d(56px, 40px, 0) scale(1.18)' },
        },
        'orb-b': {
          '0%, 100%': { transform: 'translate3d(0, 0, 0) scale(1.05)' },
          '50%': { transform: 'translate3d(-64px, -48px, 0) scale(0.92)' },
        },
      },
      animation: {
        'fade-rise': 'fade-rise 260ms cubic-bezier(0.16, 1, 0.3, 1) both',
        'pulse-ring': 'pulse-ring 2.4s ease-in-out infinite',
        sweep: 'sweep 2.2s ease-in-out infinite',
        'logo-pulse': 'logo-pulse 3.4s ease-in-out infinite',
        'orb-a': 'orb-a 26s ease-in-out infinite',
        'orb-b': 'orb-b 34s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};