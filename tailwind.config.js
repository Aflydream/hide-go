/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './setup.html', './src/**/*.{ts,tsx}'],
  theme: {
    fontFamily: {
      sans: ['"IBM Plex Sans Variable"', '"IBM Plex Sans"', '-apple-system', 'BlinkMacSystemFont', '"PingFang SC"', '"Microsoft YaHei UI"', '"Microsoft YaHei"', 'system-ui', 'sans-serif'],
      mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', 'ui-monospace', '"SFMono-Regular"', 'Menlo', 'Consolas', '"PingFang SC"', '"Microsoft YaHei"', 'monospace'],
    },
    fontSize: {
      '2xs': ['11px', { lineHeight: '16px' }],
      xs: ['12px', { lineHeight: '18px' }],
      sm: ['13px', { lineHeight: '20px' }],
      base: ['14px', { lineHeight: '22px' }],
      lg: ['16px', { lineHeight: '24px' }],
      xl: ['20px', { lineHeight: '28px' }],
      '2xl': ['24px', { lineHeight: '30px' }],
      '3xl': ['30px', { lineHeight: '36px' }],
    },
    borderRadius: {
      none: '0',
      sm: '4px',
      DEFAULT: '6px',
      md: '8px',
      lg: '10px',
      xl: '14px',
      '2xl': '18px',
      full: '9999px',
    },
    extend: {
      colors: {
        bg: token('bg'),
        surface: { DEFAULT: token('surface'), 2: token('surface-2'), 3: token('surface-3') },
        line: { DEFAULT: token('line'), strong: token('line-strong'), control: token('line-control') },
        fg: { DEFAULT: token('fg'), muted: token('fg-muted'), subtle: token('fg-subtle') },
        brand: { DEFAULT: token('brand'), solid: token('brand-solid'), on: token('brand-on') },
        ok: { DEFAULT: token('ok') },
        danger: { DEFAULT: token('danger'), solid: token('danger-solid') },
        warn: { DEFAULT: token('warn') },
        info: { DEFAULT: token('info') },
        focus: token('focus'),
      },
      transitionDuration: { DEFAULT: '160ms' },
      transitionTimingFunction: { DEFAULT: 'cubic-bezier(0.2, 0, 0, 1)' },
      boxShadow: {
        control: 'var(--shadow-control)',
        card: 'var(--shadow-card)',
        sheet: 'var(--shadow-sheet)',
        overlay: 'var(--shadow-overlay)',
      },
    },
  },
  plugins: [],
};
