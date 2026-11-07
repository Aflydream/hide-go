/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter"', '-apple-system', 'BlinkMacSystemFont', '"PingFang SC"', '"Microsoft YaHei"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"SFMono-Regular"', 'Menlo', 'Monaco', 'Consolas', 'ui-monospace', 'monospace'],
      },
      colors: {
        canvas: '#F2F1ED',
        paper: '#FFFFFF',
        warm: {
          50: '#F8F7F4',
          100: '#F2F1ED',
          200: '#E5E3DC',
          300: '#D4D1C7',
          400: '#A19E93',
          500: '#706E66',
          600: '#525049',
          900: '#131B20',
        },
        brand: {
          DEFAULT: '#00A87E',
          dark: '#008A67',
          soft: '#EAF6F2',
        },
      },
      boxShadow: {
        panel: '0 1px 3px 0 rgba(19, 27, 32, 0.04), 0 1px 2px -1px rgba(19, 27, 32, 0.03)',
        pill: '0 1px 2px 0 rgba(19, 27, 32, 0.06)',
      },
    },
  },
  plugins: [],
};
