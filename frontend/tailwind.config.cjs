/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        app: {
          bg:      '#0b0d13',
          surface: '#111520',
          raised:  '#171b2a',
          overlay: '#1d2135',
        },
        'border-subtle':  '#1e2338',
        'border-default': '#252b3d',
        'border-strong':  '#303751',
        'text-primary':   '#edf0f7',
        'text-secondary': '#7d8aa0',
        'text-muted':     '#404d66',
        accent: {
          400: '#8b82ff',
          500: '#6d63ff',
          600: '#574ede',
        },
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#22c55e',
        info:     '#3b82f6',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'slide-in': 'slide-in 220ms cubic-bezier(0.16,1,0.3,1) both',
        'fade-in':  'fade-in 150ms ease-out both',
        'float-up': 'float-up 180ms ease-out both',
      },
      keyframes: {
        'slide-in': {
          from: { transform: 'translateX(100%)', opacity: '0' },
          to:   { transform: 'translateX(0)',    opacity: '1' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'float-up': {
          from: { transform: 'translateY(8px)', opacity: '0' },
          to:   { transform: 'translateY(0)',   opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
