/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0b1220',
          800: '#0f172a',
          700: '#111c2e',
          600: '#1e293b',
          500: '#334155',
        },
        accent: {
          cyan: '#22d3ee',
          blue: '#3b82f6',
          amber: '#f59e0b',
          red: '#ef4444',
          green: '#10b981',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
