import React from 'react'
import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../context/ThemeContext'

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()
  const isDark = theme === 'dark'

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-navy-600 bg-navy-900/80 hover:bg-navy-700/60 transition text-xs select-none"
      title={`Switch to ${isDark ? 'Light' : 'Dark'} mode`}
      aria-label="Toggle theme mode"
    >
      <div className="relative w-4 h-4 flex items-center justify-center">
        {isDark ? (
          <Moon className="w-3.5 h-3.5 text-cyan-400 transition-transform duration-300 transform rotate-0" />
        ) : (
          <Sun className="w-3.5 h-3.5 text-amber-500 transition-transform duration-300 transform rotate-0" />
        )}
      </div>
      <span className="font-medium text-slate-300">
        {isDark ? 'Dark' : 'Light'}
      </span>
    </button>
  )
}
