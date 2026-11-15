/**
 * Display helpers for the Users & Access table. The hours themselves come from accessRules.hoursFor (R-I:
 * role_defaults + extra_windows); the edge's `today` (edge/policy/schedule.py) is authoritative for its zone.
 */
import type { AccessWindow, DayCode } from '../api/types'

const TZ = 'Asia/Kolkata'
const DAYS: DayCode[] = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT']

export interface LocalDay {
  /** YYYY-MM-DD in Asia/Kolkata */
  date: string
  day: DayCode
}

/** Local date in Asia/Kolkata (kiosk time zone), independent of the laptop's zone. */
export function localDay(at: Date = new Date()): LocalDay {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short' }).formatToParts(at)
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? ''
  const wd = get('weekday').slice(0, 3).toUpperCase() as DayCode
  return { date: `${get('year')}-${get('month')}-${get('day')}`, day: DAYS.includes(wd) ? wd : 'MON' }
}

export function daysText(days: readonly DayCode[]): string {
  if (days.length === 7) return 'daily'
  if (days.length === 5 && ['MON', 'TUE', 'WED', 'THU', 'FRI'].every((d) => days.includes(d as DayCode))) return 'MON–FRI'
  if (days.length === 6 && !days.includes('SUN')) return 'MON–SAT'
  return days.join(' ')
}

export function windowsText(ws: readonly AccessWindow[]): string {
  return ws.map((w) => `${daysText(w.days)} ${w.start}–${w.end}`).join(' · ')
}

/** Short summary of extra windows: "LIBRARY: SUN 07:00–21:00". */
export function extraWindowsText(ew: Record<string, AccessWindow[]>): string {
  return Object.entries(ew)
    .filter(([, ws]) => ws.length)
    .map(([zone, ws]) => `${zone}: ${windowsText(ws)}`)
    .join(' · ')
}
