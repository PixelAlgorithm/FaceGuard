/**
 * Demo identities (user_id + display name + role only) for the /register and /admin pick lists and the
 * operator role fallback. Source: config/schedule.demo.json (the live bundle source), generated into
 * demoUsers.generated.ts by scripts/fetch-assets.mjs (predev / prebuild / npm run assets). Falls back to the
 * vite plugin's list (config/schedule.example.json) if the generated list is empty.
 */
import fallbackUsers from 'virtual:demo-users'
import { DEMO_USERS_SOURCE as GENERATED_SOURCE, GENERATED_DEMO_USERS } from './demoUsers.generated'

export interface DemoUser {
  user_id: string
  display: string
  role: string
}

export const DEMO_USERS: readonly DemoUser[] = GENERATED_DEMO_USERS.length ? GENERATED_DEMO_USERS : fallbackUsers
export const DEMO_USERS_SOURCE: string = GENERATED_DEMO_USERS.length ? GENERATED_SOURCE : 'config/schedule.example.json'
