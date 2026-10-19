/** What the profile list shows beside a signed-in profile's state. */
export type SessionTime =
    | { kind: "none" }
    | { kind: "since"; secs: number; known: boolean }
    | { kind: "left"; secs: number };

/** Profile fields the label reads (backend ProfileSummary, unix seconds; 0 = unknown). */
export interface SessionTimes {
    signedIn: boolean;
    session_started_at?: number;
    session_expires_at?: number;
}

/** Time signed in, or (with `showLoggedIn` off) time left. An unknown expiry falls
 *  back to time signed in, and an unknown sign-in time counts from 0. Not signed in
 *  shows nothing. */
export function sessionTime(p: SessionTimes, nowSec: number, showLoggedIn: boolean): SessionTime {
    if (!p.signedIn) return { kind: "none" };
    if (!showLoggedIn && p.session_expires_at) {
        return { kind: "left", secs: Math.floor(p.session_expires_at - nowSec) };
    }
    const started = p.session_started_at || 0;
    return { kind: "since", secs: started ? Math.max(0, Math.floor(nowSec - started)) : 0, known: !!started };
}
