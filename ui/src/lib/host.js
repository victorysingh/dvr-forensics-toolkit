// Where is this console actually running?
//
// The product's top bar claims "offline · read-only", and the claim is a
// real one: the Python viewer binds 127.0.0.1 and never opens a device. On
// an examiner's workstation that is true. Served from anywhere else it is
// not, so the console must not keep asserting it.
//
// This is not demo scaffolding. A forensic tool that misreports its own
// posture is worse than one that says plainly it is a demonstration, and the
// check costs one comparison.

const NAMES = new Set(["localhost", "::1", "[::1]", ""]);

/** True when served by the local viewer, i.e. the real product. */
export function isLoopback() {
  try {
    const h = location.hostname;
    if (NAMES.has(h)) return true;
    // the whole 127.0.0.0/8 block is loopback, not just 127.0.0.1
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
  } catch {
    return true;          // no location to read: assume the real thing
  }
}

/** True when this is the hosted demonstration build. */
export const isDemo = () => !isLoopback();
