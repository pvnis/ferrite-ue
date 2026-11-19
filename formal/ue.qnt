// The Ferrite UE's registration path across its layers, as a Quint model:
// NAS 5GMM (ferrite_nas::machine::MmMachine), 5GMM-IDLE / CONNECTED
// (CmMachine), RRC (ferrite_rrc::machine::RrcMachine, random access folded
// into Connecting), and the stack glue that ties them together
// (ferrite-ue/src/stack.rs). The network (gNB, core) and the timers act
// nondeterministically.
//
// The per-layer transitions are the Rust tables; what the model adds is
// their composition, which the tables cannot see. Properties:
//   * noStuck: whenever the UE wants to register, something is pending that
//     will make progress (a timer, a retry, a connection in progress);
//   * t3510Consistent: T3510 runs exactly while a registration is in
//     progress (TS 24.501 §5.5.1.2.2);
//   * cmFollowsRrc: 5GMM-CONNECTED exactly while RRC is connected;
//   * backoff: at most 5 registration attempts in a row without the T3502
//     wait (TS 24.501 §5.5.1.2.7: the attempt counter, T3511, T3502).
//
// `FIXED` selects the stack's behaviour on an RRC establishment failure
// during registration: false = before 2026-11-19 (the stack retried by
// itself and restarted the NAS registration, resetting its attempt counter),
// true = the NAS handles it as the abnormal case it is.
//
//   quint run formal/ue.qnt --main=current --invariant=backoff   (violated)
//   quint run formal/ue.qnt --main=fixed --invariant=allProps         (holds)
module ue {
  const FIXED: bool

  /// 5GMM states (the subset on the registration path).
  type Mm = DeregInit | DeregNormal | DeregAttempting | DeregNoSupi | RegInit | SecMode | Registered

  type State = {
    mm: Mm,
    cmConnected: bool,
    // RRC: "Idle" | "Connecting" | "Connected"
    rrc: str,
    t3510: bool,
    t3511: bool,
    t3502: bool,
    t300: bool,
    // NasUe::reg_attempts
    regAttempts: int,
    // The stack's retry timer (ConnectionRetry::retry_at), current behaviour only.
    stackRetry: bool,
    // NAS asked for a connection (NasEvent::ConnectionNeeded) not yet made.
    connNeeded: bool,
    // The stack started (SIB1 seen).
    started: bool,
    // Registration requests in a row without the T3502 wait (for `backoff`).
    attemptsInRow: int,
    // The last action, for counterexamples.
    last: str,
  }

  var s: State

  pure val MAX_ATTEMPTS = 5

  def inRegistration(m: Mm): bool = m == RegInit or m == SecMode

  // NasUe::send_registration_request (via start_registration or
  // initiate_registration): RegistrationInitiated, T3510, T3511/T3502 off.
  def sendRegistration(x: State, resetAttempts: bool, why: str): State =
    x.with("mm", RegInit)
      .with("t3510", true)
      .with("t3511", false)
      .with("t3502", false)
      .with("regAttempts", if (resetAttempts) 0 else x.regAttempts)
      .with("attemptsInRow", x.attemptsInRow + 1)
      .with("last", why)

  // NasUe::registration_attempt_failed: attempt counter, then T3511 or
  // (after MAX_ATTEMPTS) T3502 with the counter reset.
  def attemptFailed(x: State, why: str): State =
    val n = x.regAttempts + 1
    x.with("mm", DeregAttempting)
      .with("t3510", false)
      .with("t3511", n < MAX_ATTEMPTS)
      .with("t3502", n >= MAX_ATTEMPTS)
      .with("regAttempts", if (n >= MAX_ATTEMPTS) 0 else n)
      .with("last", why)

  // The RRC connection request the stack makes (RrcUe::connect / connect_for).
  def connect(x: State): State =
    x.with("rrc", "Connecting").with("t300", true).with("connNeeded", false)

  // An RRC establishment failure (random access, T300) reaching the stack
  // (RrcEvent::Failed): NAS 5GMM-IDLE, then either the stack's own retry
  // (current) or the NAS abnormal case (fixed).
  def establishmentFailed(x: State, why: str): State =
    val idle = x.with("rrc", "Idle").with("t300", false).with("cmConnected", false)
    if (FIXED)
      if (inRegistration(idle.mm)) attemptFailed(idle, why) else idle.with("last", why)
    else
      idle.with("stackRetry", true).with("last", why)

  action init = s' = {
    mm: DeregInit,
    cmConnected: false,
    rrc: "Idle",
    t3510: false,
    t3511: false,
    t3502: false,
    t300: false,
    regAttempts: 0,
    stackRetry: false,
    connNeeded: false,
    started: false,
    attemptsInRow: 0,
    last: "init",
  }

  // SIB1: the stack starts the first registration (start_connection).
  action cellConfigured = all {
    not(s.started),
    s' = connect(sendRegistration(s.with("started", true), true, "cellConfigured")),
  }

  // Random access and RRCSetup succeed: RRC_CONNECTED, 5GMM-CONNECTED.
  action rrcSetup = all {
    s.rrc == "Connecting",
    s' = s.with("rrc", "Connected").with("t300", false).with("cmConnected", true).with("last", "rrcSetup"),
  }

  // Random access fails or T300 expires.
  action establishmentFailure = all {
    s.rrc == "Connecting",
    s' = establishmentFailed(s, "establishmentFailure"),
  }

  // The stack's retry timer (current behaviour): a registered NAS owns its
  // retries; otherwise start_connection restarts the registration.
  action stackRetryDue = all {
    s.stackRetry,
    s.rrc == "Idle",
    s' = if (s.mm == Registered or s.connNeeded) s.with("stackRetry", false).with("connNeeded", true).with("last", "stackRetryDue")
         else if (s.mm == DeregNoSupi) s.with("stackRetry", false).with("last", "stackRetryDue (barred)")
         else connect(sendRegistration(s.with("stackRetry", false), true, "stackRetryDue")),
  }

  action t3510Expiry = all {
    s.t3510,
    inRegistration(s.mm),
    s' = attemptFailed(s, "t3510Expiry"),
  }

  // T3511 / T3502 expiry: initiate_registration, at once when connected,
  // else behind a ConnectionNeeded.
  action retryTimerExpiry = all {
    s.t3511 or s.t3502,
    val afterWait = if (s.t3502) s.with("attemptsInRow", 0) else s
    val sent = sendRegistration(afterWait, false, if (s.t3502) "t3502Expiry" else "t3511Expiry")
    s' = if (s.cmConnected) sent else sent.with("connNeeded", true),
  }

  // The stack makes the connection the NAS asked for (nas_connect).
  action nasConnect = all {
    s.connNeeded,
    s.rrc == "Idle",
    s' = connect(s).with("last", "nasConnect"),
  }

  // Authentication and security mode (folded: RegistrationInitiated → SecurityMode).
  action coreSecurity = all {
    s.mm == RegInit,
    s.cmConnected,
    s' = s.with("mm", SecMode).with("last", "coreSecurity"),
  }

  action coreAccept = all {
    inRegistration(s.mm),
    s.cmConnected,
    s' = s.with("mm", Registered).with("t3510", false).with("regAttempts", 0)
          .with("attemptsInRow", 0).with("last", "coreAccept"),
  }

  // REGISTRATION REJECT with an abnormal cause (attempt counter).
  action coreRejectAbnormal = all {
    inRegistration(s.mm),
    s.cmConnected,
    s' = attemptFailed(s, "coreRejectAbnormal"),
  }

  // REGISTRATION REJECT #3 / #6 / #7: the USIM is invalid until switch off.
  action coreRejectNoSupi = all {
    inRegistration(s.mm),
    s.cmConnected,
    s' = s.with("mm", DeregNoSupi).with("t3510", false).with("t3511", false)
          .with("t3502", false).with("last", "coreRejectNoSupi"),
  }

  // The UE switches off: DEREGISTRATION REQUEST with switch off (local).
  action switchOff = all {
    s.mm == Registered,
    s' = s.with("mm", DeregNormal).with("last", "switchOff"),
  }

  // RRCRelease: 5GMM-IDLE; a registration in progress keeps T3510 running.
  action release = all {
    s.rrc == "Connected",
    s' = s.with("rrc", "Idle").with("cmConnected", false).with("last", "release"),
  }

  // Radio link failure without AS security: RRC_IDLE, the stack's failure path.
  action rlf = all {
    s.rrc == "Connected",
    not(s.mm == Registered),
    s' = establishmentFailed(s, "rlf"),
  }

  action step = any {
    cellConfigured,
    rrcSetup,
    establishmentFailure,
    stackRetryDue,
    t3510Expiry,
    retryTimerExpiry,
    nasConnect,
    coreSecurity,
    coreAccept,
    coreRejectAbnormal,
    coreRejectNoSupi,
    release,
    rlf,
    switchOff,
  }

  // --- properties ---

  val wantsRegistration = s.started and (inRegistration(s.mm) or s.mm == DeregAttempting)
  val progressPending =
    s.t3510 or s.t3511 or s.t3502 or s.stackRetry or s.connNeeded or s.rrc != "Idle"
  val noStuck = wantsRegistration implies progressPending

  val t3510Consistent = s.t3510 iff inRegistration(s.mm)

  val cmFollowsRrc = s.cmConnected iff s.rrc == "Connected"

  val backoff = s.attemptsInRow <= MAX_ATTEMPTS

  val allProps = noStuck and t3510Consistent and cmFollowsRrc and backoff
}

module current {
  import ue(FIXED = false).*
}

module fixed {
  import ue(FIXED = true).*
}
