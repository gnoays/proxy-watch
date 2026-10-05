//! Small pure helpers shared by the parsers. Not part of the public API.

// Split an authority-ish string into a host part and an optional port.
pub(crate) fn split_host_port(input: &str) -> Result<(&str, Option<u16>), String> {
    if input.starts_with('[') {
        let Some(end) = input.find(']') else {
            return Err("unbalanced '[' in IPv6 literal".to_owned());
        };
        let host = &input[..=end];
        let rest = &input[end + 1..];
        if rest.is_empty() {
            return Ok((host, None));
        }
        let Some(port) = rest.strip_prefix(':') else {
            return Err("unexpected trailing text after IPv6 literal".to_owned());
        };
        return Ok((host, parse_port(port)?));
    }

    match input.rfind(':') {
        // Exactly one colon: `host:port`.
        Some(idx) if !input[..idx].contains(':') => {
            Ok((&input[..idx], parse_port(&input[idx + 1..])?))
        }
        // No colon, or several colons (an unbracketed IPv6 literal).
        _ => Ok((input, None)),
    }
}

fn parse_port(text: &str) -> Result<Option<u16>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    port_from_digits(text)
        .map(Some)
        .ok_or_else(|| invalid_port_reason(text))
}

// The one port grammar in this crate: `1*DIGIT`, in range.
//
// `u16::from_str` also accepts a sign, and neither reference does: Chromium reads a bypass
// rule's port with `ParseInt32(…, NON_NEGATIVE)` and a proxy spec's with `url::ParsePort`.
// Leaving the sign in made this the only one of the three that honoured `host:+80`
// (Chromium drops the rule, Go keeps a textual port that never equals `80`), and it made
// [`invalid_port_reason`]'s own words, "expected only ASCII digits 0-9", false about the
// grammar it names. Leading zeros stay legal: `NON_NEGATIVE` says "0003 is valid and
// equivalent to 3". Callers that read a port from somewhere other than an authority string
// (`sys::proxy_dict`) come through here so the grammar has one home.
pub(crate) fn port_from_digits(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u16>().ok()
}

// Describe why `text` did not parse as a `u16` port, without ever echoing `text`
// itself back in the message.
fn invalid_port_reason(text: &str) -> String {
    let len = text.chars().count();
    let digits = text.chars().filter(char::is_ascii_digit).count();
    if digits == len {
        format!("invalid port: {len}-digit number is out of the 0-65535 range")
    } else {
        format!(
            "invalid port: {len} character{} ({digits} ASCII digit{}, {} other), expected only ASCII digits 0-9",
            if len == 1 { "" } else { "s" },
            if digits == 1 { "" } else { "s" },
            len - digits,
        )
    }
}

// Quote `text` for an [`Error`](crate::Error) `reason`, but only when it cannot be
// carrying a credential; otherwise describe its shape the way [`invalid_port_reason`]
// does.
pub(crate) fn quote_if_not_credential_shaped(text: &str) -> String {
    if userinfo_delimiter_end(text).is_none() {
        return format!("{text:?}");
    }
    withheld_description(text)
}

// What stands in for text that may be a credential: its length, and why it is not shown.
fn withheld_description(text: &str) -> String {
    let len = text.chars().count();
    format!("<{len} characters, withheld: it may hold a user:password fragment>")
}

pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

// Match `text` against a glob with `*` only. `HostPattern::Wildcard` and the `?`-free
// `shExpMatch` route share this matcher; `pac::hostfn::wildcard_match` handles `?`.
//
// Allocates nothing: a PAC script picks the pattern, and a `Vec` of its parts costs 16 bytes
// per `*` outside the interpreter's memory limit.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let Some((first, after_first)) = pattern.split_once('*') else {
        return pattern == text;
    };
    let (middle, last) = after_first.rsplit_once('*').unwrap_or(("", after_first));
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    // An empty part (a trailing `*`, or `**` anywhere) needs no case of its own: a branch
    // for it is one no input could tell from its absence, because `ends_with("")` is true
    // of every string and `find("")` is `Some(0)`, which is the same "match nothing here
    // and move on" a hand-written `continue` would spell out.
    for part in middle.split('*') {
        match rest.find(part) {
            Some(idx) => rest = &rest[idx + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

// Decode `%XX` escapes in a URL userinfo component.
//
// Invalid escapes are passed through unchanged, and the result is only decoded when
// the bytes form valid UTF-8 (otherwise the input is returned as-is).
pub(crate) fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_owned();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_owned())
}

// What every redaction in this crate puts in place of a secret: `ProxyAuth`'s `Debug`,
// `trace::render::MaskedUrl`, and `redact_userinfo` below. One name because
// `residual_credential_shaped` reads back what `redact_userinfo` wrote, and because
// `MaskedUrl` emits both: the token itself on the branch that rebuilds the URL, and this
// function's output on the branch that does not.
pub(crate) const MASK: &str = "***";

// Mask the `user:password@` occurrences in `input`, without assuming it parses as a URL.
// Not all of them: a space, a tab or a newline is a hard boundary the mask may not reach
// back past, so a password holding one splits into pieces that no longer look like
// credentials and none of them is masked (`alice:my pass@host` comes out whole). A
// carriage return separates *occurrences* but is not a hard boundary, so it costs
// nothing here; see the two sets below. A caller holding a single *token* wants
// [`redact_offending_token`] instead, which withholds that shape rather than printing it.
//
// The callers holding a whole *sentence* (a PAC return
// ([`Error::pac_invalid_result`](crate::Error)), engine text
// ([`pac_evaluation`](crate::Error)), a `GError` message
// (`sys::linux::portal::safe_message`)) cannot use it: the withhold pass would take the
// whole message and leave the reader nothing. They go through
// [`redact_and_sanitize_untrusted`], keeping the weaker mask knowingly, and a credential
// whose password holds a plain space, inside a sentence whose spaces are words, is not
// something either function can separate; nothing in this crate masks that. A tab or a
// newline in the same position is masked, but only because that wrapper replaces it before
// the scan runs; calling the two passes the other way round loses it.
pub(crate) fn redact_userinfo(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.contains('@') {
        return std::borrow::Cow::Borrowed(input);
    }

    let mut out = String::with_capacity(input.len());
    let mut copied_up_to = 0usize;

    // Index boundaries and delimiters once. Rescanning the widening prefix for each
    // `@` makes unbounded PAC returns and Windows `http_proxy` values quadratic.
    // Count `%3A` and `://` only when the whole delimiter fits inside the span.
    let bytes = input.as_bytes();
    let mut at_positions: Vec<usize> = Vec::new();
    // Whitespace the mask may not reach back past: the three characters named below, not
    // `\r`.
    let mut boundaries: Vec<usize> = Vec::new();
    let mut colons: Vec<usize> = Vec::new();
    let mut encoded_colons: Vec<usize> = Vec::new();
    let mut schemes: Vec<usize> = Vec::new();
    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'@' => at_positions.push(i),
            b' ' | b'\t' | b'\n' => boundaries.push(i),
            b':' => {
                colons.push(i);
                if bytes.get(i + 1) == Some(&b'/') && bytes.get(i + 2) == Some(&b'/') {
                    schemes.push(i);
                }
            }
            b'%' if bytes.get(i + 1) == Some(&b'3')
                && bytes
                    .get(i + 2)
                    .is_some_and(|h| h.eq_ignore_ascii_case(&b'a')) =>
            {
                encoded_colons.push(i);
            }
            _ => {}
        }
    }

    // [`userinfo_delimiter_end`] over `input[from..upto]`, as an absolute offset. The
    // tie-break is that function's: the earlier start wins, and the literal wins a tie it
    // cannot have, since a `:` and a `%` are different bytes. Only the first
    // candidate of each spelling is examined; a later one starts further right, so if the
    // first does not fit in the span none of them does.
    let first_delimiter_end = |from: usize, upto: usize| -> Option<usize> {
        let literal = colons
            .get(colons.partition_point(|&c| c < from))
            .copied()
            // `c < upto` rather than `c + 1 <= upto`, which is what the encoded test below
            // spells and would have made the shared rule, "the delimiter fits whole",
            // visible in both. Clippy rejects that spelling.
            .filter(|&c| c < upto);
        let encoded = encoded_colons
            .get(encoded_colons.partition_point(|&e| e < from))
            .copied()
            .filter(|&e| e + 3 <= upto);
        match (literal, encoded) {
            (Some(literal), Some(encoded)) => Some(if literal <= encoded {
                literal + 1
            } else {
                encoded + 3
            }),
            (Some(literal), None) => Some(literal + 1),
            (None, Some(encoded)) => Some(encoded + 3),
            (None, None) => None,
        }
    };

    for (i, &at) in at_positions.iter().enumerate() {
        // Use the last `@` in an authority segment as the userinfo terminator so an
        // `@` inside the password does not leak the rest (`alice:pa@ss@host`).
        //
        // Only the *next* `@` is asked. Asking every later one reads as the more careful
        // question and is the same question: each candidate widens the same span, and both
        // halves of the test (no whitespace, no `//`) only ever go from holding to not, so
        // a candidate that fails cannot be rescued by a later one and the first answer is
        // the answer. Asking them all rescans the widening span once per candidate, which
        // costs a factor of the token's length, and nothing in this crate bounds that
        // length. The token is whatever failed to parse, so an `http_proxy` holding one
        // reaches here through the error that rejects it; see
        // [`a_pathological_token_does_not_stall_the_error_that_rejects_it`].
        if let Some(&next) = at_positions.get(i + 1) {
            let between = &input[at + 1..next];
            if !between
                .bytes()
                .any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
                && !between.contains("//")
            {
                continue;
            }
        }

        // Hard boundaries are whitespace and a scheme's `://`: not a bare `//` inside a
        // password (`alice:aa//bb@host`), not an earlier `@`, and not a `://` inside the
        // password either (`alice:aa://bb@host`). **Whitespace here is the three
        // characters above and not `\r`**, unlike the set that ends an occurrence: a hard
        // boundary is what the mask may not reach back past, so a character listed here
        // is one a password may not contain and stay masked. `alice:pa\rss@host` is
        // masked today and stays that way. Adding `\r` for symmetry would print it.
        // The scheme is looked for *within* what the other two boundaries already left, and
        // only the first one that a scheme could stand in front of is taken, the rule
        // [`scheme_delimiter_end`] states and the `filter` below applies, so a password
        // carrying its own `://` cannot push the boundary past the `user:` half and strand
        // it there.
        let crossed = boundaries.partition_point(|&b| b < at);
        let after_marker = if crossed == 0 {
            0
        } else {
            boundaries[crossed - 1] + 1
        };
        let base = after_marker.max(copied_up_to);
        let segment_start = schemes
            .get(schemes.partition_point(|&s| s < base))
            .copied()
            .filter(|&s| s + 3 <= at && first_delimiter_end(base, s).is_none())
            .map_or(base, |s| s + 3);

        if let Some(delimiter_end) = first_delimiter_end(segment_start, at) {
            out.push_str(&input[copied_up_to..delimiter_end]);
            out.push_str(MASK);
            copied_up_to = at;
        }
    }

    out.push_str(&input[copied_up_to..]);
    std::borrow::Cow::Owned(out)
}

// Mask a token that failed to parse, wherever one is kept for the caller to see: an
// [`Error`](crate::Error) `input` field, a `rejected` list, a warning. `redact_userinfo`
// first, then withhold the token outright if a `user:password` fragment could still be
// hiding in it. Only `@` makes userinfo recognisable, and a token that failed to parse
// may never have reached one (`http://[bob:pw]:8080`, `http://bob:pw`). Whitespace also
// defeats the mask, whose scan restarts past it, and the withhold pass covers the two
// shapes where that costs something: the restart stranding the `user:` half from its `@`,
// and the restart blocking the skip to a later `@`
// ([`mask_boundary_stranded_a_tail`]). Neither test is "the token holds whitespace"; a
// space in a host (`alice:***@bad host:8080`) and two credentials in a row
// (`alice:***@proxy1 bob:***@proxy2`) are both still named, and the tests below pin that.
pub(crate) fn redact_offending_token(input: &str) -> String {
    let masked = redact_userinfo(input);
    if stranded_userinfo_shaped(&masked) || residual_credential_shaped(&masked) {
        return withheld_description(&masked);
    }
    masked.into_owned()
}

// After [`redact_userinfo`], whether a token still looks like it carries a credential.
//
// The `@`-free arm catches userinfo the mask never saw, because no `@` ended it. The `@`
// arm finds no unmasked credential on any input: it fires only where `before_at` spans an
// earlier, already masked `@`, and withholds a value that was already safe.
fn residual_credential_shaped(token: &str) -> bool {
    if mask_boundary_stranded_a_tail(token) {
        return true;
    }
    token.split([' ', '\t', '\n']).any(|piece| {
        let Some((before_at, _)) = piece.rsplit_once('@') else {
            return stranded_userinfo_shaped(piece);
        };
        let userinfo = after_scheme(before_at);
        userinfo_delimiter_end(userinfo).is_some_and(|end| &userinfo[end..] != MASK)
            && stranded_userinfo_shaped(before_at)
    })
}

// Whether the mask stopped at an `@` with the rest of a password still running on past it.
//
// [`redact_userinfo`] terminates a credential at the *last* `@` it can reach, so a password
// holding one does not survive, but it only skips to a later `@` across text holding no
// whitespace. `alice:se@cret pw@host` refuses the skip, masks at the first `@` instead, and
// leaves `cret pw`, the rest of the password, standing behind the boundary. Examined one
// whitespace-separated piece at a time nothing shows: `alice:***@cret` is masked and
// `pw@host` carries no delimiter. What names the shape is the *pair*: a piece carrying the
// mask's own `***@` boundary, and a later `@` with no userinfo of its own to explain it.
//
// The pair is also what keeps this from meaning "whitespace is withheld", which is what a
// coarser reading of it did. Two separate credentials (`alice:***@proxy1 bob:***@proxy2`)
// put userinfo in front of both `@`s, so neither is the stranded half of anything; a space
// in a host (`alice:***@bad host:8080`) leaves no second `@` at all. Both stay named.
fn mask_boundary_stranded_a_tail(token: &str) -> bool {
    let mut past_a_boundary = false;
    for piece in token.split([' ', '\t', '\n']) {
        if let Some((before_at, _)) = piece.rsplit_once('@')
            && past_a_boundary
            && userinfo_delimiter_end(after_scheme(before_at)).is_none()
        {
            return true;
        }
        past_a_boundary |= carries_a_mask_boundary(piece);
    }
    false
}

// Detect a boundary `redact_userinfo` wrote, using the delimiter and `MASK` together.
// A literal `***@` in input alone cannot prove a password tail is stranded.
fn carries_a_mask_boundary(piece: &str) -> bool {
    piece.match_indices("***@").any(|(at, _)| {
        // On bytes, not a `&str` slice: the last three bytes of arbitrary input need not
        // start a character, and `%3A` is ASCII wherever it appears.
        // Guarded rather than tested in the arm body: `alice%3:pw` ends with the literal
        // delimiter and also matches the encoded arm's *shape*, so deciding inside that
        // arm would answer for the whole match and never reach the literal one.
        match piece.as_bytes()[..at] {
            [.., b'%', b'3', hex] if hex.eq_ignore_ascii_case(&b'a') => true,
            [.., b':'] => true,
            _ => false,
        }
    })
}

// Whether a `:` survives in `token` outside the three places an address is allowed one:
// after the scheme, inside an IPv6 literal, and before the port.
fn stranded_userinfo_shaped(token: &str) -> bool {
    let rest = after_scheme(token);
    let rest = rest
        .rsplit_once('@')
        .map_or(rest, |(_, host_port)| host_port);
    // Dropping the path leaves nothing when the token starts with `/`: a scheme-relative
    // `//alice:hunter2` has its authority there. Examine it whole rather than examine "".
    let head = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let rest = if head.is_empty() { rest } else { head }.trim();
    if rest.parse::<std::net::Ipv6Addr>().is_ok() {
        return false;
    }
    // A trailing `:<digits>` is a port attempt however far out of range it is, a leading
    // `-` included (`h:-1`); the reason string [`invalid_port_reason`] builds for it
    // reads the same way.
    let host = match rest.rsplit_once(':') {
        Some((head, port)) => {
            let digits = port.strip_prefix('-').unwrap_or(port);
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                head
            } else {
                rest
            }
        }
        None => rest,
    };
    let host = strip_brackets(host);
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return false;
    }
    // `alice%3Ahunter2` is the same fragment spelled the other way, and neither a port nor
    // an IPv6 literal can hold a `%`.
    host.contains(':') || encoded_colon_at(host).is_some()
}

// Where the first user-name/password delimiter in `segment` *ends*, as a byte offset:
// everything up to the `@` should be masked from there.
pub(crate) fn userinfo_delimiter_end(segment: &str) -> Option<usize> {
    let literal = segment.find(':').map(|at| (at, at + 1));
    let encoded = encoded_colon_at(segment).map(|at| (at, at + 3));
    match (literal, encoded) {
        (Some(literal), Some(encoded)) => Some(if literal.0 <= encoded.0 {
            literal.1
        } else {
            encoded.1
        }),
        (found, None) | (None, found) => found.map(|(_, end)| end),
    }
}

// What follows a scheme's `://`.
fn after_scheme(token: &str) -> &str {
    scheme_delimiter_end(token).map_or(token, |end| &token[end..])
}

// Where a scheme's `://` ends in `token`, as a byte offset: the *first* one, and only
// when what precedes it could be a scheme. A scheme cannot hold a userinfo delimiter, so
// in `alice:pw://x` the `://` is inside the password; taking it as the boundary would
// leave the `user:` half in front of it, where nothing looks for it any more.
fn scheme_delimiter_end(token: &str) -> Option<usize> {
    let at = token.find("://")?;
    userinfo_delimiter_end(&token[..at])
        .is_none()
        .then_some(at + 3)
}

// Where a percent-encoded colon starts: the other spelling of the delimiter.
fn encoded_colon_at(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(2)).find(|&at| {
        bytes[at] == b'%' && bytes[at + 1] == b'3' && bytes[at + 2].eq_ignore_ascii_case(&b'a')
    })
}

// How much of an untrusted string is kept before it is truncated, and the character it
// truncates to.
#[cfg_attr(
    not(any(
        pac_quickjs,
        feature = "tracing",
        all(target_os = "linux", feature = "linux-gnome")
    )),
    allow(dead_code)
)]
pub(crate) const MAX_UNTRUSTED: usize = 256;

// How a single character of untrusted text is rendered: control characters (a newline
// above all, which would otherwise let hostile input forge extra log/error lines)
// become `.`; everything else passes through unchanged.
#[cfg_attr(
    not(any(
        pac_quickjs,
        feature = "tracing",
        all(target_os = "linux", feature = "linux-gnome")
    )),
    allow(dead_code)
)]
pub(crate) fn sanitized_char(c: char) -> char {
    if c.is_control() { '.' } else { c }
}

// Replace control characters with `.` and cut `input` off after [`MAX_UNTRUSTED`]
// characters, appending `…` when it was cut.
#[cfg_attr(
    not(any(
        pac_quickjs,
        feature = "tracing",
        all(target_os = "linux", feature = "linux-gnome")
    )),
    allow(dead_code)
)]
pub(crate) fn sanitize_untrusted(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_UNTRUSTED));
    for character in input.chars().take(MAX_UNTRUSTED) {
        out.push(sanitized_char(character));
    }
    if input.chars().nth(MAX_UNTRUSTED).is_some() {
        out.push('…');
    }
    out
}

// Mask the credentials in `input`, then render what is left safe to store: control
// characters to `.`, cut off after [`MAX_UNTRUSTED`] characters.
//
// The order is part of the result, which is why the callers that need both passes come here
// rather than composing them at the call site. [`redact_userinfo`] restarts its scan at
// whitespace, and `is_control` covers two of the three characters it restarts at, so
// masking first, a password holding a tab or a newline puts the `user:` half and the `@` on
// opposite sides of a restart and comes out unmasked, and the sanitising pass then prints
// it as `alice:my.pass@host`. Sanitising first, the tab is already the ordinary character
// the scan runs straight through, and the credential is masked. A plain space is not a
// control character and still splits the scan; that shape is the one the mask cannot reach
// at all, described above [`redact_userinfo`].
//
// Truncation stays last for the mirror-image reason: cutting to [`MAX_UNTRUSTED`] first
// could sever a `user:password` from the `@` that makes it recognisable, and leave the
// front of the password standing.
//
// The order has a price, and it is paid in the same coin the mask reads: a control
// character that was *separating* two credentials stops being one, so the pair collapses
// into a single span and the mask takes all of it, host names in the middle included
// (`alice:s1@h1\nbob:s2@h2` comes out `alice:***@h2`). Nothing can tell the two apart:
// the same byte is either half of a password or the gap between messages, so this fails
// toward masking, and the reader loses text rather than the credential surviving.
// `pac` rather than the engine features: every engine feature enables it,
// and `Error::pac_invalid_result` is built under either.
#[cfg_attr(
    not(any(feature = "pac", all(target_os = "linux", feature = "linux-gnome"))),
    allow(dead_code)
)]
pub(crate) fn redact_and_sanitize_untrusted(input: &str) -> String {
    let controls_replaced: String = input.chars().map(sanitized_char).collect();
    sanitize_untrusted(&redact_userinfo(&controls_replaced))
}

// FNV-1a, 64 bit. Not a cryptographic hash and not used as one: it only has to make
// "this is not the script from last time" visible without ever printing the script
// itself.
pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_cases() {
        assert_eq!(split_host_port("h:80"), Ok(("h", Some(80))));
        assert_eq!(split_host_port("h:"), Ok(("h", None)));
        assert_eq!(split_host_port("h"), Ok(("h", None)));
        assert_eq!(split_host_port("[::1]:8080"), Ok(("[::1]", Some(8080))));
        assert_eq!(split_host_port("[::1]"), Ok(("[::1]", None)));
        assert_eq!(split_host_port("::1"), Ok(("::1", None)));
        assert!(split_host_port("[::1").is_err());
        assert!(split_host_port("h:99999").is_err());
        assert!(split_host_port("h:abc").is_err());
    }

    // A port is `1*DIGIT` in both references this crate reads ports for: Chromium parses
    // a bypass rule's with `ParseInt32(…, NON_NEGATIVE)` and a proxy spec's with
    // `url::ParsePort`, but `u16::from_str` takes a sign as well, so `h:+80` is a spelling
    // this crate has to refuse itself; no reference honours it. Leading zeros are
    // the other half of the same grammar and stay legal ("0003 is valid and equivalent
    // to 3").
    #[test]
    fn a_signed_port_is_not_a_port_but_a_zero_padded_one_is() {
        assert!(split_host_port("h:+80").is_err());
        assert!(split_host_port("h:-80").is_err());
        assert_eq!(split_host_port("h:080"), Ok(("h", Some(80))));
        assert_eq!(split_host_port("h:00000"), Ok(("h", Some(0))));
    }

    // Regression test (security fix): do not build the port-parse failure reason as
    // `format!("invalid port {text:?}")`. That echoes back whatever sat past the last
    // `:`, and `endpoint.rs`/`bypass.rs` can both, on malformed input, hand that
    // position a stray password fragment rather than an actual port. A non-digit
    // "port" must never be echoed, only described.
    #[test]
    fn invalid_port_reason_never_leaks_fragments_and_still_diagnoses() {
        let secret = "secr3t-must-never-appear";
        let at_secret = "hunter2";

        let reason = split_host_port(&format!("bob:{secret}")).unwrap_err();
        assert!(!reason.contains(secret), "{reason}");
        assert!(reason.contains("character"), "{reason}");

        let reason = split_host_port(&format!("alice:{at_secret}@proxy.example")).unwrap_err();
        assert!(!reason.contains(at_secret), "{reason}");
        assert!(!reason.contains('@'), "{reason}");

        for (input, must_not_contain, must_contain) in [
            (
                "h:99999999999999999999",
                &["99999999999999999999"][..],
                &["20-digit", "out of the 0-65535 range"][..],
            ),
            (
                "h:abc",
                &[][..],
                &["3 characters", "0 ASCII digits", "3 other"][..],
            ),
        ] {
            let reason = split_host_port(input).unwrap_err();
            for fragment in must_not_contain {
                assert!(!reason.contains(fragment), "{reason}");
            }
            for fragment in must_contain {
                assert!(reason.contains(fragment), "{reason}");
            }
        }
    }

    #[test]
    fn glob_cases() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("192.168.*", "192.168.0.1"));
        assert!(!glob_match("192.168.*", "10.0.0.1"));
        assert!(glob_match("www.*.com", "www.example.com"));
        assert!(!glob_match("www.*.com", "www.example.org"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exacts"));
    }

    #[test]
    fn percent_decode_cases() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("p%40ss"), "p@ss");
        assert_eq!(percent_decode("100%"), "100%");
        // One hex digit short at the very end: the bound that keeps `bytes[i + 2]` in range
        // is exact here, and one past it panics.
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("p%4"), "p%4");
        assert_eq!(percent_decode("%zz"), "%zz");
        // Escapes that decode to bytes no `str` can hold. The comment above the function
        // promises the input comes back untouched, and no other assertion checks that
        // promise. What it costs to lose is a password. `parse_userinfo` hands this
        // straight to `ProxyAuth`, so a lossy read replaces the undecodable bytes with
        // U+FFFD and the crate then offers the proxy a secret the user never set: an
        // authentication failure with no hint of where the value changed, and one
        // `ProxyAuth`'s `Debug` masks out of any snapshot that might have shown it. Left
        // whole, the escape is still literally there for a caller that knows the encoding.
        assert_eq!(percent_decode("p%FFss"), "p%FFss");
        // The other half of the same rule: bytes that do form a `str` are decoded, so
        // returning the input whole is a fallback rather than the answer.
        assert_eq!(percent_decode("%E3%81%82"), "あ");
    }

    #[test]
    fn redact_userinfo_without_at_sign_is_borrowed_unchanged() {
        let input = "http://proxy.example:8080/pac.js";
        match redact_userinfo(input) {
            std::borrow::Cow::Borrowed(s) => assert_eq!(s, input),
            std::borrow::Cow::Owned(s) => panic!("expected a borrow, got an allocation: {s:?}"),
        }
    }

    #[test]
    fn redact_userinfo_masks_a_scheme_prefixed_url() {
        assert_eq!(
            redact_userinfo("http://alice:hunter2@proxy.corp:8080"),
            "http://alice:***@proxy.corp:8080"
        );
    }

    #[test]
    fn redact_userinfo_masks_without_a_scheme() {
        assert_eq!(
            redact_userinfo("alice:hunter2@proxy.corp:8080"),
            "alice:***@proxy.corp:8080"
        );
    }

    // A password may carry the mask's own boundary. Taking the *last* `://` in the token
    // put the boundary inside the password, left `alice:` in front of it where nothing
    // looks for a delimiter any more, and returned every row below verbatim: password
    // included. The second `@` broke the withhold pass on top of that: it reads the last
    // `@`, finds an ordinary `host:port` behind it, and lets the token through.
    #[test]
    fn redact_userinfo_masks_a_password_holding_a_scheme_delimiter() {
        for (input, expected) in [
            (
                "http://alice:aa://bb@proxy.corp:8080",
                "http://alice:***@proxy.corp:8080",
            ),
            ("alice:aa://bb@proxy.corp:8080", "alice:***@proxy.corp:8080"),
            (
                "http://alice:aa://bb@cc@proxy.corp:8080",
                "http://alice:***@proxy.corp:8080",
            ),
        ] {
            assert_eq!(redact_userinfo(input), expected, "{input}");
            assert_eq!(redact_offending_token(input), expected, "{input}");
        }
    }

    // A scheme in front of the token does not move that boundary onto the password: the
    // mask starts looking for one only past the whitespace, so the `user:` half of the
    // *second* address is what it finds.
    #[test]
    fn redact_userinfo_masks_a_scheme_bearing_address_after_a_credential_fragment() {
        assert_eq!(
            redact_userinfo("alice:pw http://bob:secret@proxy.corp:8080"),
            "alice:pw http://bob:***@proxy.corp:8080"
        );
    }

    // A bare `//` inside the password is not a scheme boundary; only `://` is.
    #[test]
    fn redact_userinfo_masks_a_password_holding_a_double_slash() {
        assert_eq!(
            redact_userinfo("http://alice:aa//bb@proxy.corp:8080"),
            "http://alice:***@proxy.corp:8080"
        );
    }

    // `redact_userinfo` needs an `@` to see userinfo, and a token only reaches an
    // `Error` `input` field because it *failed* to parse, possibly before the `@` it
    // never had. Every row below leaked its password through `Error`'s `Debug`.
    #[test]
    fn redact_offending_token_withholds_a_stranded_user_password_fragment() {
        for input in [
            "http://[bob:hunter2]:8080",
            "http://bob:hunter2",
            "bob:hunter2:more",
        ] {
            let masked = redact_offending_token(input);
            assert!(!masked.contains("hunter2"), "{masked}");
            assert!(masked.contains("withheld"), "{masked}");
        }
    }

    // Whitespace restarts the mask's scan past the `user:` half, so a password holding it
    // survives the mask. The withhold pass is what catches that, along with the shapes
    // that never reach the mask at all: no `@` for it to recognise userinfo by
    // (`alice:aa://bb`), an authority the token leads with (`//alice:…`), and a delimiter
    // spelled `%3A`.
    #[test]
    fn redact_offending_token_withholds_when_a_password_holds_a_boundary() {
        for (input, secret) in [
            ("alice:aa://bb", "aa://bb"),
            ("http://alice:my pass@proxy.corp:8080", "my pass"),
            ("//alice:my pass@proxy.corp:8080", "my pass"),
            ("//alice:hunter2", "hunter2"),
            ("alice%3Ahunter2", "hunter2"),
        ] {
            let masked = redact_offending_token(input);
            assert!(!masked.contains(secret), "{masked}");
            assert!(masked.contains("withheld"), "{masked}");
        }
    }

    // The other half of that trade: withholding must stay rare enough that an ordinary
    // bad address is still named, out-of-range port and IPv6 literal included.
    #[test]
    fn redact_offending_token_still_names_an_ordinary_address() {
        for input in [
            "http://proxy.corp:99999",
            "https=h:-1",
            "http://[::1]:8080",
            "proxy.corp",
            "::1",
            "//proxy.corp:8080",
            "/pac.js",
            "10.0.0.0/8",
            "bob@example.com",
        ] {
            assert_eq!(redact_offending_token(input), input);
        }
        assert_eq!(
            redact_offending_token("http://alice:hunter2@proxy.corp:99999"),
            "http://alice:***@proxy.corp:99999"
        );
    }

    #[test]
    fn redact_userinfo_leaves_a_colon_less_userinfo_alone() {
        let input = "alice@proxy.corp:8080";
        assert_eq!(redact_userinfo(input), input);
    }

    #[test]
    fn redact_userinfo_masks_every_occurrence() {
        // A password embedded in a redirect target must not survive just because it
        // isn't the last `@` in the string.
        let input = "http://alice:hunter2@proxy.corp/x?next=http://bob:swordfish@evil.example";
        assert_eq!(
            redact_userinfo(input),
            "http://alice:***@proxy.corp/x?next=http://bob:***@evil.example"
        );
    }

    #[test]
    fn redact_userinfo_masks_space_separated_occurrences() {
        let input = "alice:hunter2@proxy1 bob:swordfish@proxy2";
        assert_eq!(redact_userinfo(input), "alice:***@proxy1 bob:***@proxy2");
    }

    // A carriage return separates credential occurrences like the other three separators.
    // Without it, both secrets are masked but two occurrences merge into one credential:
    // `proxy1` and `bob` disappear without an error, making a two-proxy setting appear to
    // contain one.
    //
    // Only the occurrence-end separator set includes `\r`. Do not add it to the set that
    // bounds how far the mask reaches back: splitting `alice:pa\rss@host` there would
    // expose the whole credential because neither piece looks like one. Passwords
    // containing `\r` are masked; the other three whitespace characters already cause this
    // exposure. Symmetric separator sets would trade a lost hostname for a printed
    // password.
    #[test]
    fn redact_userinfo_reads_a_carriage_return_as_a_separator_too() {
        let input = "alice:hunter2@proxy1\rbob:swordfish@proxy2";
        assert_eq!(redact_userinfo(input), "alice:***@proxy1\rbob:***@proxy2");

        // The half that must not move.
        assert_eq!(redact_userinfo("alice:pa\rss@host"), "alice:***@host");
    }

    // A password holding a delimiter the scan stops at survives completely unmasked if the
    // scan restarts just past that delimiter, because it then never finds the `:` that came
    // before it. A bare `//` inside the password does the same to a scan that reads it as a
    // scheme's `://`. Whitespace in a password still defeats this function and is caught by
    // [`redact_offending_token`] instead.
    #[test]
    fn redact_userinfo_masks_password_delimiters() {
        for (input, expected) in [
            ("http://alice:hun/ter2@host", "http://alice:***@host"),
            ("http://alice:hun?ter2@host", "http://alice:***@host"),
            ("http://alice:hun&ter2@host", "http://alice:***@host"),
            ("http://alice:hun#ter2@host", "http://alice:***@host"),
            ("http://alice:aa//bb@host", "http://alice:***@host"),
            (
                "alice:hun/te?r&2#x@proxy.corp:8080",
                "alice:***@proxy.corp:8080",
            ),
        ] {
            assert_eq!(redact_userinfo(input), expected, "input = {input:?}");
        }
    }

    // Whitespace in the password restarts the mask past the `user:` half, so the
    // withhold pass must take the whole token, including a tab, which splits the
    // same way.
    #[test]
    fn redact_offending_token_withholds_whitespace_inside_a_password() {
        for input in [
            "http://alice:my pass@proxy.corp:8080",
            "http://alice:aa\tbb@proxy.corp:8080",
        ] {
            let masked = redact_offending_token(input);
            assert!(masked.contains("withheld"), "{masked}");
            assert!(
                !masked.contains('@') && !masked.contains("alice:"),
                "the raw credential survived: {masked}"
            );
        }
    }

    // A password holding an `@` is masked to the *last* one so the rest of it does not
    // survive; except that the skip to a later `@` is refused across whitespace, which
    // left the mask terminating at the first one and `cret pw` standing behind it. The
    // withhold pass could not see it either: it examined the whitespace-separated pieces
    // one at a time, and each of them looked clean (`alice:***@cret` is masked,
    // `pw@proxy.corp:8080` carries no delimiter) while half the password sat between
    // them. Reachable as a proxy URL pasted into a `no_proxy` list, which
    // `HostPattern::parse` rejects and records whole.
    #[test]
    fn redact_offending_token_withholds_a_password_holding_both_an_at_sign_and_a_space() {
        let masked = redact_offending_token("http://alice:se@cret pw@proxy.corp:8080");
        assert!(!masked.contains("cret pw"), "{masked}");
        assert!(masked.contains("withheld"), "{masked}");
    }

    // Two whole credentials separated by a space is not that shape either. "Whitespace
    // between two `@`" is not the mark of a stranded tail: it is also what two masked
    // credentials in a row look like. Nothing is stranded here: each `@` has its own
    // userinfo in front of it, and the mask reaches both, so withholding would hide two
    // addresses to protect nothing.
    #[test]
    fn redact_offending_token_still_names_two_credentials_separated_by_a_space() {
        assert_eq!(
            redact_offending_token("alice:hunter2@proxy1 bob:swordfish@proxy2"),
            "alice:***@proxy1 bob:***@proxy2"
        );
    }

    // Not every space beside an `@` is that shape, and the difference is which side of
    // the mask's boundary it falls on. Here it is in the host, where nothing is
    // stranded: the password is masked in full and what is left names the address the
    // caller needs to see. Withholding these is too wide.
    #[test]
    fn redact_offending_token_still_names_an_address_whose_host_holds_a_space() {
        assert_eq!(
            redact_offending_token("http://alice:hunter2@bad host:8080"),
            "http://alice:***@bad host:8080"
        );
    }

    // A bracketless IPv6 literal is the one host whose own text is nothing but colons, so
    // it is told apart from a stranded `user:` by parsing it rather than by counting them,
    // and a space on either side defeats the parse. Trimming first is what keeps
    // `socks= ::1` named; without it the literal falls through to the port split, `::` is
    // read as a colon left in front of the port `1`, and the token is withheld whole. The
    // padding survives into the answer because nothing here rewrites a token it decided
    // to name, which is the same reason the host-with-a-space test above keeps its space.
    //
    // Only this caller can reach the function with whitespace at all: the two inside
    // [`residual_credential_shaped`] hand it pieces that were split on it.
    // The two spellings of the delimiter have to answer alike wherever one of them would:
    // `alice%3Ahunter2` is `alice:hunter2` written the other way, and a reader who can
    // choose the spelling chooses the one that is not looked for. The end of the token is
    // where the search for the encoded spelling can stop early, because it is the only one
    // that needs bytes after its first. Narrow the scan by the one position that lets `%3A`
    // finish exactly at the end and `bob%3A:8080` is printed while `bob::8080` is withheld;
    // this test is what holds the two together.
    //
    // What that trailing delimiter can hide is an empty password rather than a secret, so
    // this holds the rule and not a leak. The rule is what makes the leak impossible to
    // reach by re-spelling.
    #[test]
    fn redact_offending_token_withholds_both_spellings_of_a_trailing_delimiter() {
        assert_eq!(
            redact_offending_token("bob::8080"),
            withheld_description("bob::8080")
        );
        assert_eq!(
            redact_offending_token("bob%3A:8080"),
            withheld_description("bob%3A:8080")
        );
    }

    // The disjunct [`residual_credential_shaped`] cannot stand in for, and which nothing
    // else reached. That one splits on whitespace and asks each piece, and a piece carrying
    // an `@` is judged only by the userinfo *in front of* it, which the mask has already
    // turned into `***`, so the conjunct short-circuits and the rest of the piece is never
    // examined. A token with no whitespace at all is one such piece, so the colon left
    // standing behind the `@` is invisible from there. Taken whole it is a `:` outside the
    // three places an address may have one, which is what `stranded_userinfo_shaped`
    // states, and `bob::8080`, the same colon with no `@` in front of it, is withheld by
    // [`redact_offending_token_withholds_both_spellings_of_a_trailing_delimiter`]. Without
    // the disjunct, and without this test, `http://alice:***@ho:st` is printed whole.
    #[test]
    fn redact_offending_token_withholds_a_colon_the_mask_left_behind_the_at_sign() {
        let masked = redact_offending_token("http://alice:pw@ho:st");
        assert!(masked.contains("withheld"), "{masked}");
        assert!(!masked.contains("ho:st"), "{masked}");
    }

    // [`residual_credential_shaped`]'s `@` arm doing the only thing it can do, which
    // nothing reached either. Two `@`s in one whitespace-free piece is the shape that gets
    // the first masked and the second not: the skip to a later `@` refuses across the
    // `//`, exactly as it does across whitespace, so `before_at` spans the earlier `@` and
    // holds a delimiter whose tail is not the mask, which is what the first conjunct asks.
    // Nothing leaked: the mask reached `pw` at the first `@` and `b` at the second, because
    // a delimiter *between* two `@`s always falls inside the span the later one masks from.
    // What is withheld here was already safe. Recorded as the behaviour rather than
    // defended as the intent: the arm is documented to catch a *leftover* credential and
    // after [`redact_userinfo`] there is no input that leaves it one.
    #[test]
    fn redact_offending_token_withholds_a_second_credential_it_had_already_masked() {
        let masked = redact_offending_token("alice:pw@//a:b@host");
        assert!(masked.contains("withheld"), "{masked}");
    }

    // The second conjunct of that same arm, which is what keeps the shape above from
    // taking every token with two `@`s in it. Here what stands behind the second `@` is an
    // address (`a//b`) and not a stranded `user:`, and only `stranded_userinfo_shaped` asks
    // the difference. Without it this is withheld too: too wide, in the way
    // [`redact_offending_token_still_names_a_padded_ipv6_literal`] and
    // [`redact_offending_token_masks_a_double_slash_inside_a_password`] refuse in their own
    // shapes.
    #[test]
    fn redact_offending_token_still_names_a_second_at_sign_the_mask_could_not_reach() {
        assert_eq!(
            redact_offending_token("alice:pw@a//b@host"),
            "alice:***@a//b@host"
        );
    }

    #[test]
    fn redact_offending_token_still_names_a_padded_ipv6_literal() {
        assert_eq!(redact_offending_token(" ::1 "), " ::1 ");
    }

    #[test]
    fn redact_offending_token_masks_a_double_slash_inside_a_password() {
        assert_eq!(
            redact_offending_token("http://alice:aa//bb@proxy.corp:8080"),
            "http://alice:***@proxy.corp:8080"
        );
    }

    #[test]
    fn redact_userinfo_masks_an_at_sign_in_the_password() {
        assert_eq!(
            redact_userinfo("http://alice:pa@ss@host"),
            "http://alice:***@host"
        );
        assert_eq!(
            redact_userinfo("alice:p@ssw@rd@proxy.corp:8080"),
            "alice:***@proxy.corp:8080"
        );
    }

    // An unrelated `@`-bearing string with no `:` before it must still come through
    // untouched, delimiter-laden password or not.
    #[test]
    fn redact_userinfo_leaves_an_email_like_string_alone() {
        let input = "contact foo@example.com/path?x=1";
        assert_eq!(redact_userinfo(input), input);
    }

    // Undecoded, a percent-encoded delimiter escapes the mask entirely, in both
    // spellings, and `Url::password()` agrees there is no password to find, so nothing
    // downstream catches it either.
    #[test]
    fn redact_userinfo_masks_a_percent_encoded_delimiter() {
        for input in [
            "http://alice%3Ahunter2@wpad.corp/proxy.pac",
            "http://alice%3ahunter2@wpad.corp/proxy.pac",
        ] {
            let masked = redact_userinfo(input);
            assert!(
                !masked.contains("hunter2"),
                "the secret survived masking: {masked}"
            );
            assert!(masked.contains("***"), "{masked}");
            assert!(masked.ends_with("@wpad.corp/proxy.pac"), "{masked}");
        }
    }

    // The *earlier* delimiter wins, whichever way it is spelt: a literal `:` after an
    // encoded one must not pull the mask's start rightwards past the encoded secret.
    #[test]
    fn redact_userinfo_masks_from_the_earlier_of_the_two_delimiters() {
        assert_eq!(
            redact_userinfo("http://alice%3Ahunter2:second@host"),
            "http://alice%3A***@host"
        );
        assert_eq!(
            redact_userinfo("http://alice:hunter2%3Asecond@host"),
            "http://alice:***@host"
        );
    }

    // A stray `%` near the end of a segment must not index past it. `%3` and a bare `%`
    // are not delimiters, so these carry no `:` at all and come through untouched.
    #[test]
    fn redact_userinfo_survives_a_truncated_percent_escape() {
        for input in ["http://alice%3@host", "http://alice%@host", "http://a%@h"] {
            assert_eq!(redact_userinfo(input), input);
        }
    }

    // A multi-byte character sharing the segment must not turn a byte index into a
    // panic: the scan works on bytes, and every byte it accepts is ASCII.
    #[test]
    fn redact_userinfo_handles_multibyte_text_around_the_delimiter() {
        assert_eq!(
            redact_userinfo("http://アリス%3Aひみつ@host"),
            "http://アリス%3A***@host"
        );
    }

    #[test]
    fn fnv1a_is_deterministic_and_sensitive_to_every_byte() {
        assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
        assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
        assert_ne!(fnv1a(b""), fnv1a(b"a"));
    }

    // Published FNV vectors pin the offset basis, prime, and fold order; comparisons
    // between calls to `fnv1a` cannot detect a shared arithmetic error.
    #[test]
    fn fnv1a_answers_the_published_vectors_for_the_algorithm_it_names() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    // The order of the two passes decides whether a control character inside a password
    // is a hole. Masking first, a tab sends `redact_userinfo`'s scan past the `user:`
    // half and nothing is masked; sanitising first, the tab is already a `.` (an
    // ordinary character the scan runs straight through) and the credential is masked.
    // Every row is text from outside: a PAC return, engine text, a `GError` message.
    #[test]
    fn redact_and_sanitize_masks_a_password_holding_a_control_character() {
        for (input, secret) in [
            ("connect to alice:my\tpass@host failed", "my.pass"),
            ("PROXY alice:my\npass@host:8080", "my.pass"),
        ] {
            let safe = redact_and_sanitize_untrusted(input);
            assert!(!safe.contains(secret), "{safe}");
            assert!(safe.contains("***"), "{safe}");
        }
    }

    // The other spelling of the one shape nothing in this crate masks. A literal space
    // inside userinfo is a hard boundary the mask may not reach back past, so
    // `alice:my pass@host` comes out whole in a sentence: the gap described above
    // [`redact_userinfo`]. What keeps that a documented gap rather than a leak is which
    // inputs can carry a credential *this crate holds*: those arrive quoted from a URI,
    // and a URI has no way to spell a raw space. `%20` is not in the boundary set, so it
    // is masked like any other password byte, and the shape that is left unmasked is one
    // whose spaces belong to the prose around it.
    //
    // Percent-decoding ahead of the mask (the symmetry `%3A`'s own handling invites) turns
    // this back into the boundary and prints `alice:my pass@host`. This test is what holds
    // the order.
    #[test]
    fn redact_and_sanitize_masks_a_percent_encoded_space_inside_a_password() {
        let safe = redact_and_sanitize_untrusted("PROXY http://alice:my%20pass@host:8080");
        assert!(!safe.contains("my%20pass"), "{safe}");
        assert!(!safe.contains("my pass"), "{safe}");
        assert_eq!(safe, "PROXY http://alice:***@host:8080");
    }

    // Both spellings of the delimiter mark a boundary, and a name ending in `%3` before a
    // literal one is not the encoded spelling however much it looks like it.
    #[test]
    fn redact_offending_token_reads_either_spelling_of_the_delimiter_as_a_boundary() {
        for input in [
            "http://alice:se@cret pw@proxy.corp:8080",
            "http://alice%3Ase@cret pw@proxy.corp:8080",
            "http://alice%3:se@cret pw@proxy.corp:8080",
        ] {
            let masked = redact_offending_token(input);
            assert!(masked.contains("withheld"), "{input} -> {masked}");
        }
    }

    // The boundary the withhold pass looks for has to be one the mask *wrote*, not any
    // `***@` the input happened to carry. Nothing here is a credential: no delimiter
    // anywhere, so there is nothing to protect by hiding the value, and the earlier
    // version hid it anyway: it read the bare `***@` as a mask boundary and then took
    // `noreply@host`, whose `@` has no userinfo, as the stranded tail behind it.
    #[test]
    fn redact_offending_token_still_names_a_value_whose_own_text_holds_three_stars() {
        assert_eq!(
            redact_offending_token("comment ***@ noreply@host"),
            "comment ***@ noreply@host"
        );
    }

    // What the ordering costs, stated rather than discovered later: a control character
    // that was separating two credentials is a separator the mask can no longer see, so
    // the two collapse into one span and the mask takes all of it: `host1` and `bob`
    // included. Both passwords are still hidden, which is the direction this has to fail
    // in; a space in the same place stays a separator and both addresses survive.
    #[test]
    fn redact_and_sanitize_masks_across_two_credentials_a_control_character_had_separated() {
        assert_eq!(
            redact_and_sanitize_untrusted("alice:secret1@host1\nbob:secret2@host2"),
            "alice:***@host2"
        );
        assert_eq!(
            redact_and_sanitize_untrusted("alice:secret1@host1 bob:secret2@host2"),
            "alice:***@host1 bob:***@host2"
        );
    }

    // Truncate after masking: cutting first can strand `user:password` before its `@`
    // and expose the password prefix.
    #[test]
    fn a_password_that_reaches_past_the_bound_is_masked_before_the_cut_can_take_its_at_sign() {
        let password = "s".repeat(MAX_UNTRUSTED);
        let safe = redact_and_sanitize_untrusted(&format!("alice:{password}@host"));
        assert_eq!(safe, "alice:***@host");
        // Not merely "shorter than the password": one surviving run of it is the leak.
        assert!(!safe.contains("ss"), "{safe}");
    }

    #[test]
    fn sanitize_untrusted_replaces_control_characters() {
        assert_eq!(sanitize_untrusted("a\nb\tc\rd"), "a.b.c.d");
        assert_eq!(sanitize_untrusted("plain text"), "plain text");
    }

    #[test]
    fn sanitize_untrusted_truncates_long_input() {
        let long = "y".repeat(MAX_UNTRUSTED + 100);
        let sanitized = sanitize_untrusted(&long);
        assert_eq!(sanitized.chars().count(), MAX_UNTRUSTED + 1);
        assert!(sanitized.ends_with('…'), "{sanitized}");
        assert!(!sanitized.contains("yyy…y"), "{sanitized}");
    }

    #[test]
    fn sanitize_untrusted_leaves_short_input_unmarked() {
        let short = "y".repeat(MAX_UNTRUSTED);
        assert_eq!(sanitize_untrusted(&short), short);
    }

    // Many later `@` signs can make repeated skip scans quadratic in input length.
    // An environment value reaches this path while building its rejection error.
    // Spaces keep the underlying per-`@` work constant, isolating the skip decision.
    #[test]
    fn a_pathological_token_does_not_stall_the_error_that_rejects_it() {
        let input = "@// ".repeat(40_000);
        let start = std::time::Instant::now();
        let masked = redact_offending_token(&input);
        let elapsed = start.elapsed();
        assert_eq!(masked.len(), input.len(), "the token came back changed");
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "masking {} bytes took {elapsed:?}",
            input.len()
        );
    }

    // Without spaces, the skip stops at `//` and each `@` reaches the prefix scans.
    // A PAC return can reach this path without a size cap; `MAX_UNTRUSTED` truncates
    // only after masking. Exercise both `redact_offending_token` and
    // `redact_and_sanitize_untrusted`, which enter through separate callers.
    #[test]
    fn the_same_token_without_spaces_does_not_stall_it_either() {
        let input = "@//".repeat(40_000);

        let start = std::time::Instant::now();
        let masked = redact_offending_token(&input);
        let elapsed = start.elapsed();
        assert_eq!(masked.len(), input.len(), "the token came back changed");
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "masking {} bytes took {elapsed:?}",
            input.len()
        );

        let start = std::time::Instant::now();
        let sentence = redact_and_sanitize_untrusted(&input);
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "sanitising {} bytes took {elapsed:?}",
            input.len()
        );
        // Nothing to mask and nothing to sanitise, so what comes back is the truncation.
        assert_eq!(sentence.chars().count(), MAX_UNTRUSTED + 1, "{sentence}");
    }
}
