//! `EVENT` messages parsed straight into an [`Event`].
//!
//! Most of what a relay sends is `["EVENT", <subscription id>, <event>]`. Its plain spelling is
//! parsed here with `nostr-parse`, in one pass and without serde's intermediate types. Anything
//! else returns `None` and goes through [`RelayMessage::from_json`] as before, errors included:
//! another message type, an escaped subscription id, extra array elements, an event `nostr-parse`
//! refuses, or one an [`Event`] cannot hold (an empty tag, an empty signature). So this path
//! only ever yields the event `from_json` would have.
//!
//! [`RelayMessage::from_json`]: nostr::message::RelayMessage::from_json

use std::cell::RefCell;

use nostr::prelude::{Event, EventId, Kind, PublicKey, Signature, SubscriptionId, Tag, Timestamp};

thread_local! {
    // Scratch space reused across messages; nothing in it outlives a parse.
    static PARSER: RefCell<nostr_parse::Parser> = RefCell::new(nostr_parse::Parser::new());
}

#[cfg(test)]
pub(super) static DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The subscription id and event of an `EVENT` message in its plain spelling, or `None`.
///
/// `msg` is already trimmed.
pub(super) fn parse_event_message(msg: &str) -> Option<(SubscriptionId, Event)> {
    #[cfg(test)]
    if DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }

    let bytes: &[u8] = msg.as_bytes();
    let mut pos: usize = 0;
    eat(bytes, &mut pos, b"[")?;
    eat(bytes, &mut pos, b"\"EVENT\"")?;
    eat(bytes, &mut pos, b",")?;
    eat(bytes, &mut pos, b"\"")?;

    let start: usize = pos;
    let len: usize = bytes[start..]
        .iter()
        .position(|&b| b == b'"' || b == b'\\' || b < 0x20)?;
    pos = start + len;
    if bytes[pos] != b'"' {
        return None;
    }
    let subscription_id: &str = &msg[start..pos];
    pos += 1;
    eat(bytes, &mut pos, b",")?;

    // The event runs to the closing bracket: with more elements after it, the slice is not
    // one object and `nostr-parse` refuses it.
    let body: &str = msg.strip_suffix(']')?.get(pos..)?;
    let parsed: nostr_parse::Event = PARSER.with(|p| p.borrow_mut().parse(body)).ok()?;

    let sig: Signature = Signature::from_byte_array(parsed.sig?);
    let mut tags: Vec<Tag> = Vec::with_capacity(parsed.tags.len());
    for tag in parsed.tags {
        // Moves the strings; refuses an empty tag, as deserializing one does.
        tags.push(Tag::parse(tag).ok()?);
    }

    let event: Event = Event::new(
        EventId::from_byte_array(parsed.id),
        PublicKey::from_byte_array(parsed.pubkey),
        Timestamp::from_secs(parsed.created_at),
        Kind::from_u16(parsed.kind),
        tags,
        parsed.content,
        sig,
    );
    Some((SubscriptionId::new(subscription_id), event))
}

/// Skips JSON whitespace, then `token`.
fn eat(bytes: &[u8], pos: &mut usize, token: &[u8]) -> Option<()> {
    while let Some(b' ' | b'\t' | b'\n' | b'\r') = bytes.get(*pos) {
        *pos += 1;
    }
    if bytes.get(*pos..)?.starts_with(token) {
        *pos += token.len();
        Some(())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use nostr::message::RelayMessage;

    use super::*;

    const ID: &str = "70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5";
    const PUBKEY: &str = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";
    const SIG: &str = "273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502";

    fn event_json(fields: &str) -> String {
        format!(
            r#"{{"id":"{ID}","pubkey":"{PUBKEY}","created_at":1612809991,"kind":1,{fields},"sig":"{SIG}"}}"#
        )
    }

    fn message(sid: &str, event: &str) -> String {
        format!(r#"["EVENT","{sid}",{event}]"#)
    }

    /// Whenever the fast path answers, the message codec gives the same subscription id and the
    /// same event, field for field.
    fn agrees(msg: &str) -> bool {
        let Some((sid, event)) = parse_event_message(msg.trim()) else {
            return false;
        };
        match RelayMessage::from_json(msg.trim()) {
            Ok(RelayMessage::Event {
                subscription_id,
                event: expected,
            }) => {
                assert_eq!(*subscription_id, sid, "{msg}");
                assert_eq!(expected.id, event.id, "{msg}");
                assert_eq!(expected.as_json(), event.as_json(), "{msg}");
                true
            }
            other => panic!("the fast path accepted what the codec gives as {other:?}: {msg}"),
        }
    }

    fn variants() -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for fields in [
            r#""tags":[],"content":"test""#,
            r#""tags":[["e","abc"],["p","def","wss://r","mention"]],"content":"hi""#,
            r#""tags":[["t"]],"content":"one-field tag""#,
            r#""tags":[[]],"content":"empty tag""#,
            r#""tags":[["e",1]],"content":"number in a tag""#,
            r#""tags":[],"content":"esc \" \\ \/ \b\f\n\r\t \u0041\u00e9\ud83d\ude00""#,
            r#""tags":[["a","\u0000"]],"content":"nul in a tag""#,
            r#""tags":[],"content":"x","extra":{"nested":[1,2,{"a":null}]}"#,
            r#""tags":[],"content":"dup","content":"again""#,
            r#""tags":[],"tags":[],"content":"dup tags""#,
            r#""tags":[]"#,
            r#""content":"no tags""#,
            r#""tags":null,"content":"null tags""#,
            r#""tags":[],"content":null"#,
        ] {
            out.push(message("sub", &event_json(fields)));
        }

        let base: String = event_json(r#""tags":[["e","abc"]],"content":"base""#);
        let replace = |from: &str, to: &str| message("sub", &base.replacen(from, to, 1));
        out.push(replace(r#""kind":1"#, r#""kind":65535"#));
        out.push(replace(r#""kind":1"#, r#""kind":65536"#));
        out.push(replace(r#""kind":1"#, r#""kind":-1"#));
        out.push(replace(r#""kind":1"#, r#""kind":1.0"#));
        out.push(replace(r#""kind":1"#, r#""kind":1e2"#));
        out.push(replace(r#""kind":1"#, r#""kind":"1""#));
        out.push(replace(r#""created_at":1612809991"#, r#""created_at":0"#));
        out.push(replace(
            r#""created_at":1612809991"#,
            r#""created_at":18446744073709551615"#,
        ));
        out.push(replace(
            r#""created_at":1612809991"#,
            r#""created_at":18446744073709551616"#,
        ));
        out.push(replace(r#""created_at":1612809991"#, r#""created_at":-5"#));
        out.push(replace(ID, &ID.to_uppercase()));
        out.push(replace(PUBKEY, &PUBKEY.to_uppercase()));
        out.push(replace(SIG, &SIG.to_uppercase()));
        out.push(replace(&format!(r#""sig":"{SIG}""#), r#""sig":"""#));
        out.push(replace(ID, &ID[..62]));
        out.push(replace(&ID[..2], r"\u0037\u0030"));
        out.push(replace(
            PUBKEY,
            "npub1x70gv05r2utrtw7wt5ng3hz0rhxz65zjyta96ax6cq8nq5ma0hlqp9cvnc",
        ));

        // The envelope.
        out.push(base.clone());
        out.push(format!(r#"[ "EVENT" , "s p" , {base} ]"#));
        out.push(format!("[\n\t\"EVENT\",\r\n\"sub\",\n{base}\n]"));
        out.push(format!(r#"["EVENT","",{base}]"#));
        out.push(format!(r#"["EVENT","a\"b",{base}]"#));
        out.push(format!(r#"["EVENT","\u0061",{base}]"#));
        out.push(format!(r#"["EVENT","sub",{base},"extra"]"#));
        out.push(format!(r#"["EVENT","sub",{base},{base}]"#));
        out.push(format!(r#"["EVENT","sub",{base}"#));
        out.push(format!(r#"["EVENT","sub",{base}]]"#));
        out.push(format!(r#"["EVENT","sub",{base}] x"#));
        out.push(format!(r#"["EVENT",1,{base}]"#));
        out.push(format!(r#"["EVENTS","sub",{base}]"#));
        out.push(r#"["EOSE","sub"]"#.to_owned());
        out.push(r#"["EVENT","sub"]"#.to_owned());
        out.push(r#"["EVENT","sub",]"#.to_owned());
        out.push(r#"["EVENT"]"#.to_owned());
        out.push(r#"["EVENT","#.to_owned());
        out
    }

    #[test]
    fn answers_only_with_what_the_codec_gives() {
        let mut answered: usize = 0;
        for msg in variants() {
            if agrees(&msg) {
                answered += 1;
            }
        }
        // The plain spellings: six field sets, kind 65535, created_at 0 and u64::MAX, an id
        // spelled with escapes, and three envelopes. The rest are left to the codec.
        assert_eq!(answered, 13);
    }

    #[test]
    fn leaves_events_an_event_cannot_hold_to_the_codec() {
        let empty_tag: String = message("sub", &event_json(r#""tags":[["e"],[]],"content":"x""#));
        let unsigned: String = message(
            "sub",
            &event_json(r#""tags":[],"content":"x""#).replace(SIG, ""),
        );
        let escaped_sid: String = message(r"a\nb", &event_json(r#""tags":[],"content":"x""#));
        for msg in [empty_tag, unsigned, escaped_sid] {
            assert!(parse_event_message(&msg).is_none(), "{msg}");
        }
    }

    /// Byte-level mutations of valid messages: the fast path may refuse anything, but what it
    /// accepts must be exactly what the codec gives.
    #[test]
    fn mutated_messages_never_disagree() {
        let seeds: Vec<String> = variants()
            .into_iter()
            .filter(|m| parse_event_message(m).is_some())
            .collect();
        let alphabet: &[u8] = b"{}[]\",:\\ 0123456789abcdefABCDEFeEnulltrue-.+/u\n\t";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200_000 {
            let seed: &String = &seeds[(next() % seeds.len() as u64) as usize];
            let mut bytes: Vec<u8> = seed.as_bytes().to_vec();
            for _ in 0..(1 + next() % 3) {
                let at: usize = (next() % bytes.len() as u64) as usize;
                let b: u8 = alphabet[(next() % alphabet.len() as u64) as usize];
                match next() % 3 {
                    0 => bytes[at] = b,
                    1 => bytes.insert(at, b),
                    _ => {
                        bytes.remove(at);
                    }
                }
            }
            if let Ok(msg) = String::from_utf8(bytes) {
                agrees(&msg);
            }
        }
    }

    /// Every event of a nostrJsonBench corpus (`NOSTR_CORPUS=<dir>`), each wrapped in an `EVENT`
    /// message: the fast path must take every signed one and agree with the codec.
    #[test]
    #[ignore]
    fn agrees_with_the_codec_on_a_corpus() {
        let dir: String = std::env::var("NOSTR_CORPUS").expect("NOSTR_CORPUS");
        let text: String = std::fs::read_to_string(format!("{dir}/all.ndjson")).unwrap();
        let (mut taken, mut unsigned) = (0usize, 0usize);
        for line in text.lines().filter(|l| !l.is_empty()) {
            let msg: String = message("sub", line);
            if agrees(&msg) {
                taken += 1;
            } else {
                assert!(
                    line.contains(r#""sig":"""#),
                    "refused a signed event: {line}"
                );
                unsigned += 1;
            }
        }
        println!("{taken} taken, {unsigned} unsigned left to the codec");
    }
}
