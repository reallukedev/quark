//! Persistent rooms in SQLite: configuration, subject, avatar, affiliations and the recent
//! history shown to people joining. Temporary rooms never touch the database.

use crate::db::{params, Db, DbError, Migration, OptionalExtension};

use super::room::Affiliation;

pub static MIGRATION: Migration = Migration {
    module: "muc",
    steps: &["CREATE TABLE muc_rooms (
        service TEXT NOT NULL,
        room TEXT NOT NULL,
        config TEXT NOT NULL,
        subject TEXT,
        subject_nick TEXT,
        subject_at INTEGER,
        salt TEXT NOT NULL,
        creator TEXT,
        created INTEGER NOT NULL,
        vcard TEXT,
        PRIMARY KEY (service, room)
    ) WITHOUT ROWID;
    CREATE INDEX muc_rooms_by_creator ON muc_rooms (service, creator);
    CREATE TABLE muc_affiliations (
        service TEXT NOT NULL,
        room TEXT NOT NULL,
        jid TEXT NOT NULL,
        affiliation TEXT NOT NULL,
        reason TEXT,
        -- A nickname registered with the room (XEP-0045 §7.10), reserved for this person.
        nick TEXT,
        -- The nickname they last used, for mentions while they're away.
        last_nick TEXT,
        PRIMARY KEY (service, room, jid),
        FOREIGN KEY (service, room) REFERENCES muc_rooms (service, room) ON DELETE CASCADE
    ) WITHOUT ROWID;
    CREATE INDEX muc_affiliations_by_jid ON muc_affiliations (jid);
    CREATE TABLE muc_history (
        id INTEGER PRIMARY KEY,
        service TEXT NOT NULL,
        room TEXT NOT NULL,
        stamp INTEGER NOT NULL,
        sid TEXT NOT NULL,
        sender TEXT NOT NULL,
        xml TEXT NOT NULL,
        FOREIGN KEY (service, room) REFERENCES muc_rooms (service, room) ON DELETE CASCADE
    );
    CREATE INDEX muc_history_by_room ON muc_history (service, room, id);"],
};

/// The `muc_rooms` row.
#[derive(Debug, Clone)]
pub struct RoomRow {
    pub config: String,
    pub subject: Option<String>,
    pub subject_nick: Option<String>,
    pub subject_at: Option<i64>,
    pub salt: String,
    pub creator: Option<String>,
    pub created: i64,
    pub vcard: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AffRow {
    pub jid: String,
    pub affiliation: Affiliation,
    pub reason: Option<String>,
    pub nick: Option<String>,
    pub last_nick: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HistRow {
    pub stamp: i64,
    pub sid: String,
    pub sender: String,
    pub xml: String,
}

/// A whole room, as written when it becomes persistent and read when it's loaded.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub row: RoomRow,
    pub affiliations: Vec<AffRow>,
    pub history: Vec<HistRow>,
}

/// A change to a persistent room.
#[derive(Debug)]
pub enum Op {
    /// Writes the room from scratch (it was just created persistent, or became persistent).
    Snapshot(Box<Snapshot>),
    Room(Box<RoomRow>),
    /// Sets an affiliation; `Affiliation::None` removes the row.
    Affiliation(AffRow),
    /// Adds a message to the join history, keeping the newest `keep`.
    History {
        row: HistRow,
        keep: u32,
    },
    /// Drops a message from the join history (retracted or moderated).
    Unhistory {
        sid: String,
    },
    /// The room is gone or became temporary.
    Delete,
}

/// Applies `ops` to one room in a single transaction.
pub async fn apply(db: &Db, service: &str, room: &str, ops: Vec<Op>) -> Result<(), DbError> {
    if ops.is_empty() {
        return Ok(());
    }
    let (s, r) = (service.to_string(), room.to_string());
    db.write(move |t| {
        for op in ops {
            match op {
                Op::Snapshot(snap) => {
                    t.execute("DELETE FROM muc_rooms WHERE service = ?1 AND room = ?2", params![s, r])?;
                    write_row(t, &s, &r, &snap.row)?;
                    for a in &snap.affiliations {
                        write_affiliation(t, &s, &r, a)?;
                    }
                    let mut st = t.prepare_cached(
                        "INSERT INTO muc_history (service, room, stamp, sid, sender, xml) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?;
                    for h in &snap.history {
                        st.execute(params![s, r, h.stamp, h.sid, h.sender, h.xml])?;
                    }
                }
                Op::Room(row) => update_row(t, &s, &r, &row)?,
                Op::Affiliation(a) => write_affiliation(t, &s, &r, &a)?,
                Op::History { row, keep } => {
                    t.prepare_cached("INSERT INTO muc_history (service, room, stamp, sid, sender, xml) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
                        .execute(params![s, r, row.stamp, row.sid, row.sender, row.xml])?;
                    // Trim to the newest `keep`: the index makes this a short range scan.
                    t.prepare_cached(
                        "DELETE FROM muc_history WHERE service = ?1 AND room = ?2 AND id <= \
                         (SELECT id FROM muc_history WHERE service = ?1 AND room = ?2 ORDER BY id DESC LIMIT 1 OFFSET ?3)",
                    )?
                    .execute(params![s, r, keep])?;
                }
                Op::Unhistory { sid } => {
                    t.prepare_cached("DELETE FROM muc_history WHERE service = ?1 AND room = ?2 AND sid = ?3")?
                        .execute(params![s, r, sid])?;
                }
                Op::Delete => {
                    t.execute("DELETE FROM muc_rooms WHERE service = ?1 AND room = ?2", params![s, r])?;
                }
            }
        }
        Ok(())
    })
    .await
}

fn write_row(t: &rusqlite::Transaction<'_>, s: &str, r: &str, row: &RoomRow) -> rusqlite::Result<()> {
    t.prepare_cached(
        "INSERT INTO muc_rooms (service, room, config, subject, subject_nick, subject_at, salt, creator, created, vcard)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?
    .execute(params![
        s,
        r,
        row.config,
        row.subject,
        row.subject_nick,
        row.subject_at,
        row.salt,
        row.creator,
        row.created,
        row.vcard
    ])?;
    Ok(())
}

/// Updates an existing room only: a room destroyed meanwhile must not come back.
fn update_row(t: &rusqlite::Transaction<'_>, s: &str, r: &str, row: &RoomRow) -> rusqlite::Result<()> {
    t.prepare_cached(
        "UPDATE muc_rooms SET config = ?3, subject = ?4, subject_nick = ?5, subject_at = ?6, vcard = ?7 WHERE service = ?1 AND room = ?2",
    )?
    .execute(params![s, r, row.config, row.subject, row.subject_nick, row.subject_at, row.vcard])?;
    Ok(())
}

fn write_affiliation(t: &rusqlite::Transaction<'_>, s: &str, r: &str, a: &AffRow) -> rusqlite::Result<()> {
    if a.affiliation == Affiliation::None {
        t.prepare_cached("DELETE FROM muc_affiliations WHERE service = ?1 AND room = ?2 AND jid = ?3")?.execute(params![s, r, a.jid])?;
    } else {
        t.prepare_cached(
            "INSERT INTO muc_affiliations (service, room, jid, affiliation, reason, nick, last_nick) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (service, room, jid) DO UPDATE SET affiliation = excluded.affiliation, reason = excluded.reason,
                 nick = excluded.nick, last_nick = excluded.last_nick",
        )?
        .execute(params![s, r, a.jid, a.affiliation.as_str(), a.reason, a.nick, a.last_nick])?;
    }
    Ok(())
}

/// Reads a persistent room.
pub async fn load(db: &Db, service: &str, room: &str) -> Result<Option<Snapshot>, DbError> {
    let (s, r) = (service.to_string(), room.to_string());
    db.read(move |c| {
        let row = c
            .prepare_cached(
                "SELECT config, subject, subject_nick, subject_at, salt, creator, created, vcard FROM muc_rooms WHERE service = ?1 AND room = ?2",
            )?
            .query_row(params![s, r], |x| {
                Ok(RoomRow {
                    config: x.get(0)?,
                    subject: x.get(1)?,
                    subject_nick: x.get(2)?,
                    subject_at: x.get(3)?,
                    salt: x.get(4)?,
                    creator: x.get(5)?,
                    created: x.get(6)?,
                    vcard: x.get(7)?,
                })
            })
            .optional()?;
        let Some(row) = row else { return Ok(None) };
        let mut st = c.prepare_cached("SELECT jid, affiliation, reason, nick, last_nick FROM muc_affiliations WHERE service = ?1 AND room = ?2")?;
        let affiliations = st
            .query_map(params![s, r], |x| {
                let aff: String = x.get(1)?;
                Ok(AffRow {
                    jid: x.get(0)?,
                    affiliation: Affiliation::parse(&aff).unwrap_or(Affiliation::None),
                    reason: x.get(2)?,
                    nick: x.get(3)?,
                    last_nick: x.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut st = c.prepare_cached("SELECT stamp, sid, sender, xml FROM muc_history WHERE service = ?1 AND room = ?2 ORDER BY id")?;
        let history = st
            .query_map(params![s, r], |x| Ok(HistRow { stamp: x.get(0)?, sid: x.get(1)?, sender: x.get(2)?, xml: x.get(3)? }))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(Snapshot { row, affiliations, history }))
    })
    .await
}

/// Every persistent room on a service, with its configuration (JSON).
pub async fn list(db: &Db, service: &str) -> Result<Vec<(String, String)>, DbError> {
    let s = service.to_string();
    db.read(move |c| {
        let mut st = c.prepare_cached("SELECT room, config FROM muc_rooms WHERE service = ?1 ORDER BY room")?;
        let rows = st.query_map([s], |x| Ok((x.get(0)?, x.get(1)?)))?;
        rows.collect()
    })
    .await
}

/// Persistent rooms someone created on a service (for the per-person limit).
pub async fn count_created_by(db: &Db, service: &str, creator: &str) -> Result<usize, DbError> {
    let (s, c) = (service.to_string(), creator.to_string());
    db.read(move |x| {
        x.prepare_cached("SELECT COUNT(*) FROM muc_rooms WHERE service = ?1 AND creator = ?2")?
            .query_row(params![s, c], |r| r.get::<_, i64>(0))
    })
    .await
    .map(|n| usize::try_from(n).unwrap_or(0))
}

/// Removes an account's affiliations everywhere (the account is gone).
pub async fn forget(db: &Db, jid: &str) -> Result<(), DbError> {
    let j = jid.to_string();
    db.write(move |t| t.execute("DELETE FROM muc_affiliations WHERE jid = ?1", [j])).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> RoomRow {
        RoomRow {
            config: "{}".into(),
            subject: Some("hi".into()),
            subject_nick: None,
            subject_at: None,
            salt: "s".into(),
            creator: Some("a@x".into()),
            created: 1,
            vcard: None,
        }
    }

    fn hist(n: i64) -> HistRow {
        HistRow { stamp: n, sid: format!("s{n}"), sender: "a@x".into(), xml: "<message/>".into() }
    }

    #[tokio::test]
    async fn rooms_round_trip_and_history_is_trimmed() {
        let db = Db::memory().unwrap();
        db.migrate(&[&MIGRATION]).unwrap();
        let aff = AffRow { jid: "a@x".into(), affiliation: Affiliation::Owner, reason: None, nick: Some("al".into()), last_nick: None };
        let snap = Snapshot { row: row(), affiliations: vec![aff], history: vec![] };
        apply(&db, "rooms.x", "r", vec![Op::Snapshot(Box::new(snap))]).await.unwrap();
        for n in 0..5 {
            apply(&db, "rooms.x", "r", vec![Op::History { row: hist(n), keep: 3 }]).await.unwrap();
        }
        apply(&db, "rooms.x", "r", vec![Op::Unhistory { sid: "s3".into() }]).await.unwrap();
        let back = load(&db, "rooms.x", "r").await.unwrap().unwrap();
        assert_eq!(back.row.subject.as_deref(), Some("hi"));
        assert_eq!(back.affiliations[0].affiliation, Affiliation::Owner);
        assert_eq!(back.history.iter().map(|h| h.stamp).collect::<Vec<_>>(), vec![2, 4]);
        assert_eq!(count_created_by(&db, "rooms.x", "a@x").await.unwrap(), 1);
        assert_eq!(list(&db, "rooms.x").await.unwrap().len(), 1);

        let none = AffRow { jid: "a@x".into(), affiliation: Affiliation::None, reason: None, nick: None, last_nick: None };
        apply(&db, "rooms.x", "r", vec![Op::Affiliation(none)]).await.unwrap();
        assert!(load(&db, "rooms.x", "r").await.unwrap().unwrap().affiliations.is_empty());

        apply(&db, "rooms.x", "r", vec![Op::Delete]).await.unwrap();
        assert!(load(&db, "rooms.x", "r").await.unwrap().is_none());
        let left: i64 = db.read(|c| c.query_row("SELECT COUNT(*) FROM muc_history", [], |r| r.get(0))).await.unwrap();
        assert_eq!(left, 0, "history goes with the room");
    }
}
