//! Minimal nf_tables netlink layer for the subnet-router NAT rules.
//!
//! Everything noeio needs from netfilter fits in one dedicated table:
//!
//! ```text
//! table ip noeio {
//!     chain postrouting { type nat hook postrouting priority 100;
//!         ip saddr <overlay> oifname <lan> masquerade }
//!     chain forward { type filter hook forward priority 0;
//!         iifname <tun> oifname <lan> accept
//!         iifname <lan> oifname <tun> ct state established,related accept }
//!     chain mssclamp { type filter hook forward priority -150;
//!         iifname <tun> tcp flags syn tcp option maxseg size set rt mtu
//!         oifname <tun> tcp flags syn tcp option maxseg size set rt mtu }
//! }
//! ```
//!
//! The table is rebuilt whole (delete + create in one batch) rather than
//! diffed, and deleted whole on shutdown and at start-up. That makes it
//! idempotent without a state file, and a dedicated table can't collide with
//! `iptables-nft`'s `nat` / `filter` / `mangle` tables.
//!
//! Encoding is done with `netlink-packet-netfilter` (MIT, pure Rust, no C
//! library, no `nft` binary). Expressions the crate has no type for (`masq`,
//! `ct`, `rt`, `byteorder`, `exthdr`) are emitted through
//! `Expressions::Other` with hand-encoded attributes taken from the kernel's
//! `nf_tables.h`; the byte-level tests below pin those encodings.
//!
//! `rustables` would have been the obvious crate for this but is GPL-3.0,
//! which this Apache-2.0 project cannot link. `nftnl` links `libnftnl` /
//! `libmnl` through pkg-config, which the musl cross build cannot provide.

use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_netfilter::nftables::{
    Bitwise, ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions,
    Hook, Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator,
    Payload, Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict,
    VerdictAttribute,
};
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use std::io;
use std::net::Ipv4Addr;

/// The one table noeio owns. Never `nat` / `filter` / `mangle`: those belong
/// to `iptables-nft`.
pub const TABLE: &str = "noeio";
pub const CHAIN_POSTROUTING: &str = "postrouting";
pub const CHAIN_FORWARD: &str = "forward";
pub const CHAIN_MSSCLAMP: &str = "mssclamp";

/// Hook priorities, matching the legacy iptables tables they stand in for so
/// ordering against an `iptables-nft` install is predictable.
const PRIO_SRCNAT: i32 = 100;
const PRIO_FILTER: i32 = 0;
const PRIO_MANGLE: i32 = -150;

/// Longest interface name the kernel accepts (`IFNAMSIZ - 1`).
pub const IFNAMSIZ_MAX: usize = 15;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NETLINK_NETFILTER: isize = 12;

/// `NF_ACCEPT` as a verdict code (the crate's `Verdict` enum covers only the
/// nft-internal codes; kernel verdicts are plain `NF_*` values).
const NF_ACCEPT: u32 = 1;

/// `NFT_REG_1` as the big-endian u32 attribute value used by the hand-encoded
/// expressions.
const REG1_BE: [u8; 4] = 1u32.to_be_bytes();

// nf_tables.h attribute numbers for expressions the crate has no type for.
const NFTA_MASQ_FLAGS: u16 = 1;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
const NFTA_RT_DREG: u16 = 1;
const NFTA_RT_KEY: u16 = 2;
const NFT_RT_TCPMSS: u32 = 3;
const NFTA_BYTEORDER_SREG: u16 = 1;
const NFTA_BYTEORDER_DREG: u16 = 2;
const NFTA_BYTEORDER_OP: u16 = 3;
const NFTA_BYTEORDER_LEN: u16 = 4;
const NFTA_BYTEORDER_SIZE: u16 = 5;
const NFT_BYTEORDER_HTON: u32 = 1;
#[allow(dead_code)]
const NFTA_EXTHDR_DREG: u16 = 1;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
const TCPOPT_MAXSEG: u32 = 2;
/// `ct state established | related` bitmask (`NF_CT_STATE_BIT(...)`).
const CT_STATE_ESTABLISHED_RELATED: u32 = 0x6;
const PAYLOAD_BASE_NETWORK: u32 = 1;
const PAYLOAD_BASE_TRANSPORT: u32 = 2;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAG_SYN: u8 = 0x02;

/// What the table should contain. Everything is validated in [`Ruleset::new`]
/// so the encoder never sees an unbounded string (NF-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// Overlay source range to masquerade.
    pub overlay: (Ipv4Addr, u8),
    /// Interface facing the LAN (SNAT egress).
    pub lan_if: String,
    /// The noeio TUN.
    pub tun_if: String,
    /// Install the MSS clamp chain.
    pub mss_clamp: bool,
}

impl Ruleset {
    pub fn new(
        overlay: (Ipv4Addr, u8),
        lan_if: &str,
        tun_if: &str,
        mss_clamp: bool,
    ) -> io::Result<Self> {
        check_ifname(lan_if)?;
        check_ifname(tun_if)?;
        if overlay.1 > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("prefix /{} is out of range", overlay.1),
            ));
        }
        Ok(Self {
            overlay,
            lan_if: lan_if.to_string(),
            tun_if: tun_if.to_string(),
            mss_clamp,
        })
    }
}

fn check_ifname(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > IFNAMSIZ_MAX
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{name}' is not a valid interface name"),
        ));
    }
    Ok(())
}

/// Why a netfilter operation failed, mapped to the action the operator needs
/// to take (NF-5).
#[derive(Debug)]
pub enum NfError {
    /// No `CAP_NET_ADMIN` in this network namespace.
    Permission(io::Error),
    /// nf_tables NAT support is missing: the `nft_masq` / `nf_nat` modules
    /// are not loaded and cannot be auto-loaded from here (typical in an
    /// unprivileged container).
    NatUnsupported(io::Error),
    /// nf_tables itself is unavailable (kernel too old or `NF_TABLES` off).
    Unsupported(io::Error),
    Other(io::Error),
}

impl std::fmt::Display for NfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permission(e) => write!(
                f,
                "netfilter: permission denied ({e}). noeio needs CAP_NET_ADMIN in its own network namespace to act as a subnet router"
            ),
            Self::NatUnsupported(e) => write!(
                f,
                "netfilter: NAT chain rejected ({e}). The kernel could not load nf_tables NAT support; run `modprobe nft_masq nf_nat nft_ct` on the host (a container cannot load modules itself)"
            ),
            Self::Unsupported(e) => write!(
                f,
                "netfilter: nf_tables unavailable ({e}). Linux >= 4.18 with NF_TABLES, NF_TABLES_IPV4, NF_TABLES_NAT, NFT_MASQ and NFT_CT is required to act as a subnet router"
            ),
            Self::Other(e) => write!(f, "netfilter: {e}"),
        }
    }
}

impl std::error::Error for NfError {}

impl From<NfError> for io::Error {
    fn from(e: NfError) -> Self {
        let kind = match &e {
            NfError::Permission(_) => io::ErrorKind::PermissionDenied,
            NfError::NatUnsupported(_) | NfError::Unsupported(_) => io::ErrorKind::Unsupported,
            NfError::Other(inner) => inner.kind(),
        };
        io::Error::new(kind, e.to_string())
    }
}

type NfMsg = NetlinkMessage<NetfilterMessage>;

fn nf(family: NetfilterProtoFamily, inner: NfTablesMessage, flags: u16) -> NfMsg {
    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(NetfilterMessage::new(
            NetfilterHeader::new(family, 0, 0),
            inner,
        )),
    );
    msg.header.flags = NLM_F_REQUEST | flags;
    msg
}

fn batch_control(kind: ControlMessage) -> NfMsg {
    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(NetfilterMessage::new(
            // res_id must be the nftables subsystem or the batch is silently
            // ignored.
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFNL_SUBSYS_NFTABLES),
            kind,
        )),
    );
    msg.header.flags = NLM_F_REQUEST;
    msg
}

// ---- message builders -------------------------------------------------------

pub(crate) fn new_table() -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::NewTable(TableMessage {
            attributes: vec![TableAttribute::Name(TABLE.into())],
        }),
        NLM_F_CREATE | NLM_F_ACK,
    )
}

pub(crate) fn del_table() -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::DeleteTable(TableMessage {
            attributes: vec![TableAttribute::Name(TABLE.into())],
        }),
        NLM_F_ACK,
    )
}

pub(crate) fn get_table() -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::GetTable(TableMessage {
            attributes: vec![TableAttribute::Name(TABLE.into())],
        }),
        NLM_F_ACK,
    )
}

pub(crate) fn dump_chains() -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::GetChain(ChainMessage {
            attributes: vec![ChainAttribute::Table(TABLE.into())],
        }),
        NLM_F_DUMP,
    )
}

pub(crate) fn dump_rules() -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::GetRule(RuleMessage {
            attributes: vec![RuleAttribute::Table(TABLE.into())],
        }),
        NLM_F_DUMP,
    )
}

pub(crate) fn new_base_chain(
    name: &str,
    chain_type: &str,
    hook: InetHookNumber,
    priority: i32,
) -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::NewChain(ChainMessage {
            attributes: vec![
                ChainAttribute::Table(TABLE.into()),
                ChainAttribute::Name(name.into()),
                ChainAttribute::Policy(NF_ACCEPT),
                ChainAttribute::Type(chain_type.into()),
                ChainAttribute::Hook(vec![
                    Hook::Number(hook.into()),
                    Hook::Priority(priority as u32),
                ]),
            ],
        }),
        NLM_F_CREATE | NLM_F_ACK,
    )
}

fn new_rule(chain: &str, exprs: Vec<Expressions>) -> NfMsg {
    nf(
        NetfilterProtoFamily::IPv4,
        NfTablesMessage::NewRule(RuleMessage {
            attributes: vec![
                RuleAttribute::Table(TABLE.into()),
                RuleAttribute::Chain(chain.into()),
                RuleAttribute::Expressions(exprs.into_iter().map(Into::into).collect()),
            ],
        }),
        NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK,
    )
}

// ---- expression helpers -----------------------------------------------------

/// `IFNAMSIZ`-padded, NUL-terminated interface name as nft compares it.
fn ifname_bytes(name: &str) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.resize(16, 0);
    v
}

fn match_ifname(key: MetaKey, name: &str) -> [Expressions; 2] {
    [
        Expressions::Meta(vec![
            Meta::Key(key),
            Meta::DestinationRegister(Register::Reg1),
        ]),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(ifname_bytes(name))),
        ]),
    ]
}

/// `ip saddr <net>/<prefix>`: load the 4-byte source address, mask, compare.
fn match_saddr(net: Ipv4Addr, prefix: u8) -> Vec<Expressions> {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = u32::from(net) & mask;
    vec![
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(PAYLOAD_BASE_NETWORK),
            Payload::Offset(12),
            Payload::Len(4),
        ]),
        Expressions::Bitwise(vec![
            Bitwise::SourceRegister(Register::Reg1),
            Bitwise::DestinationRegister(Register::Reg1),
            Bitwise::Length(4),
            Bitwise::Mask(DataAttribute::Value(mask.to_be_bytes().to_vec())),
            Bitwise::Xor(DataAttribute::Value(vec![0; 4])),
        ]),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(net.to_be_bytes().to_vec())),
        ]),
    ]
}

fn accept() -> Expressions {
    Expressions::Immediate(vec![
        Immediate::DestinationRegister(Register::Verdict),
        Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
            Verdict::Other(NF_ACCEPT),
        )])),
    ])
}

fn masquerade() -> Expressions {
    Expressions::Other {
        expression_type: "masq".into(),
        attributes: vec![DefaultNla::new(
            NFTA_MASQ_FLAGS,
            0u32.to_be_bytes().to_vec(),
        )],
    }
}

/// `ct state established,related`.
fn match_ct_established_related() -> Vec<Expressions> {
    vec![
        Expressions::Other {
            expression_type: "ct".into(),
            attributes: vec![
                DefaultNla::new(NFTA_CT_DREG, REG1_BE.to_vec()),
                DefaultNla::new(NFTA_CT_KEY, NFT_CT_STATE.to_be_bytes().to_vec()),
            ],
        },
        Expressions::Bitwise(vec![
            Bitwise::SourceRegister(Register::Reg1),
            Bitwise::DestinationRegister(Register::Reg1),
            Bitwise::Length(4),
            // ct state is host-endian in the register.
            Bitwise::Mask(DataAttribute::Value(
                CT_STATE_ESTABLISHED_RELATED.to_ne_bytes().to_vec(),
            )),
            Bitwise::Xor(DataAttribute::Value(vec![0; 4])),
        ]),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::NotEqual),
            Cmp::Data(DataAttribute::Value(vec![0; 4])),
        ]),
    ]
}

/// `tcp flags syn tcp option maxseg size set rt mtu`.
fn tcp_syn_mss_clamp() -> Vec<Expressions> {
    vec![
        Expressions::Meta(vec![
            Meta::Key(MetaKey::L4Proto),
            Meta::DestinationRegister(Register::Reg1),
        ]),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![IPPROTO_TCP])),
        ]),
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(PAYLOAD_BASE_TRANSPORT),
            Payload::Offset(13),
            Payload::Len(1),
        ]),
        Expressions::Bitwise(vec![
            Bitwise::SourceRegister(Register::Reg1),
            Bitwise::DestinationRegister(Register::Reg1),
            Bitwise::Length(1),
            Bitwise::Mask(DataAttribute::Value(vec![TCP_FLAG_SYN])),
            Bitwise::Xor(DataAttribute::Value(vec![0])),
        ]),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::NotEqual),
            Cmp::Data(DataAttribute::Value(vec![0])),
        ]),
        Expressions::Other {
            expression_type: "rt".into(),
            attributes: vec![
                DefaultNla::new(NFTA_RT_DREG, REG1_BE.to_vec()),
                DefaultNla::new(NFTA_RT_KEY, NFT_RT_TCPMSS.to_be_bytes().to_vec()),
            ],
        },
        Expressions::Other {
            expression_type: "byteorder".into(),
            attributes: vec![
                DefaultNla::new(NFTA_BYTEORDER_SREG, REG1_BE.to_vec()),
                DefaultNla::new(NFTA_BYTEORDER_DREG, REG1_BE.to_vec()),
                DefaultNla::new(NFTA_BYTEORDER_OP, NFT_BYTEORDER_HTON.to_be_bytes().to_vec()),
                DefaultNla::new(NFTA_BYTEORDER_LEN, 2u32.to_be_bytes().to_vec()),
                DefaultNla::new(NFTA_BYTEORDER_SIZE, 2u32.to_be_bytes().to_vec()),
            ],
        },
        Expressions::Other {
            expression_type: "exthdr".into(),
            attributes: vec![
                DefaultNla::new(NFTA_EXTHDR_SREG, REG1_BE.to_vec()),
                DefaultNla::new(NFTA_EXTHDR_TYPE, vec![TCPOPT_MAXSEG as u8]),
                DefaultNla::new(NFTA_EXTHDR_OFFSET, 2u32.to_be_bytes().to_vec()),
                DefaultNla::new(NFTA_EXTHDR_LEN, 2u32.to_be_bytes().to_vec()),
                DefaultNla::new(NFTA_EXTHDR_OP, NFT_EXTHDR_OP_TCPOPT.to_be_bytes().to_vec()),
            ],
        },
    ]
}

/// The full batch that (re)builds the table from `rules`: delete, create,
/// chains, rules — one transaction, so a failure leaves the previous state
/// rather than half a table.
pub(crate) fn build_batch(rules: &Ruleset) -> Vec<NfMsg> {
    let (net, prefix) = rules.overlay;
    let mut msgs = vec![batch_control(ControlMessage::BatchBegin)];
    msgs.push(del_table());
    msgs.push(new_table());
    msgs.push(new_base_chain(
        CHAIN_POSTROUTING,
        "nat",
        InetHookNumber::PostRouting,
        PRIO_SRCNAT,
    ));
    msgs.push(new_base_chain(
        CHAIN_FORWARD,
        "filter",
        InetHookNumber::Forward,
        PRIO_FILTER,
    ));

    let mut masq = match_saddr(net, prefix);
    masq.extend(match_ifname(MetaKey::Oifname, &rules.lan_if));
    masq.push(masquerade());
    msgs.push(new_rule(CHAIN_POSTROUTING, masq));

    let mut out = match_ifname(MetaKey::Iifname, &rules.tun_if).to_vec();
    out.extend(match_ifname(MetaKey::Oifname, &rules.lan_if));
    out.push(accept());
    msgs.push(new_rule(CHAIN_FORWARD, out));

    let mut back = match_ifname(MetaKey::Iifname, &rules.lan_if).to_vec();
    back.extend(match_ifname(MetaKey::Oifname, &rules.tun_if));
    back.extend(match_ct_established_related());
    back.push(accept());
    msgs.push(new_rule(CHAIN_FORWARD, back));

    if rules.mss_clamp {
        msgs.push(new_base_chain(
            CHAIN_MSSCLAMP,
            "filter",
            InetHookNumber::Forward,
            PRIO_MANGLE,
        ));
        for key in [MetaKey::Iifname, MetaKey::Oifname] {
            let mut clamp = match_ifname(key, &rules.tun_if).to_vec();
            clamp.extend(tcp_syn_mss_clamp());
            msgs.push(new_rule(CHAIN_MSSCLAMP, clamp));
        }
    }
    msgs.push(batch_control(ControlMessage::BatchEnd));
    msgs
}

/// Delete the table if it exists: one batch, treats ENOENT as success.
pub(crate) fn delete_batch() -> Vec<NfMsg> {
    vec![
        batch_control(ControlMessage::BatchBegin),
        del_table(),
        batch_control(ControlMessage::BatchEnd),
    ]
}

// ---- socket -----------------------------------------------------------------

/// A blocking netfilter netlink socket. Operations are short and rare (boot,
/// config change, shutdown), so callers wrap them in `spawn_blocking`.
pub struct NfSocket {
    sock: netlink_sys::Socket,
    seq: u32,
}

impl NfSocket {
    pub fn open() -> Result<Self, NfError> {
        let mut sock = netlink_sys::Socket::new(NETLINK_NETFILTER).map_err(classify_open)?;
        sock.bind_auto().map_err(classify_open)?;
        Ok(Self { sock, seq: 1 })
    }

    fn send_all(&mut self, msgs: &mut [NfMsg]) -> io::Result<u32> {
        let first_seq = self.seq;
        let mut buf = Vec::new();
        for msg in msgs.iter_mut() {
            msg.header.sequence_number = self.seq;
            self.seq = self.seq.wrapping_add(1);
            msg.finalize();
            let start = buf.len();
            buf.resize(start + msg.buffer_len(), 0);
            msg.serialize(&mut buf[start..]);
        }
        self.sock.send(&buf, 0)?;
        Ok(first_seq)
    }

    /// Read replies until every ACK we asked for arrived (or one error).
    /// `expected_acks` is the number of messages sent with `NLM_F_ACK`.
    fn collect_acks(&mut self, expected_acks: usize) -> io::Result<()> {
        let mut seen = 0;
        while seen < expected_acks {
            let (bytes, _) = self.sock.recv_from_full()?;
            let mut offset = 0;
            while offset < bytes.len() {
                let msg: NfMsg = NetlinkMessage::deserialize(&bytes[offset..])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                offset += msg.header.length as usize;
                match msg.payload {
                    NetlinkPayload::Error(err) if err.code.is_some() => return Err(err.to_io()),
                    NetlinkPayload::Error(_) => seen += 1,
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Dump request: collect every inner message until `NLMSG_DONE`.
    fn dump(&mut self, mut req: NfMsg) -> io::Result<Vec<NfTablesMessage>> {
        self.send_all(std::slice::from_mut(&mut req))?;
        let mut out = Vec::new();
        loop {
            let (bytes, _) = self.sock.recv_from_full()?;
            let mut offset = 0;
            while offset < bytes.len() {
                let msg: NfMsg = NetlinkMessage::deserialize(&bytes[offset..])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                offset += msg.header.length as usize;
                match msg.payload {
                    NetlinkPayload::Done(_) => return Ok(out),
                    NetlinkPayload::Error(err) if err.code.is_some() => return Err(err.to_io()),
                    NetlinkPayload::InnerMessage(NetfilterMessage {
                        inner: NetfilterMessageInner::NfTables(m),
                        ..
                    }) => out.push(m),
                    _ => {}
                }
            }
        }
    }

    /// Send a batch and wait for its ACKs. `acks` = number of ACK-flagged
    /// messages in it (control messages are not ACKed).
    fn batch(&mut self, mut msgs: Vec<NfMsg>) -> io::Result<()> {
        let acks = msgs
            .iter()
            .filter(|m| m.header.flags & NLM_F_ACK != 0)
            .count();
        self.send_all(&mut msgs)?;
        self.collect_acks(acks)
    }

    /// Replace the `noeio` table with `rules`, atomically.
    pub fn apply(&mut self, rules: &Ruleset) -> Result<(), NfError> {
        // The delete inside the batch fails with ENOENT when the table is
        // absent, which aborts the whole transaction — so make sure it
        // exists first (a bare create is idempotent with NLM_F_CREATE).
        self.batch(vec![
            batch_control(ControlMessage::BatchBegin),
            new_table(),
            batch_control(ControlMessage::BatchEnd),
        ])
        .map_err(classify_apply)?;
        self.batch(build_batch(rules)).map_err(classify_apply)
    }

    /// Remove the `noeio` table. Absent is success.
    pub fn clear(&mut self) -> Result<(), NfError> {
        match self.batch(delete_batch()) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(classify_apply(e)),
        }
    }

    /// Whether the `noeio` table currently exists.
    pub fn table_exists(&mut self) -> Result<bool, NfError> {
        let mut req = get_table();
        req.header.flags = NLM_F_REQUEST;
        self.send_all(std::slice::from_mut(&mut req))
            .map_err(NfError::Other)?;
        let (bytes, _) = self.sock.recv_from_full().map_err(NfError::Other)?;
        let msg: NfMsg = NetlinkMessage::deserialize(&bytes).map_err(|e| {
            NfError::Other(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        })?;
        match msg.payload {
            NetlinkPayload::Error(err) if err.raw_code() == -libc::ENOENT => Ok(false),
            NetlinkPayload::Error(err) if err.code.is_some() => Err(classify_apply(err.to_io())),
            _ => Ok(true),
        }
    }

    /// Read back the table for verification: `(chain name, type, hook,
    /// priority)` for each base chain and `(chain, expression names)` for
    /// each rule. This is how tests prove the kernel understood the rules
    /// the way we meant them (AC-18), not just that it ACKed them.
    pub fn read_back(&mut self) -> Result<TableView, NfError> {
        let mut view = TableView::default();
        for m in self.dump(dump_chains()).map_err(NfError::Other)? {
            if let NfTablesMessage::NewChain(ChainMessage { attributes }) = m {
                let mut c = ChainView::default();
                for a in attributes {
                    match a {
                        ChainAttribute::Name(n) => c.name = n,
                        ChainAttribute::Type(t) => c.chain_type = t,
                        ChainAttribute::Hook(hooks) => {
                            for h in hooks {
                                match h {
                                    Hook::Number(n) => c.hook = Some(u32::from(n)),
                                    Hook::Priority(p) => c.priority = Some(p as i32),
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                view.chains.push(c);
            }
        }
        for m in self.dump(dump_rules()).map_err(NfError::Other)? {
            if let NfTablesMessage::NewRule(RuleMessage { attributes }) = m {
                let mut r = RuleView::default();
                for a in attributes {
                    match a {
                        RuleAttribute::Chain(c) => r.chain = c,
                        RuleAttribute::Expressions(list) => {
                            for e in list {
                                if let ListAttribute::Element(attrs) = e {
                                    for attr in attrs {
                                        if let ExpressionAttribute::Name(n) = attr {
                                            r.expressions.push(n);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                view.rules.push(r);
            }
        }
        Ok(view)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChainView {
    pub name: String,
    pub chain_type: String,
    pub hook: Option<u32>,
    pub priority: Option<i32>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleView {
    pub chain: String,
    pub expressions: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TableView {
    pub chains: Vec<ChainView>,
    pub rules: Vec<RuleView>,
}

fn classify_open(e: io::Error) -> NfError {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => NfError::Permission(e),
        Some(libc::EPROTONOSUPPORT) | Some(libc::EAFNOSUPPORT) => NfError::Unsupported(e),
        _ => NfError::Other(e),
    }
}

/// Errors from a table build. ENOENT here is *not* "table missing" (we just
/// created it in the same transaction) — it is the kernel failing to load a
/// module for an expression or chain type, almost always NAT (NF-5.3).
fn classify_apply(e: io::Error) -> NfError {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => NfError::Permission(e),
        Some(libc::ENOENT) => NfError::NatUnsupported(e),
        Some(libc::EOPNOTSUPP) | Some(libc::EPROTONOSUPPORT) | Some(libc::EAFNOSUPPORT) => {
            NfError::Unsupported(e)
        }
        _ => NfError::Other(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(mut msg: NfMsg) -> Vec<u8> {
        msg.header.sequence_number = 0;
        msg.finalize();
        let mut buf = vec![0; msg.buffer_len()];
        msg.serialize(&mut buf);
        buf
    }

    /// NFAC-2: byte-level pins, cross-checked against `nft --debug=netlink`
    /// captures of the same rules. Netlink header: len(4) type(2) flags(2)
    /// seq(4) pid(4); then nfgenmsg family(1) version(1) res_id(2 BE).
    #[test]
    fn batch_begin_targets_nftables_subsystem() {
        let raw = bytes(batch_control(ControlMessage::BatchBegin));
        // type = NFNL_MSG_BATCH_BEGIN (0x10), flags = NLM_F_REQUEST
        assert_eq!(&raw[4..8], &[0x10, 0x00, 0x01, 0x00]);
        // nfgenmsg: family unspec, version 0, res_id = 10 big-endian
        assert_eq!(&raw[16..20], &[0x00, 0x00, 0x00, 0x0a]);
    }

    #[test]
    fn new_table_message_bytes() {
        let raw = bytes(new_table());
        // type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE = 0x0a00
        assert_eq!(&raw[4..6], &[0x00, 0x0a]);
        // flags = REQUEST | ACK | CREATE = 0x0405
        assert_eq!(&raw[6..8], &[0x05, 0x04]);
        // family = NFPROTO_IPV4
        assert_eq!(raw[16], 2);
        // NFTA_TABLE_NAME "noeio\0" padded: nla len 10, type 1
        assert_eq!(&raw[20..24], &[0x0a, 0x00, 0x01, 0x00]);
        assert_eq!(&raw[24..30], b"noeio\0");
    }

    #[test]
    fn nat_base_chain_has_type_hook_and_priority() {
        let raw = bytes(new_base_chain(
            CHAIN_POSTROUTING,
            "nat",
            InetHookNumber::PostRouting,
            PRIO_SRCNAT,
        ));
        assert_eq!(&raw[4..6], &[0x03, 0x0a], "NFT_MSG_NEWCHAIN");
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("noeio\0"));
        assert!(s.contains("postrouting\0"));
        assert!(s.contains("nat\0"), "chain type attribute must be present");
        // Hook nested attr: number 4 (postrouting), priority 100
        let hook_num: &[u8] = &[0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04];
        let hook_prio: &[u8] = &[0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x64];
        assert!(raw.windows(8).any(|w| w == hook_num));
        assert!(raw.windows(8).any(|w| w == hook_prio));
    }

    #[test]
    fn mangle_priority_is_negative_two_complement() {
        let raw = bytes(new_base_chain(
            CHAIN_MSSCLAMP,
            "filter",
            InetHookNumber::Forward,
            PRIO_MANGLE,
        ));
        // -150 as u32 big-endian = 0xffffff6a
        let prio: &[u8] = &[0x08, 0x00, 0x02, 0x00, 0xff, 0xff, 0xff, 0x6a];
        assert!(raw.windows(8).any(|w| w == prio));
    }

    #[test]
    fn ifname_is_padded_to_ifnamsiz() {
        // nft compares the full 16-byte field: "eth0" -> 0x30687465 0 0 0
        let b = ifname_bytes("eth0");
        assert_eq!(b.len(), 16);
        assert_eq!(&b[..4], b"eth0");
        assert!(b[4..].iter().all(|&x| x == 0));
        let b = ifname_bytes("noeio0");
        assert_eq!(&b[..6], b"noeio0");
    }

    #[test]
    fn saddr_match_masks_and_compares_network() {
        // ip saddr 110.20.0.0/16 -> mask ffff0000, cmp 6e140000
        let exprs = match_saddr(Ipv4Addr::new(110, 20, 0, 7), 16);
        match &exprs[1] {
            Expressions::Bitwise(attrs) => {
                assert!(
                    attrs.contains(&Bitwise::Mask(DataAttribute::Value(vec![0xff, 0xff, 0, 0])))
                );
            }
            other => panic!("{other:?}"),
        }
        match &exprs[2] {
            Expressions::Cmp(attrs) => {
                assert!(attrs.contains(&Cmp::Data(DataAttribute::Value(vec![0x6e, 0x14, 0, 0]))));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn masquerade_rule_bytes_name_the_expression() {
        let mut exprs = match_saddr(Ipv4Addr::new(110, 20, 0, 0), 16);
        exprs.extend(match_ifname(MetaKey::Oifname, "eth0"));
        exprs.push(masquerade());
        let raw = bytes(new_rule(CHAIN_POSTROUTING, exprs));
        assert_eq!(&raw[4..6], &[0x06, 0x0a], "NFT_MSG_NEWRULE");
        // flags = REQUEST | ACK | CREATE | APPEND = 0x0c05
        assert_eq!(&raw[6..8], &[0x05, 0x0c]);
        let s = String::from_utf8_lossy(&raw);
        for name in ["payload\0", "bitwise\0", "cmp\0", "meta\0", "masq\0"] {
            assert!(s.contains(name), "missing expression {name:?}");
        }
        // NFTA_MASQ_FLAGS = 0 as nested u32
        let masq_flags: &[u8] = &[0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(raw.windows(8).any(|w| w == masq_flags));
    }

    #[test]
    fn ct_state_rule_uses_ct_expression() {
        let raw = bytes(new_rule(CHAIN_FORWARD, match_ct_established_related()));
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("ct\0"));
        // NFTA_CT_KEY = NFT_CT_STATE (0)
        let key: &[u8] = &[0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(raw.windows(8).any(|w| w == key));
    }

    #[test]
    fn mss_clamp_rule_has_rt_byteorder_exthdr() {
        let raw = bytes(new_rule(CHAIN_MSSCLAMP, tcp_syn_mss_clamp()));
        let s = String::from_utf8_lossy(&raw);
        for name in [
            "meta\0",
            "cmp\0",
            "payload\0",
            "bitwise\0",
            "rt\0",
            "byteorder\0",
            "exthdr\0",
        ] {
            assert!(s.contains(name), "missing expression {name:?}");
        }
        // NFTA_RT_KEY = NFT_RT_TCPMSS (3)
        let rt_key: &[u8] = &[0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
        assert!(raw.windows(8).any(|w| w == rt_key));
        // NFTA_EXTHDR_OP = TCPOPT (1)
        let op: &[u8] = &[0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(raw.windows(8).any(|w| w == op));
    }

    #[test]
    fn full_batch_shape() {
        let rules =
            Ruleset::new((Ipv4Addr::new(110, 20, 0, 0), 16), "eth0", "noeio0", true).unwrap();
        let msgs = build_batch(&rules);
        // begin, del, new table, 2 base chains, masq, fwd, back, mss chain, 2 mss rules, end
        assert_eq!(msgs.len(), 12);
        let acks = msgs
            .iter()
            .filter(|m| m.header.flags & NLM_F_ACK != 0)
            .count();
        assert_eq!(acks, 10);
        let rules =
            Ruleset::new((Ipv4Addr::new(110, 20, 0, 0), 16), "eth0", "noeio0", false).unwrap();
        assert_eq!(build_batch(&rules).len(), 9);
    }

    /// NFAC-7: inputs are bounded before they reach the encoder.
    #[test]
    fn ruleset_rejects_bad_inputs() {
        let ok = (Ipv4Addr::new(10, 0, 0, 0), 8);
        assert!(Ruleset::new(ok, "eth0", "noeio0", true).is_ok());
        assert!(Ruleset::new(ok, "", "noeio0", true).is_err());
        assert!(
            Ruleset::new(ok, "abcdefghijklmnop", "noeio0", true).is_err(),
            "16 chars"
        );
        assert!(
            Ruleset::new(ok, "abcdefghijklmno", "noeio0", true).is_ok(),
            "15 chars"
        );
        assert!(Ruleset::new(ok, "eth0; rm -rf /", "noeio0", true).is_err());
        assert!(Ruleset::new(ok, "eth0", "no eio", true).is_err());
        assert!(Ruleset::new((Ipv4Addr::new(10, 0, 0, 0), 33), "eth0", "noeio0", true).is_err());
    }

    #[test]
    fn errors_are_classified_by_operator_action() {
        assert!(matches!(
            classify_apply(io::Error::from_raw_os_error(libc::EPERM)),
            NfError::Permission(_)
        ));
        assert!(matches!(
            classify_apply(io::Error::from_raw_os_error(libc::ENOENT)),
            NfError::NatUnsupported(_)
        ));
        assert!(matches!(
            classify_apply(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
            NfError::Unsupported(_)
        ));
        assert!(matches!(
            classify_open(io::Error::from_raw_os_error(libc::EPROTONOSUPPORT)),
            NfError::Unsupported(_)
        ));
        let msg = NfError::NatUnsupported(io::Error::from_raw_os_error(libc::ENOENT)).to_string();
        assert!(msg.contains("modprobe"), "{msg}");
    }

    /// AC-18 / AC-19 / AC-20: real kernel round trip. Needs CAP_NET_ADMIN;
    /// run with `cargo test -p noeio-net-route -- --ignored` inside the
    /// privileged build container (which has no `nft` binary).
    #[test]
    #[ignore]
    fn apply_read_back_clear_roundtrip() {
        let mut nf = NfSocket::open().expect("open netfilter socket");
        nf.clear().expect("clear on a missing table is fine");
        assert!(!nf.table_exists().unwrap());

        let rules =
            Ruleset::new((Ipv4Addr::new(110, 20, 0, 0), 16), "eth0", "noeio0", true).unwrap();
        nf.apply(&rules).expect("apply");
        // Twice: must be idempotent.
        nf.apply(&rules).expect("re-apply");
        assert!(nf.table_exists().unwrap());

        let view = nf.read_back().expect("read back");
        let chain = |n: &str| {
            view.chains
                .iter()
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("chain {n}"))
        };
        let post = chain(CHAIN_POSTROUTING);
        assert_eq!(post.chain_type, "nat");
        assert_eq!(post.hook, Some(u32::from(InetHookNumber::PostRouting)));
        assert_eq!(post.priority, Some(PRIO_SRCNAT));
        let fwd = chain(CHAIN_FORWARD);
        assert_eq!(fwd.chain_type, "filter");
        assert_eq!(fwd.priority, Some(PRIO_FILTER));
        assert_eq!(chain(CHAIN_MSSCLAMP).priority, Some(PRIO_MANGLE));

        let in_chain = |n: &str| {
            view.rules
                .iter()
                .filter(|r| r.chain == n)
                .collect::<Vec<_>>()
        };
        let post_rules = in_chain(CHAIN_POSTROUTING);
        assert_eq!(post_rules.len(), 1);
        assert!(
            post_rules[0].expressions.iter().any(|e| e == "masq"),
            "{post_rules:?}"
        );
        let fwd_rules = in_chain(CHAIN_FORWARD);
        assert_eq!(fwd_rules.len(), 2);
        assert!(fwd_rules[1].expressions.iter().any(|e| e == "ct"));
        let mss_rules = in_chain(CHAIN_MSSCLAMP);
        assert_eq!(mss_rules.len(), 2);
        assert!(mss_rules[0].expressions.iter().any(|e| e == "exthdr"));

        nf.clear().expect("clear");
        assert!(!nf.table_exists().unwrap());
        nf.clear().expect("second clear is a no-op");
    }
}
