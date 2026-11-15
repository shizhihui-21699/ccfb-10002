//! fwanalyze：防火墙规则遮蔽/冗余/冲突分析与报文模拟。
//! 全部地址/端口运算基于整数闭区间的精确并/交/差，不做抽样。
#![allow(dead_code)]

mod analyze;
mod intervals;
mod ip;
mod model;
mod output;
mod parser_iptables;
mod parser_nft;
mod simulate;

use ip::IpAddr;
use model::Ruleset;
use std::process::exit;

fn usage() -> ! {
    eprintln!(
        "fwanalyze — 防火墙规则遮蔽/冗余/冲突分析与报文模拟（精确 CIDR 区间运算）

用法:
  fwanalyze analyze  [--json] [--output FILE] <rules-file> [<rules-file> ...]
      分析规则集，按链分组输出遮蔽、冗余、冲突；--json 导出 JSON。

  fwanalyze simulate [--json] [--table TABLE] [--chain CHAIN] \\
                     --src ADDR --dst ADDR --proto PROTO \\
                     [--sport PORT] [--dport PORT] \\
                     [--iif NAME] [--oif NAME] [--icmp-type N] [--state STATE] \\
                     <rules-file> [<rules-file> ...]
      报文模拟：打印走过的链、求值与命中的规则、最终判定。
      --table/--chain 指定入口链（默认 filter/INPUT）。

  fwanalyze dump <rules-file> [<rules-file> ...]
      调试：逐条打印解析后的匹配空间。

文件格式按内容自动识别（iptables-save 或 nft list ruleset），可混合传入。
"
    );
    exit(2);
}

#[derive(Default)]
struct Args {
    json: bool,
    output: Option<String>,
    table: String,
    chain: Option<String>,
    src: Option<String>,
    dst: Option<String>,
    proto: Option<String>,
    sport: u16,
    dport: u16,
    files: Vec<String>,
}

fn parse_args(argv: &[String]) -> (&str, Args) {
    if argv.is_empty() {
        usage();
    }
    let cmd = argv[0].as_str();
    if !matches!(cmd, "analyze" | "simulate" | "dump") {
        usage();
    }
    let mut a = Args::default();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => a.json = true,
            "--output" => {
                i += 1;
                a.output = Some(argv.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--table" => {
                i += 1;
                a.table = argv.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--chain" => {
                i += 1;
                a.chain = Some(argv.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--src" => {
                i += 1;
                a.src = Some(argv.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--dst" => {
                i += 1;
                a.dst = Some(argv.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--proto" => {
                i += 1;
                a.proto = Some(argv.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--sport" => {
                i += 1;
                a.sport = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            }
            "--dport" => {
                i += 1;
                a.dport = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            }
            "--iif" => {
                i += 1;
                let _ = argv.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--oif" => {
                i += 1;
                let _ = argv.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--icmp-type" => {
                i += 1;
                let _ = argv.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--state" => {
                i += 1;
                let _ = argv.get(i).cloned().unwrap_or_else(|| usage());
            }
            "-h" | "--help" => usage(),
            other if other.starts_with("--") => {
                eprintln!("未知参数: {other}");
                usage();
            }
            other => a.files.push(other.to_string()),
        }
        i += 1;
    }
    if a.files.is_empty() {
        eprintln!("错误: 至少需要一个规则文件\n");
        usage();
    }
    (cmd, a)
}

/// 按内容嗅探格式：出现 `table ... {` 或 `chain ... {` 视为 nft，否则 iptables-save。
fn detect_format(content: &str) -> Format {
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("table ") && t.contains('{') {
            return Format::Nft;
        }
        if t.starts_with("chain ") {
            return Format::Nft;
        }
        if t.starts_with('*') || t.starts_with(":") || t.starts_with("-A ") {
            return Format::Iptables;
        }
    }
    Format::Iptables
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Iptables,
    Nft,
}

fn load_files(files: &[String]) -> Result<Ruleset, String> {
    let mut ruleset = Ruleset::default();
    for path in files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取 {path}: {e}"))?;
        let fmt = detect_format(&content);
        match fmt {
            Format::Iptables => parser_iptables::parse_iptables_save(&content, path, &mut ruleset)?,
            Format::Nft => parser_nft::parse_nft_ruleset(&content, path, &mut ruleset)?,
        }
    }
    Ok(ruleset)
}

fn proto_from_str(s: &str) -> Result<u8, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "sctp" => 132,
        other => other.parse().map_err(|_| format!("未知协议: {s}"))?,
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, args) = parse_args(&argv);

    let ruleset = match load_files(&args.files) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("解析失败: {e}");
            exit(1);
        }
    };

    for w in &ruleset.warnings {
        eprintln!("警告: {w}");
    }

    if cmd == "dump" {
        for table in &ruleset.tables {
            for chain in &table.chains {
                println!("=== {}/{} ({} 条) ===", table.name, chain.name, chain.rules.len());
                for r in &chain.rules {
                    println!("#{} {} -> {}", r.id.index, r.raw, r.verdict.raw);
                    let fields = output::describe_match(&r.matches, table.family);
                    if r.matches.is_empty() {
                        println!("    匹配空间: 空集");
                    } else if fields.is_empty() {
                        println!("    匹配空间: 全集");
                    } else {
                        for (k, v) in fields {
                            println!("    {k}: {v}");
                        }
                    }
                    if !r.unsupported.is_empty() {
                        println!("    未建模(按全匹配): {}", r.unsupported.join("; "));
                    }
                }
            }
        }
        return;
    }

    if cmd == "analyze" {
        let report = analyze::analyze(&ruleset);
        if args.json {
            let json = output::print_json(&ruleset, &report);
            emit(&args.output, &json);
        } else {
            output::print_text(&ruleset, &report);
            if let Some(path) = &args.output {
                let json = output::print_json(&ruleset, &report);
                std::fs::write(path, json).unwrap_or_else(|e| {
                    eprintln!("写入 {path} 失败: {e}");
                    exit(1);
                });
                eprintln!("JSON 已写入 {path}");
            }
        }
        return;
    }

    // simulate
    let src_s = args.src.clone().unwrap_or_else(|| {
        eprintln!("错误: simulate 需要 --src\n");
        usage();
    });
    let dst_s = args.dst.clone().unwrap_or_else(|| {
        eprintln!("错误: simulate 需要 --dst\n");
        usage();
    });
    let proto_s = args.proto.clone().unwrap_or_else(|| {
        eprintln!("错误: simulate 需要 --proto\n");
        usage();
    });
    let src = match IpAddr::parse(&src_s) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("错误: {e}");
            exit(1);
        }
    };
    let dst = match IpAddr::parse(&dst_s) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("错误: {e}");
            exit(1);
        }
    };
    if src.family != dst.family {
        eprintln!("错误: 源/目的地址族不一致");
        exit(1);
    }
    let proto = match proto_from_str(&proto_s) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("错误: {e}");
            exit(1);
        }
    };

    // 重新解析一遍以拿到被 parse_args 丢弃的可选参数（保留原始 argv 直接取）
    let (iif, oif, icmp_type, state) = extract_packet_options(&argv);

    let pkt = simulate::Packet {
        src_ip: src,
        dst_ip: dst,
        proto,
        src_port: args.sport,
        dst_port: args.dport,
        iif,
        oif,
        icmp_type,
        state,
    };

    let table = if args.table.is_empty() {
        "filter".to_string()
    } else {
        args.table
    };
    let chain = args.chain.unwrap_or_else(|| "INPUT".to_string());

    if ruleset.table(&table).is_none() {
        eprintln!("错误: 表 {table} 不存在（可用表: {}）",
            ruleset.tables.iter().map(|t| t.name.as_str())
                .collect::<Vec<_>>().join(", "));
        exit(1);
    }
    if ruleset.table(&table).unwrap().chain(&chain).is_none() {
        eprintln!("错误: 链 {table}:{chain} 不存在");
        exit(1);
    }

    let res = simulate::simulate(&ruleset, &pkt, &table, &chain);
    if args.json {
        let json = output::simulation_json(&pkt, &res);
        emit(&args.output, &json);
    } else {
        output::print_simulation(&pkt, &res);
        if let Some(path) = &args.output {
            let json = output::simulation_json(&pkt, &res);
            std::fs::write(path, json).unwrap_or_else(|e| {
                eprintln!("写入 {path} 失败: {e}");
                exit(1);
            });
            eprintln!("JSON 已写入 {path}");
        }
    }
}

fn extract_packet_options(
    argv: &[String],
) -> (String, String, Option<u8>, Option<model::ConnState>) {
    let mut iif = String::new();
    let mut oif = String::new();
    let mut icmp_type = None;
    let mut state = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--iif" => {
                i += 1;
                iif = argv.get(i).cloned().unwrap_or_default();
            }
            "--oif" => {
                i += 1;
                oif = argv.get(i).cloned().unwrap_or_default();
            }
            "--icmp-type" => {
                i += 1;
                icmp_type = argv.get(i).and_then(|v| v.parse().ok());
            }
            "--state" => {
                i += 1;
                if let Some(s) = argv.get(i) {
                    state = model::parse_conn_state(s);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (iif, oif, icmp_type, state)
}

fn emit(path: &Option<String>, content: &str) {
    match path {
        Some(p) => std::fs::write(p, content).unwrap_or_else(|e| {
            eprintln!("写入 {p} 失败: {e}");
            exit(1);
        }),
        None => println!("{content}"),
    }
}
