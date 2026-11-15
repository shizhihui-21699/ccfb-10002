# fwanalyze

防火墙规则静态分析与报文模拟工具（纯 Rust，零外部依赖）。读取 `iptables-save` /
`ip6tables-save` 与 `nft list ruleset` 导出，精确计算：

- **遮蔽（shadowed）**：规则在链内永远不会被求值 —— 任何能命中它的报文都已被前面的
  终结规则（ACCEPT/DROP/REJECT/QUEUE/GOTO，或目标链必然终结的 JUMP）抢先处理。
  支持多规则**联合遮蔽**，并通过最小化回溯只列出不可或缺的遮蔽者，明确给出“被哪条遮住”。
- **冗余（redundant）**：匹配条件自相矛盾（匹配空间为空），或与前面规则匹配空间完全相同。
- **冲突（conflict）**：两条规则匹配空间有交集但动作不同，交集按字段精确给出报文范围。
- 另报：不可达自定义链、悬空跳转（目标链不存在）。

所有地址/端口/协议都转成整数**闭区间**做并/交/差精确运算（IPv4 用 u32、IPv6 用 u128），
CIDR、点分掩码、iprange、端口段一律按真实区间处理，**不做任何抽样或前缀近似**。

## 构建

```
cargo build --release
```

## 用法

分析（终端按链分组输出）：

```
fwanalyze analyze rules.txt
fwanalyze analyze --json --output report.json a.rules b.nft   # 多文件、混合格式
```

报文模拟（打印走过的链、求值/命中的规则序号、最终判定）：

```
fwanalyze simulate --src 10.1.2.3 --dst 9.9.9.9 --proto tcp \
                   --sport 40000 --dport 443 --iif eth0 rules.txt
# 可选：--oif、--icmp-type N、--state NEW|ESTABLISHED|RELATED|UNTRACKED|INVALID
#      --table/--chain 指定入口链（默认 filter/INPUT）；--json 导出轨迹
```

调试（逐条打印解析后的匹配空间）：

```
fwanalyze dump rules.nft
```

文件格式按内容自动识别，可在一次调用中混合传入 iptables 与 nft 文件。

## 判定语义要点

- 遮蔽只在**同一链内、按规则顺序**判定；跨链通过 JUMP/GOTO 的可达性与“必然终结”
  定点计算纳入（自定义链开头即无条件终结规则时，跳到它的规则也算终结规则）。
- ACCEPT 与 DROP 都会终结报文路径，因此都能遮蔽其后同空间规则。
- 模拟器完整复现 JUMP（带返回）、GOTO（不返回）、显式/隐式 RETURN、链尾默认策略，
  并对跳转环做深度保护、对悬空链给出明确错误。
- 无法精确建模的 match（如 tcp-flags、limit、mark）按“匹配所有”保守处理并在输出中标注，
  宁可少报遮蔽也不虚构死规则。

## 测试

```
cargo test
```

`tests/fixtures/` 下提供了故意写满遮蔽/联合遮蔽/冗余/冲突/不可达链的 iptables、nft、
IPv6 验证规则集。
