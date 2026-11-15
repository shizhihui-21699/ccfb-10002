# fwaudit — 防火墙规则集审计工具

读取 `iptables-save` / `ip6tables-save` 和 `nft list ruleset` 的导出文件，
基于**精确 CIDR 区间运算**（非抽样）找出死规则、冗余规则和冲突规则，
并可对单个报文做链遍历模拟。

## 构建

```sh
cargo build --release
# 二进制在 target/release/fwaudit
```

## 用法

### 规则分析

```sh
fwaudit analyze --input rules.v4                 # iptables-save 导出
fwaudit analyze --input rules.nft                # nft list ruleset 导出
fwaudit analyze --input a.v4 --input b.nft       # 多文件合并分析
fwaudit analyze --input rules.v4 --json report.json
```

每条规则解析成若干"超矩形"（源/目的地址区间集 × 协议集 × 源/目的端口区间集
× 接口 × 不透明谓词），IPv4/IPv6 分族处理。对每条规则，用它前面所有
终止型规则（ACCEPT/DROP/REJECT/DNAT/…）的匹配集逐条做精确减法：

- **SHADOWED（被遮蔽）**：差集为空——该规则永远不可能命中。若遮蔽者动作
  与它不一致（或混杂），归入此类，需要人工确认。
- **REDUNDANT（冗余）**：差集为空且所有遮蔽者动作相同——删掉它行为不变，
  可安全清理。
- **POLICY-DUP**：终止规则兜住了所有到达它的流量，且动作与链 policy 相同。
- **CONFLICT（冲突）**：前后两条终止规则动作不同，且前者的"存活区"与后者
  匹配集有非空交集，输出精确的重叠区间。

每条发现都给出具体是**哪几条规则**遮蔽了它（按规则在链中的 1 起始序号，
与 `iptables -L --line-numbers` 一致）。

自定义链处理：跳到"必然终止"的链（所有路径都到达终止 verdict 且不 RETURN，
例如末尾是无条件 DROP 的 LOGDROP 链）的 jump/goto 也算遮蔽者——跳过去就
回不来了。

### 报文模拟

```sh
fwaudit simulate --input rules.v4 \
    --src 10.1.2.3 --dst 8.8.8.8 --proto tcp --sport 40000 --dport 22 \
    [--table filter] [--chain INPUT] [--iif eth0] [--json]
```

打印报文走过的每条链、命中的每条规则、jump/goto/RETURN 过程和最终
verdict（含链 policy 落底）。带 `ct state` 等无法静态判定的匹配时，
按命中处理并标注 `?? assumed true`。

## 语义与保守性说明

- 地址段一律展开为精确整数区间做交/并/差，无任何采样。
- 无法精确建模的匹配（`ct state`、tcp flags、未知扩展）记为**不透明谓词**：
  带谓词的规则只能被"谓词是其子集"的规则遮蔽——宁可少报遮蔽，绝不误报。
  冲突检测则反向保守：可能重叠即报"可能冲突"。
- 接口匹配按精确字符串处理；`! -i eth0`、`eth+` 这类通配降级为不透明谓词。
  因此"无接口约束的规则被多条不同接口的细则联合遮蔽"这种边角情形不报。
- nft 命名集合（`set`，含 `flags interval` 区间）、集合字面量 `{ }`、
  取反 `!=`、端口范围均精确展开；vmap/concat 键降级为不透明谓词。
- 单条链内分析；跨链的遮蔽判定只利用"必然终止链"这一可证明的性质。

## 测试

```sh
cargo test
```

- 单元测试：区间/矩形运算（含 u128::MAX 边界回归）。
- 集成测试：`tests/fixtures/broken.{v4,nft}` 里埋设的每一处遮蔽/冗余/
  冲突都必须被检出。
- 穷举交叉验证（`tests/bruteforce.rs`）：在小报文空间内随机生成规则集，
  逐报文暴力模拟一阶语义，与分析器结果逐条比对。
