# 多 ZKVM 后端支持调研报告

> 调研目标：
> 1. `eth-act/ere` 是否对 `scroll-zkvm-prover` 项目有用，如何结合。
> 2. 在 ere 支持的 ZKVM 中，哪些适合本项目未来的多 ZKVM 后端支持。
>
> 调研日期：2026-06-21  
> 当前项目 ZKVM：OpenVM v1.6.0  
> ere 版本：0.12.2

---

## 1. 执行摘要

### 结论一览

| ZKVM | ere 版本 | 是否适合作为第二后端 | 关键判断 |
|------|----------|---------------------|----------|
| **OpenVM** | v1.4.3 | 已是当前后端（但 ere 版本落后） | 继续作为主力，ere 的抽象层可参考但不可直接复用 |
| **SP1** | v6.1.0 | **有条件适合（首选候选）** | 生产级、EVM verifier 成熟、precompile 丰富，但需重写 guest/host |
| **RISC Zero** | v3.0.5 | **有条件适合** | 成熟、EVM verifier 可用，但证明生成偏慢、架构差异大 |
| **ZisK** | v0.18.0 | **不适合现在，可作远期 R&D** | 性能潜力大，但预生产、无原生 pairing、缺少生产验证 |
| **Airbender** | 73d69b5 | **不适合当前 commit** | 无 EVM verifier、无 Keccak/SHA-256、无 pairing precompile |

### 对 ere 的总体判断

**ere 当前对 scroll-zkvm-prover 没有直接可用性，但可作为内部抽象层设计的参考。**

- ere 是一个统一的 zkVM SDK 适配层（trait-based adapter），不是通用 IR 或翻译层。
- ere 支持的 OpenVM 版本（v1.4.3）低于项目当前使用版本（v1.6.0），且其 `prove()` 只返回聚合 STARK 证明，不涵盖 scroll 需要的 SNARK/EVM verifier 流程。
- ere 的 `Compiler` / `zkVMProver` / `zkVMVerifier` / `Platform` trait 设计清晰，可为 scroll 未来构建自己的 `ZkvmBackend` 抽象层提供设计参考。
- 不建议将 ere 作为依赖直接集成；更现实的路径是借鉴其模式，在 scroll 内部实现一个更贴合 zkEVM 多层证明管道的后端 trait 层。

---

## 2. 当前项目架构与多 ZKVM 化的难度

### 2.1 当前架构特点

`scroll-zkvm-prover` 当前完全基于 **OpenVM v1.6.0**，耦合较深：

| 层次 | OpenVM 相关实现 |
|------|----------------|
| 工作区依赖 | `Cargo.toml` 中 `openvm`、`openvm-sdk`、`openvm-circuit`、`openvm-native-*`、`openvm-stark-sdk` 等 |
| Host Prover | `crates/prover/src/prover/mod.rs` 使用 `Sdk`、`SdkVmConfig`、`AppConfig<SdkVmConfig>`、`StarkProver<...>` |
| Setup/加载 | `crates/prover/src/setup.rs` 读取 `app.vmexe` + `openvm.toml` |
| Proof 类型 | `crates/types/src/proof.rs` 封装 `EvmProof`、`Proof<SC>`、`BabyBear` public values |
| Aggregation Key | `crates/types/src/zkvm.rs` 通过 `Sdk::riscv32().agg_pk()` 硬编码 |
| Verifier | `crates/verifier/src/verifier.rs` 使用 `AggVerifyingKey`、`AppExecutionCommit`、`Sdk::verify_proof` |
| Circuit trait | `crates/types/circuit/src/lib.rs` 调用 `openvm::io::reveal_bytes32`，嵌入 `root_verifier.asm` |
| Guest I/O | `crates/types/circuit/src/io.rs` 使用 `openvm_rv32im_guest::hint_*` 和 `openvm::io::read_vec` |
| Guest circuits | `crates/circuits/*-circuit/src/main.rs` 使用 `openvm::entry!`、`openvm::init!` 及 OpenVM precompile |
| Build 工具 | `crates/build-guest` 生成 ELF、`.vmexe`、commitments、`root_verifier.asm`、Solidity verifier |

### 2.2 多层证明管道

```
chunk-circuit  →  StarkProof (chunk)
                    ↓
batch-circuit  →  StarkProof (batch)  （聚合多个 chunk proof）
                    ↓
bundle-circuit →  EvmProof/SNARK      （聚合多个 batch proof，输出链上可验证证明）
```

最终输出：
- `releases/dev/{chunk,batch,bundle}/app.vmexe`
- `releases/dev/verifier/openVmVk.json`
- EVM verifier contract (`verifier.sol` / `verifier.bin`)

### 2.3 引入第二 ZKVM 的难点评估

**难度：高但可行，需要多层重构。**

主要障碍：
1. **Guest 程序不可移植**：`crates/circuits/*-circuit` 深度使用 OpenVM guest intrinsic（`openvm_keccak256_guest`、`openvm_pairing`、`openvm_ecc_guest`、内联 `root_verifier.asm`）。第二后端需要重写 chunk/batch/bundle 的 guest 实现。
2. **Proof / commitment 格式绑定 OpenVM**：`StarkProof` 内部是 `Proof<SC>` / `BabyBear`；`EvmProof` 绑定 OpenVM 的 Halo2 wrapper。
3. **Prover 是具体 OpenVM 机器**：`crates/prover/src/prover/mod.rs` 需要抽象为 `ZkvmBackend` trait。
4. **Verifier 是具体实现**：`UniversalVerifier` 需要后端化。
5. **StdIn / input 编码是 OpenVM 专用**：`ProvingTask::build_guest_input` 返回 `openvm_sdk::StdIn`。
6. **Build 工具链**：`crates/build-guest` 需要并行或 trait 化。

**已有可复用的共享层**：
- `types-base` 中的 witness 类型（`ChunkWitness`、`BatchWitness`、`BundleWitness`）
- `PublicInputs` 版本/分叉处理
- `Circuit::validate` 业务逻辑
- rollup 逻辑（`ChunkInfo`、`BatchInfo`、`BundleInfo`）

### 2.4 建议的抽象插入点

```
┌─────────────────────────────────────────┐
│  scroll-zkvm-prover/src/backend.rs      │  ZkvmBackend trait
│  - setup / execute / prove_stark        │
│  - prove_snark / get_vk                 │
├─────────────────────────────────────────┤
│  Prover<B: ZkvmBackend> 或 enum Prover   │
├─────────────────────────────────────────┤
│  ProofEnum（opaque bytes + 公共元数据）   │
├─────────────────────────────────────────┤
│  共享 Scroll 逻辑层                      │
│  types-base, Circuit::validate, PublicInputs │
├─────────────────────────────────────────┤
│  各后端 Guest 程序 + Host SDK             │
│  OpenVMBackend, Sp1Backend, Risc0Backend │
└─────────────────────────────────────────┘
```

---

## 3. `eth-act/ere` 详细分析

### 3.1 ere 是什么

- **定位**：Unified zkVM Interface & Toolkit
- **口号**："Compile. Execute. Prove. Verify." —— 一套 ergonomic Rust API 跨多个 zkVM。
- **本质**：基于 trait 的 SDK 适配层，不是通用 IR、翻译层或测试框架。

### 3.2 支持的 ZKVM

| zkVM | ere 锁定版本 | ISA | GPU | 多 GPU | Cluster |
|------|-------------|-----|-----|--------|---------|
| Airbender | 73d69b5 | RV32IMA | ✓ | ✓ | |
| OpenVM | v1.4.3 | RV32IMA | ✓ | | |
| RISC Zero | v3.0.5 | RV32IMA | ✓ | ✓ | |
| SP1 | v6.1.0 | RV64IMA | ✓ | | |
| ZisK | v0.18.0 | RV64IMA | ✓ | ✓ | ✓ |

### 3.3 核心架构

```
ere/
├── crates/compiler/core       # Compiler trait, Elf
├── crates/compiler/{zkvm}     # 各后端编译器
├── crates/prover/core         # zkVMProver trait, Input, reports
├── crates/prover/{zkvm}       # 各后端 prover
├── crates/platform/core       # Platform trait（guest 侧）
├── crates/platform/{zkvm}     # 各后端 guest API
├── crates/verifier/core       # zkVMVerifier trait
├── crates/verifier/{zkvm}     # 各后端 verifier
├── crates/dockerized          # Docker/gRPC 封装
└── crates/catalog             # zkVMKind, 版本管理
```

核心 trait：

```rust
// Compiler
pub trait Compiler {
    fn compile(&self, guest_directory: impl AsRef<Path>, args: &[String]) -> Result<Elf, Self::Error>;
}

// Prover
pub trait zkVMProver {
    type Verifier: zkVMVerifier;
    fn execute(&self, input: &Input) -> Result<(PublicValues, ProgramExecutionReport), Self::Error>;
    fn prove(&self, input: &Input) -> Result<(PublicValues, Proof, ProgramProvingReport), Self::Error>;
    fn verify(&self, proof: &Proof) -> Result<PublicValues, Self::Error>;
    fn program_vk(&self) -> &ProgramVk;
}

// Verifier
pub trait zkVMVerifier {
    type ProgramVk: Encode + Decode;
    type Proof: Encode + Decode;
    fn verify(&self, proof: &Self::Proof) -> Result<PublicValues, Self::Error>;
}

// Guest Platform
pub trait Platform {
    fn read_input() -> impl Deref<Target = [u8]>;
    fn write_output(output: &[u8]);
    fn print(message: &str);
    fn cycle_count() -> u64;
}
```

### 3.4 抽象机制

- 通用类型：`Elf`、`Input`、`PublicValues`、`ProgramExecutionReport`、`ProgramProvingReport`、`ProverResource`
- Host↔Guest I/O 为原始字节；后端仅在需要时添加 framing
- `ProgramVk` / `Proof` 通过 `ere-codec` 做 `Encode`/`Decode`
- Dockerized 模式通过 gRPC 封装，无需本地 SDK

### 3.5 许可证与成熟度

- **License**：MIT / Apache-2.0 双许可
- **版本**：0.12.2
- **MSRV**：Rust 1.88
- **创建时间**：2025-05-11（约 1 年）
- **活跃度**：活跃，最近提交 2026-06-16
- **社区**：84 stars，25 forks，32 open issues，14 贡献者
- **评估**：年轻但积极维护，核心团队小

### 3.6 对 scroll-zkvm-prover 的适用性

| 维度 | ere 现状 | scroll 需求 | 差距 |
|------|---------|------------|------|
| OpenVM 版本 | v1.4.3 | v1.6.0 | 版本落后，OpenVM 高度版本敏感 |
| Proof 类型 | 聚合 STARK | SNARK + EVM verifier | 不覆盖最终 SNARK/合约输出 |
| 多层聚合 | 无 | chunk → batch → bundle | 无现成抽象 |
| Guest 模型 | 简单 Platform + Input | 复杂 continuation + precompile | 不够 |
| EVM verifier | 无抽象 | 必须生成 Solidity verifier | 缺失 |

**判断**：
- **不能直接集成使用**。
- **可参考其 trait 设计**：`Compiler` / `zkVMProver` / `zkVMVerifier` / `Platform` 的设计模式可作为 scroll 内部 `ZkvmBackend` 抽象层的灵感来源。
- 如果未来 scroll 要支持多 ZKVM，更合理的路径是：**自己定义一个更贴合 zkEVM 多层证明管道的后端 trait 层**，而不是直接依赖 ere。

---

## 4. 各 ZKVM 适配性详细评估

### 4.1 SP1 v6.1.0

#### 概况

| 项目 | 内容 |
|------|------|
| ISA | RISC-V `RV64IMA`，支持 `std` |
| 延续性 | 原生 sharding，自动分片并递归压缩 |
| 递归/聚合 | 支持 `verify_sp1_proof(vkey, public_values_digest)`，任意深度递归 |
| Proof 系统 | Plonky3 FRI STARK over BabyBear → BN254 Groth16/Plonk |
| EVM verifier | `sp1-contracts`：Groth16 (~260 B, ~270k gas) / Plonk (~868 B, ~300k gas)，已部署主网 |

#### 性能与 Precompile

- 宣传在区块链工作负载上比其他 zkVM 快 4–28 倍
- SP1 Reth 区块证明约 $0.01–0.02/tx
- GPU 集群可在 ~40 秒内证明以太坊主网区块（SP1 Turbo）
- 单机内存约 2 GB；超过 120B cycles 需显式聚合
- Precompile：keccak256、sha256、secp256k1、ed25519、BN254 曲线/域操作、BLS12-381 曲线/域操作、`uint256_mulmod`、`bigint`、unconstrained 模式
- **注意**：无专用 `bn254_pairing` syscall，pairing 通过 BN254 precompile + `substrate-bn` patch 实现（alt_bn128_pair ~6.6M cycles）

#### 成熟度

- License：MIT / Apache-2.0
- 声称生产就绪；Veridise、Cantina、Zellic、KALOS 审计；bug bounty
- 主网部署；声称 >$1B TVL
- 非常活跃（v6.2.2 当前；MSRV Rust 1.91）

#### 已知 zkEVM/Rollup 用例

- OP Succinct（OP Stack ZK validity/fault proofs）v4.3.0 on SP1 v6.1.0
- RSP（Reth Succinct Processor）
- Taiko 多 prover 模型包含 SP1
- Polygon AggLayer、Celestia Blobstream、Avail Vector、SP1 Helios
- Scroll 曾与 Succinct 合作定制 precompile，但自身 zkEVM prover 使用 OpenVM

#### 对 scroll 的适配性

| 需求 | 评估 |
|------|------|
| 多层聚合 chunk→batch→bundle | 可行。每层级可为独立 SP1 ELF；下层生成 `Compressed` proof，上层通过 `verify_sp1_proof` 验证；最终 wrap 为 Groth16/Plonk。但需从零实现聚合树和 public value 连线。 |
| EVM verifier | **强契合**。成熟、已部署的 verifier gateway。 |
| 重 precompile | **强契合**标准以太坊原语；Scroll 专用曲线/哈希可能需要自定义 precompile。 |
| 大 witness | 中等契合。stdin 为任意字节，public values 无限制但会哈希；guest 内存约 2 GB，超大 witness 需 Merkle 化/流式。 |

#### 关键障碍

1. ISA/移植差距：SP1 用 RV64IMA，OpenVM v1.6 不同；guest/host/commitment 工具需重写。
2. 无原生分层 scaffold：chunk/batch/bundle 需手写递归 SP1 程序。
3. Public value 模型不同：SP1 将 public values 哈希为 digest，与 OpenVM 的 Merkle root/public array 模型不同。
4. 自定义 precompile：Scroll 特定瓶颈可能需要新 precompile。
5. 版本敏感：SP1 升级会改变 ELF build 和 verifier key，需重新部署合约。
6. 证明硬件：本地 GPU prover 存在，但优化/成本优化可能依赖 Succinct Prover Network，引入信任/成本考量。

#### 结论

**SP1 v6.1.0 是最适合作为第二 ZKVM 后端的候选。**

- 生产级、EVM verifier 成熟、precompile 丰富、生态活跃。
- 不是 drop-in replacement，需要重大重构。
- 建议 PoC：先移植一个简化 circuit tier，测量端到端证明时间/内存。

---

### 4.2 RISC Zero v3.0.5

#### 概况

| 项目 | 内容 |
|------|------|
| ISA | RISC-V `rv32im`，ELF binary，~4 GB 内存，1 kB 分页 |
| 递归/聚合 | `lift`/`join` 递归树 + `env::verify` 组合 |
| Proof 系统 | STARK → Groth16 |
| EVM verifier | 成熟的 `RiscZeroGroth16Verifier`，~256 字节证明，~200k–300k gas |

#### 性能与 Precompile

- Precompile：SHA-256、Keccak、BN254、BLS12-381、secp256k1、RSA、256-bit mod-mul
- 覆盖 zkEVM 加密需求，但 guest 需使用 RISC Zero 的 patch crates
- 支持 continuation；分页 page-in/out ~1,130 cycles/page
- Boundless 上 ~1M cycles/sec；证明生成通常比 SP1/OpenVM 慢，但证明更小、验证更快

#### 成熟度

- 成立于 2021 年，融资 $54M
- 主网 verifier、Boundless marketplace
- 高成熟度、维护良好

#### 对 scroll 的适配性

| 需求 | 评估 |
|------|------|
| 多层聚合 | 原则上支持 chunk→batch→bundle，但需重新设计；无 OpenVM 式 `root_verifier.asm` |
| EVM verifier | **强契合**。成熟、可升级 EVM verifier contract。 |
| 重 precompile | **覆盖需求**。 |
| 大 witness | 可用，但内存局部性/分页成本关键。 |

#### 关键障碍

1. Proof-system mismatch：Halo2/KZG → Groth16，需替换最终 SNARK 管道、SRS/trusted setup、verifier contract。
2. Guest-circuit 重写：scroll 的 OpenVM 专用 circuits、commitments、hints 需移植到 `risc0_zkvm::guest::env`。
3. 聚合架构重设计：OpenVM 可编程 root verifier 与 RISC Zero 固定递归树 + Groth16 wrapper 不直接映射。
4. 证明延迟风险：RISC Zero 证明生成通常慢于 OpenVM/SP1。
5. 内存/分页成本：大且随机访问的 witness 可能昂贵。

#### 结论

**RISC Zero v3.0.5 是第二适合的候选。**

- 成熟、EVM verifier 强、precompile 完整。
- 但证明生成较慢，架构差异大，需要大量重写。
- 建议：不要作为短期迁移目标；如团队愿意重大重构，先做简化 chunk circuit 的 PoC。

---

### 4.3 ZisK v0.18.0

#### 概况

| 项目 | 内容 |
|------|------|
| ISA | RISC-V 64-bit (`RV64IMA`)，target `riscv64ima-zisk-zkvm-elf` |
| 执行 | 软件模拟器、native ASM executor、CUDA GPU、组合模式 |
| 大规模程序 | step limit 2³⁶ (64 Gsteps)；平均 ETH 区块 ~310 Msteps，峰值 ~950 Msteps |
| 分布式 | 支持 coordinator + workers、MPI、gRPC/QUIC hint streaming |
| Proof 系统 | PIL2 STARK over execution trace，Plonky3/FRI 风格 commitment |
| 递归/聚合 | v0.18.0 支持在 guest 程序中验证 ZisK 证明，实现聚合 |
| EVM verifier | GPU Plonk SNARK wrapper：~1 KB proof，~250k gas，<2 s wrap time |

#### 性能与 Precompile

- 宣称 1.5 GHz guest 执行速度和实时以太坊区块证明
- ETHProofs 实时证明数据不完整；行业综述将 ZisK 列在 SP1/Pico 之后的第二梯队
- Precompile：keccak_f、sha256_f、blake2b、poseidon2、secp256k1、secp256r1、BN254/BLS12-381 曲线 & Fp2 操作、256/384-bit 模运算、DMA 内存操作
- **关键缺失**：无专用 BN254 或 BLS12-381 pairing precompile。pairing 通过 `libziskos.a` 中大量低层 field/curve 操作组合实现。

#### 成熟度

- License：Apache-2.0 / MIT 双许可
- **预生产**：每个 release 页面明确标注 "active development"、未审计、未充分测试、请勿用于生产、破坏性变更预期
- 2025 年 6 月从 Polygon 拆出到 SilentSig，~7 名核心开发者

#### 已知用例

- `zisk-eth-client`（Reth-based stateless validator）
- Vocdoni `davinci-zkvm`
- Nethereum EVM→ZisK
- Cysic Venus 硬件 fork
- **无已知生产 zkEVM/rollup**

#### 对 scroll 的适配性

| 需求 | 评估 |
|------|------|
| 多层聚合 | 可行，但需用 ZisK guest-level proof verifier 重新实现聚合，替代 OpenVM `root_verifier.asm`。 |
| EVM verifier | 支持 Plonk wrapper。但需 ~36 GB Plonk proving key + per-program setup key。 |
| 重 precompile | 多数原语存在，但 **BN254/BLS12-381 pairing 是组合的**，对 Scroll chunk/batch 电路是性能/集成风险。 |
| 大 witness | **契合**：1 GB 持久输入流 + streaming hints/pipelining。 |
| Public inputs | ZisK 允许 256 字节 public output；Scroll 已将 PI 哈希为 32 字节，OK。 |
| 生产就绪 | **未就绪**。 |

#### 关键障碍

1. 预生产/未审计，明确标注不适用于生产。
2. 无原生 BN254/BLS12-381 pairing precompile。
3. 不同聚合模型：需替换 OpenVM root verifier。
4. Per-program setup + 大 Plonk key 增加构建/运维开销。
5. 生产 track record 有限。

#### 结论

**ZisK 是有潜力的远期 R&D 目标，但当前不适合替换 OpenVM v1.6。**

- 开源、GPU 加速、分布式设计、可输出 EVM-verifiable Plonk 证明。
- 预生产状态 + 缺少原生 pairing 是决定性障碍。
- 如果 scroll 未来实现了抽象的多后端架构，可将 ZisK 作为实验性后端加入。

---

### 4.4 Airbender (commit 73d69b5)

#### 概况

| 项目 | 内容 |
|------|------|
| ISA | RISC-V RV32I+M，machine-mode，bare-metal，无 `std` |
| Proof 系统 | DEEP STARK/FRI over Mersenne31 (2³¹−1)，BLAKE2s/BLAKE3 hashes |
| 延续性 | 将执行拆分为 ~4M-cycle chunks，通过 memory/delegation arguments 链接 |
| 递归 | 支持：Rust verifier 编译为 RISC-V 并递归证明 |
| SNARK/EVM verifier | **当前 commit 未实现** —— 流程止于递归 STARK artifact |
| 最大程序规模 | ~2³⁰ cycles (~1B cycles) |
| 性能 | H100 上 ~21.8 MHz，RTX 4090 上 ~9.7 MHz；单 H100 证明以太坊区块 ~35 s |

#### Precompile

- 仅 **BLAKE2s/Blake3 rounds** 和 **U256 BigInt**（ADD/SUB/MUL/EQ 等）
- **Keccak256、SHA-256、BN254/BLS12-381 pairing 均无 precompile**
- Keccak 仅在后续 dev release 中加入；pairing 需用 U256 构建或纯 RV32IM 执行，对 zkEVM 极其昂贵

#### 成熟度

- License：Apache-2.0 / MIT 双许可
- 2025 年 6 月发布 beta，Matter Labs 积极维护
- 目标用于 ZKsync Atlas chains

#### 对 scroll 的适配性

| 需求 | 评估 |
|------|------|
| 多层聚合 | Airbender 原生支持单长程序分片和递归压缩；但不直接支持多个独立 chunk proof 聚合为 batch、再 bundle。需自定义 RISC-V verifier guest。 |
| EVM verifier | **当前 commit 无 SNARK wrapper，决定性障碍。** |
| 重 precompile | **缺失 Keccak/SHA-256 和 pairing，决定性障碍。** |
| 大 witness | 通过 nondeterminism CSR / input file 提供；RAM 地址空间 2³⁰ 字节；public output 限制 32 字节（可哈希）。 |

#### 关键障碍

| 障碍 | 严重程度 |
|------|---------|
| 当前 commit 无 SNARK/EVM wrapper | **Critical** |
| 无 Keccak/SHA-256 precompile | **Critical** |
| 无 BN254/BLS12-381 pairing precompile | **Critical** |
| 无内置多程序聚合层 | High |
| 当前 commit 最大 ~2³⁰ cycles | Medium |
| Public output 限制 32 字节 | Low（可哈希） |

#### 结论

**Airbender 当前 commit 不适合 scroll-zkvm-prover。**

- 缺乏链上证明输出和 zkEVM 关键加密 precompile。
- 原始证明速度极快，ISA 与 OpenVM 相同（RV32I+M），未来若加入 SNARK wrapper、Keccak、pairing delegation，可重新评估。

---

## 5. 多 ZKVM 后端支持路线图建议

### 5.1 短期（0–3 个月）

1. **不引入 ere 作为依赖**，但将其 trait 设计作为内部抽象层的参考。
2. **冻结 OpenVM v1.6 主路径**，继续作为唯一生产后端。
3. **在代码中插入 `ZkvmBackend` trait**：
   - 定义于 `crates/prover/src/backend.rs`
   - 方法：`setup`、`execute`、`prove_stark`、`prove_snark`、`get_vk`、`build_guest_input`
4. **将 `Prover` 泛型化**：`Prover<B: ZkvmBackend>` 或 enum dispatcher。
5. **将 OpenVM 现有逻辑封装为 `OpenVmBackend`**，保持行为不变。
6. **Proof 类型抽象**：`ProofEnum` 保留，但内部从具体 OpenVM 类型改为 opaque bytes + 公共元数据。

### 5.2 中期（3–9 个月）

1. **选择 SP1 作为第二后端试点**：
   - 先移植一个简化 chunk circuit，不追求完整功能。
   - 测量证明时间、内存、cycle count、EVM verifier gas。
2. **定义跨后端公共层**：
   - 共享 witness 类型（已存在，保持）
   - 共享 `PublicInputs` 编码
   - 共享 commitment/PI hash 约定
3. **实现 `Sp1Backend`**：
   - SP1 guest 版本的 chunk/batch/bundle circuit
   - SP1 版本的 build-guest 工具
   - SP1 版本的 verifier 适配
4. **并行比较 OpenVM 与 SP1** 在同一 witness 上的性能。

### 5.3 长期（9–18 个月）

1. 根据 SP1 试点结果，决定是否将 RISC Zero 纳入候选池。
2. 持续跟踪 Airbender 和 ZisK 的成熟度：
   - Airbender：等待 SNARK wrapper、Keccak、pairing delegation 稳定。
   - ZisK：等待生产就绪声明、审计、原生 pairing precompile。
3. 建立多后端 CI：每个后端独立构建、独立运行 integration test（chunk→batch→bundle）。
4. 文档化后端切换策略、版本管理、verifier contract 部署流程。

---

## 6. 与 ere 的结合方式（如仍想参考）

### 6.1 不建议直接集成的理由

1. **版本锁定冲突**：ere 锁定 OpenVM v1.4.3，scroll 使用 v1.6.0，OpenVM guest/host 不兼容。
2. **Proof 类型不匹配**：ere 的 `prove()` 返回聚合 STARK，scroll 需要 SNARK/EVM verifier。
3. **缺少多层聚合抽象**：ere 没有 chunk→batch→bundle 的 scaffold。
4. **Guest 模型过简**：ere 的 `Platform` + `Input` 不适合 scroll 复杂 continuation/precompile 电路。

### 6.2 可借鉴的设计元素

| ere 组件 | 可借鉴内容 | scroll 内部化方式 |
|----------|-----------|------------------|
| `Compiler` trait | 统一 guest 编译入口 | `ZkvmBackend::build_guest` |
| `zkVMProver` trait | 统一 execute/prove/verify | `ZkvmBackend` trait |
| `zkVMVerifier` trait | 统一 verify | `BackendVerifier` trait |
| `Platform` trait | guest I/O 抽象 | `GuestPlatform` trait（但需扩展 precompile/continuation） |
| `PublicValues` | 公共输出约定 | 复用现有 `PublicInputs` + 32-byte PI hash |
| Dockerized / gRPC | SDK-free 使用 | 未来可作为 build/proving farm 的封装 |

### 6.3 最小引用方式

如果团队仍希望与 ere 保持联系：
- 订阅 ere 的 release，观察其 OpenVM 版本升级和 SNARK/EVM 抽象进展。
- 在内部 trait 设计时参考 ere 的接口签名，但不直接引入 crate。
- 可将 ere 作为跨 zkVM 基准测试工具，用于简单程序（非完整 zkEVM）的性能对比。

---

## 7. 风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 引入第二后端导致代码复杂度剧增 | 高 | 先抽象 trait 层，保持 OpenVM 主路径稳定；第二后端从 PoC 开始 |
| Guest 重写引入 bug | 高 | 与 OpenVM 版本共享 witness/PublicInputs 规范；双跑对比验证 |
| 不同后端的 proof format / verifier contract 管理复杂 | 中 | 每个后端独立 release 目录、独立 verifier 部署脚本 |
| 版本升级敏感（OpenVM/SP1 均如此） | 中 | 建立版本锁定、缓存清理、强制重建 SOP（参考 `AGENTS.md`） |
| 运维/硬件成本增加 | 中 | 明确各后端硬件要求；优先本地 GPU，谨慎使用第三方 proving network |
| Airbender/ZisK 不成熟导致投入浪费 | 高 | 不投入生产开发，仅跟踪；纳入决策看板 |

---

## 8. 附录

### 8.1 调研过程中产生的文档

| 文件 | 内容 |
|------|------|
| `docs/ere-raw-notes.md` | ere 仓库原始调研笔记 |
| `docs/risc0-raw-notes.md` | RISC Zero 原始笔记 |
| `docs/risc0-assessment-report.md` | RISC Zero 评估报告 |
| `docs/sp1-raw-notes.md` | SP1 原始笔记 |
| `docs/zisk-raw-notes.md` | ZisK 原始笔记 |
| `docs/airbender-raw-notes.md` | Airbender 原始笔记 |

### 8.2 关键参考链接

- ere: https://github.com/eth-act/ere
- SP1: https://github.com/succinctlabs/sp1
- RISC Zero: https://github.com/risc0/risc0
- ZisK: https://github.com/0xPolygonHermez/zisk
- Airbender: https://github.com/matter-labs/zksync-airbender

### 8.3 术语对照

| 英文 | 中文 |
|------|------|
| zkVM | 零知识虚拟机 |
| STARK | 可扩展透明知识论证 |
| SNARK | 简洁非交互知识论证 |
| Continuation | 延续执行/分段执行 |
| Aggregation | 聚合 |
| Recursion | 递归 |
| Precompile | 预编译合约/加速原语 |
| Pairing | 双线性配对 |
| Verifier contract | 链上验证合约 |
| Witness | 见证数据 |
| Public inputs | 公共输入 |
