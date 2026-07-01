# ZisK 作为第三 ZKVM 后端的可行性评估

> 评估目标：在已经把 **SP1** 作为第二后端（commit `de900716 "sp1"`）之后，评估
> [ZisK](https://github.com/0xPolygonHermez/zisk/releases) v0.18.0 能否作为 `scroll-zkvm-prover`
> 的又一个后端；如果可行，按“框架化 / 通用”的方式接入，方便未来继续拓展。
>
> 评估日期：2026-07-01
> 当前主后端：OpenVM v1.6.0；第二后端：SP1 v6.3.0（隔离在 `sp1/` workspace）
> ZisK 版本：v0.18.0

---

## 0. 一句话结论

**ZisK 在“单层 chunk PoC”意义上可以接入，值得纳入通用后端框架；但一个可上线的
chunk→batch→bundle+EVM 全管道，现在还不是“问题不大”——它被 ZisK 的预生产成熟度、
本机 GPU 证明的既有失败记录、以及不成熟的 guest 内递归所阻塞。**

> **实测更新（2026-07-01）**：本次已把 chunk 层真正落地——真实 chunk guest（`ChunkInfo::try_from`
> 全量区块执行）**成功编译到 ZisK 目标并用 `ziskemu` 跑通**，提交的 32 字节 `pi_hash` 与 SP1
> **逐字节一致**（`0x363c27bd…8abc3ca8`），证明是同一套真实逻辑而非 stub。执行速度对比见
> `docs/benchmark-sp1-vs-zisk.md`；**证明（proving）**在单区块负载下已通过 GPU 跑通（约 100s）。
>
> 此外，**guest 内递归也跑通**：用 GPU 生成单区块 chunk STARK 证明后，batch 层 guest 在
> `ziskemu` 里调用 `zisk-verifier` 成功验证了该子证明，输出首字节为 `1`（VERIFIED）。

因此本次采取的路线：**把后端抽象成通用框架 + 落地一个 ZisK chunk 层脚手架（能编译、能执行、
能尝试证明）**，把 batch/bundle 递归留作显式 TODO，等 ZisK 稳定后再补。

---

## 1. 结论一览

| 维度 | 判断 | 依据 |
|------|------|------|
| 架构可移植性 | ✅ 可行 | RV64IMA，`ziskos` guest I/O 与 SP1 guest 模式一一对应 |
| Host 侧可编程证明 | ✅ 可行 | `zisk-sdk` 提供 `ProverClient::embedded()/.gpu()/.setup()/.execute()/.prove()` |
| 共享业务逻辑复用 | ✅ 可行 | `scroll-zkvm-types-*` 已在 SP1 接入时做成后端无关（`openvm` feature 门控） |
| EVM verifier | ⚠️ 有但重 | STARK→Plonk wrapper（~1KB，~250k gas），需 per-program setup + ~36GB Plonk key |
| 多层递归聚合 | ⚠️ 可工作但不成熟 | v0.18.0 可在 guest 内验证 ZisK 证明，PoC 已跑通；但 API/文档少，batch 层仍需 blob-KZG |
| 成熟度 | ❌ 预生产 | 每个 release 页面显式标注 未审计 / 勿用于生产 / 预期破坏性变更 |
| 本机 GPU 证明 | ⚠️ 单区块可通，大负载未稳 | 单区块 chunk（604M steps）GPU 约 100s 并验证成功；此前 6 区块/旧版本有失败史 |
| pairing precompile | ⚠️ 组合实现 | 无专用 BN254/BLS12-381 pairing CSR（SP1 同样无专用 pairing syscall） |

---

## 2. ZisK 与现有后端的架构映射

| 层次 | OpenVM v1.6 | SP1 v6.3 | ZisK v0.18 |
|------|-------------|----------|------------|
| ISA | RV32IMA | RV64IMA | RV64IMA（`riscv64ima-zisk-zkvm-elf`） |
| Guest 入口 | `openvm::entry!` | `sp1_zkvm::entrypoint!` | `ziskos::entrypoint!` |
| Guest 读输入 | `openvm::io::read_vec` | `sp1_zkvm::io::read_vec` | `ziskos::io::read()/read_input_slice()` |
| Guest 提交 PI | `reveal_bytes32` | `io::commit_slice` | `ziskos::io::commit(&..)` |
| Host 证明 API | `openvm-sdk` `Sdk` | `sp1-sdk` `CudaProver` | `zisk-sdk` `ProverClient::embedded()` |
| 基础证明 | STARK(Plonky3) | STARK(Plonky3/BabyBear) | STARK(PIL2/Proofman/Plonky3) |
| 递归 | `root_verifier.asm` | `verify_sp1_proof` + `write_proof` | guest 内验证 zisk 证明（新、少文档） |
| EVM SNARK | Halo2-KZG | gnark Groth16/Plonk | GPU Plonk wrapper |
| Guest 编译 | `cargo openvm build` | `sp1_build::build_program_with_args` | `cargo-zisk build` |
| 公共输出上限 | 32B(padded) | 无限(哈希成 digest) | 256B buffer |

**要点**：guest 端 I/O 与 host 端可编程证明这两个最关键的“可接入性”维度，ZisK 都具备，
而且和 SP1 的接入形状高度相似——这正是把后端框架化后能低成本容纳 ZisK 的原因。

---

## 3. 复用现有共享层

SP1 接入时已经把业务逻辑与 OpenVM 解耦，ZisK 可以直接复用，无需再改主 workspace 逻辑：

- `scroll-zkvm-types-base`：`PublicInputs` / `Version` / `ChunkInfo` / `BatchInfo` / `BundleInfo`。
- `scroll-zkvm-types-chunk`（`scroll` feature，不开 `openvm`）：`ChunkWitness` + `ChunkInfo::try_from`。
- `scroll-zkvm-types-batch` / `-bundle`：batch/bundle 见证与校验逻辑。
- OpenVM 专用 crypto 已在 `openvm` feature 后面；ZisK guest 走 `alloy-primitives`
  的 `native-keccak`（ZisK 通过 syscall 加速 keccak），与 reth guest 用法一致。

因此 ZisK 的 chunk guest 本质上就是：`ziskos::io` 读 `ChunkWitness` 字节 →
`bincode` 反序列化 → `ChunkInfo::try_from` → `(chunk_info, version).pi_hash()` →
`ziskos::io::commit(pi_hash)`。与 `sp1/circuits/chunk-circuit/src/main.rs` 逐行对应。

---

## 4. GPU 证明：从“历史失败”到“单区块可通”

本机 `~/kunxian/zkvm-arena` 里保留了此前用 `cargo-zisk prove --gpu` 在**同一台 4×RTX 3090**
上跑 `zisk-eth-client` 区块证明的日志。三个版本全部在“证明”阶段失败：

| 版本 | 结果 | 失败点 |
|------|------|--------|
| v0.16.0 | 失败 | `Service mt failed to respond to ping` / `Connection refused (127.0.0.1:23116)`（ASM microservice 起不来） |
| v0.17.0 | 失败 | `EXECUTE` ok(1.3s) → `CALCULATING_CONTRIBUTIONS`(196s) → `GENERATING_INNER_PROOFS` 崩溃：`Failed assert in template/function VerifyEvaluations0`，witness generation failed / abort |
| v0.18.0 | 失败 | 证明日志为空（0 字节），`metrics: {}`，未产出证明 |

**本次（2026-07-01） reinstall v0.18.0 + 下载 STARK proving key 后重新测试：**

| 负载 | 参数 | 结果 | 耗时 |
|------|------|------|------|
| bundle stub, 16k steps, CPU, `-c -l` | minimal + prebuilt emulator | ✅ 成功 | 106s |
| chunk, block 20239240, GPU, default | `-g`, full STARK | ✅ 成功并验证 | 99.9s |
| chunk, blocks 20239240–41, GPU, default | `-g`, full STARK | ✅ 成功并验证 | 149.1s |
| chunk, blocks 20239240–45, GPU, `-m` | `-g -m`, low-memory full STARK | ⏹️ 手动中止（witness 生成过慢，>5min 未进 proof 阶段） | >300s |
| chunk, CPU, default | 无 `-g` | ❌ ASM microservice semaphore `WaitTimeout` |
| chunk, CPU, `-l` | prebuilt emulator | ❌ `EmuContext::new() input size must be a multiple of 8`（输入未 8 字节对齐） |

**关键发现**

1. **输入文件必须 8 字节对齐**。`cargo-zisk prove -i` 默认把文件内容直接喂给 guest；我们的 chunk
   guest 使用 ZisK-framed 输入（`[u64 LE len][payload][pad to 8]`），其长度天然 8 对齐，所以无问题。
   bundle stub 的测试输入只有 4 字节，导致 prebuilt emulator panic。
2. **ASM microservice 在本机 CPU 路径上不稳定**。默认（ASM runner）的小负载证明会 semaphore
   `WaitTimeout`；加上 `-l` 使用 prebuilt emulator 后可绕过。
3. **GPU 证明对单/双区块 chunk 可用**。604M steps 约 100s，1.08B steps 约 149s，
   均 `-y` 验证通过。6 区块（3B steps）`-m` 低内存模式 witness 生成过慢（5min 未进 proof
   阶段），说明大负载要么需要更长时间，要么需要其他参数（`-c` minimal 会延长证明时间、
   `-x` 限制 witness 内存）或更高规格的 GPU 显存。
4. **guest 内递归可用**。用生成的单/双区块 chunk 证明喂给 batch guest，batch guest 在
   `ziskemu` 中调用 `zisk-verifier` 的 `verify_vadcop_final_proof`，约 2s 返回 VERIFIED。

---

## 5. 其他工程成本

1. **工具链需重装**：`rustup` 里 `zisk` toolchain 是悬空链接（`~/.zisk` 已被清理）。需
   `ziskup -v 0.18.0` 重新安装 `cargo-zisk`/`ziskemu`/toolchain。
2. **证明 key 体积大**：STARK proving key 需 `--provingkey` 下载 + 生成 constant tree；
   EVM/Plonk 还需 `ziskup setup_snark` 的 ~36GB SNARK key。本机剩余磁盘 ~151G，够用但需留意。
3. **per-program setup**：每个 guest ELF 证明前要 `cargo-zisk program-setup -e elf`（ROM setup）。
4. **真实区块执行的 chunk guest**：实测**已能用主仓库现成的 `scroll-tech/revm`（scroll-v91）
   + 一个 getrandom 0.3 shim 编译并链接到 ZisK 目标**，无需 ZisK 专用的 revm/alloy patch
   （比预期乐观）。唯一的坑是 `cargo-zisk build` 会覆盖 `RUSTFLAGS`（导致 `.cargo/config.toml`
   的 rustflags 被忽略），以及 ziskos 只注册了 getrandom 0.2 后端、graph 又拉了 getrandom 0.3
   —— 均已在 `zisk/` 脚手架里解决并记录。
5. **递归聚合**：batch guest 已能调用 `zisk-verifier::verify_vadcop_final_proof` 验证子 chunk
   证明（单区块已跑通），但 batch 层仍需实现 Scroll 的 batch 校验（blob-KZG 等），bundle 层
   仍需 EVM Plonk wrap。API/文档少，属于继续推进而非已完成的点。

---

## 6. 采取的落地方式（框架化 / 通用）

为了“方便未来拓展”，本次不是只为 ZisK 写一次性代码，而是抽出一个后端无关的接口层：

- **主 workspace 新增 `crates/backend`（`scroll-zkvm-backend`）**：定义后端无关的
  `ZkvmBackend` trait（`setup/execute/prove_stark/prove_snark/verify/build_guest_input`）
  与中立的 `ProofEnum`/`ProgramKey`/`ProofStat`（不透明字节 + 元数据）。纯类型与 trait，
  不依赖任何 zkVM SDK，不触碰 OpenVM 证明路径。
- **约定并行的隔离后端 workspace**：`sp1/` 与新增的 `zisk/` 结构对称，各自解决自己的
  revm/alloy 依赖图，共同复用 `crates/types/*` 与 `crates/backend`。
- **`zisk/` 脚手架**：`circuits/{chunk,batch,bundle}-circuit`（chunk 为真实逻辑；batch 为
  可编译的递归验证 PoC，已能验证子 chunk 证明；bundle 为可编译 stub + `TODO(recursion)`）、
  `build-guest/`（产出 ZisK ELF）、`prove-zisk/`（`zisk-sdk` host，复用 SP1 的 `witness.rs`）、
  `recursion-test/`（guest 内递归 PoC 的 host 驱动）、`.cargo/config.toml`、`AGENTS.md`、Makefile targets。

这样“再加第 N 个后端”的路径是机械的：复制一个后端 workspace + 实现 `ZkvmBackend`。

---

## 7. 分阶段建议

1. **现在（本次交付）**：通用后端框架 + ZisK chunk 脚手架（可编译/可执行/可证明单区块）+
   guest 内递归 PoC（batch 验证子 chunk 证明）+ SP1↔ZisK 执行速度对比 + 证明阶段如实记录。
2. **近期**：调优 6 区块等大负载的 GPU 证明参数（`-c` minimal / `-m` 低内存 / `-x` witness
   上限），拿到完整 chunk 证明速度；补齐 per-program setup 成本。
3. **中期**：在 batch guest 中实现 Scroll 的 batch 校验（blob-KZG 等），并评估 bundle 层
   EVM Plonk 输出。
4. **长期**：如 ZisK 发布稳定版并完成审计，纳入多后端 CI，与 OpenVM/SP1 一起做 like-for-like 对比。

---

## 8. 关键来源

- ZisK releases：https://github.com/0xPolygonHermez/zisk/releases
- ZisK 原始调研笔记：`docs/zisk-raw-notes.md`
- 多后端调研总报告：`docs/multi-zkvm-backend-research.md`
- SP1 接入参考：`sp1/AGENTS.md`、`sp1/prover-test/src/main.rs`
- 本机 ZisK 证明失败日志：`~/kunxian/zkvm-arena/results/zisk/*/*.log`
- SP1↔ZisK 速度对比：`docs/benchmark-sp1-vs-zisk.md`
