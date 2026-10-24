# Xplay6 8.19.16 root 路线 v3（2026-10-23，KGSL UAF 前提被二进制证伪）

## v2 的错误（已用设备镜像反汇编证伪）
- **KGSL 目标 context 有引用计数，不存在"detach 后 stale context"UAF**。
  `kgsl_cmdbatch_add_sync_timestamp`@0x5393c0 实证：
  1) `idr_find(device->context_idr@0xa50, sync->context_id)`（fast path 读 `[device+0xa50]`）
  2) 检查 `[ctx+0x20]` bit1（PRIV_DETACHED）；已 detach → 直接 -EINVAL
  3) **`_kgsl_context_get` 内联原子自增 `[ctx+0]`**（0x539670-0x5396a8，refcount==0 → 失败）
  4) 写入 synclist：id@0 / type=0(TIMESTAMP)@4 / cmdbatch@8 / context@0x10 / timestamp@0x18 / device@0x30
  5) `kgsl_add_event(device, ctx+0x40, ts, kgsl_cmdbatch_sync_func, &synclist[id])`（再 +1 ref）
  → 事件 pending 期间 ctx 至少被 2 个 ref 持有；`kgsl_context_detach.part.23`@0x52f7f0 的顺序是
  `drawctxt_detach → kgsl_cancel_events(ctx+0x40) → kgsl_del_event_group → refcount-- → (==0)kgsl_context_destroy`，
  owner ref 最后才放 → **整个 destroy/flush 期间 ctx 不会被释放**。
- 因此 v2 的 A/B 路线（stale group 被回收后走到 4 参数调用）**没有入口**，作废。
- E1 实验（Y==X 判据）**设计无效**：新 2215 周期的 binder_thread kzalloc 本身就会优先拿到刚被 destroy 释放的 synclist 块，
  无论 synclist 当初是否落在 X，Y 都会等于 X（混淆）。

## 仍然成立的资产（实测/反汇编）
- **CVE-2019-2215 泄漏 320/320**：free binder_thread(kmalloc-512) → SO_ATTACH_FILTER kmemdup(496) 占位 →
  close(epfd) 的 list_del 把 chunk+0xA0 写回自身 → SO_GET_FILTER 读出 chunk 地址 X。**只有泄漏，没有任意写。**
- **无 PAN / 无 SW-PAN**（config: `# CONFIG_ARM64_PAN is not set`、`# CONFIG_ARM64_SW_TTBR0_PAN is not set`）
  → 内核可直接解引用用户态指针（读；PXN 仍禁止执行用户代码）。这意味着：一旦拿到任何"内核按指针走链"的入口，
  链可以指向用户内存（自建假 event/argv），无需知道内核堆地址。
- **KGSL 事件 walk 精确语义**（kgsl_cancel_events@0x5452e8，无条件 signal）：
  group->events.next@group+0x10 → event = node-0x28；循环判据 `&event->node != &group->events`；
  list_del 写 `*(node.next+8)=node.prev; *(node.prev)=node.next`，随后写 POISON 到 node；
  `event->result=2`；`queue_kthread_work(0xffffffc0018746b8 /*静态 kthread_worker*/, event+0x40)`。
  `_kgsl_event_worker` → `func(event->device, event->group, event->priv, event->result)` 四参数全可控。
- `_process_event_group`@0x545488：group 布局 context@0 / lock@8 / events@0x10 / processed@0x30 /
  **readtimestamp@0x78 / priv@0x80**；flush 分支不调用 readtimestamp，直接 signal 全部事件。
- `_kgsl_event_worker` 需要 work.func 位于 event+0x50（= _kgsl_event_worker 0xffffffc0005456cc）。
- /dev/kgsl-3d0 0666，shell 可 open/ioctl；kgsl_fops **没有 .poll**（不能 epoll 注册 context 内 waitqueue）。
- shell 不可读 dmesg/kptr_restrict/kallsyms(全0)/modprobe/core_pattern/sysfs kgsl/debugfs；perf_event_paranoid=3。

## 结论：缺的不是"调用原语"，而是"一个悬垂指针"
- 只要能让内核沿一个指向已释放对象（已被我们内容可控地回收）的指针走一次链表，就能：
  1) 把 events.next 指向**用户态**假 event（地址已知），
  2) 假 event 的 node.next 指回链尾（可用用户态自环 + 以用户地址为终点，本次接受"回调入队后 fault"，PANIC_ON_OOPS 未开启），
  3) work.func=_kgsl_event_worker，func=call_usermodehelper，path/argv/envp 全在用户内存，
  4) 回调在 kworker 上执行，与触发线程是否 oops 无关。
- 所以下一步的唯一重点是：**找一个 shell 可达的 use-after-free / 悬垂指针**（不要求任意写）。

## 候选面（按可达性排序）
1. **/dev/ashmem（0666，shell 可读写）**：ASHMEM_SET_NAME/SIZE/PIN/UNPIN 的并发与 mmap vm_ops 生命周期。
2. **/dev/hwbinder（0666）**：hwbinder 是独立 binder 实例，同样存在 thread/proc 生命周期路径。
3. /dev/ion（0644，只能 O_RDONLY 打开，仍需确认 ioctl 是否检查 FMODE_WRITE / SELinux）。
4. binder 本体其它对象（binder_node/binder_ref/binder_transaction）的释放顺序。
5. KGSL 其它生命周期（event 对象双重 free、cmdbatch 竞态）——本已证明 context 侧无 UAF。

## 下一步（具体）
- **N1**：静态审计 ashmem 驱动（镜像内符号 + 源码对比），确认是否存在 shell 可触发的 UAF/越界；
  先看 `ashmem_ioctl` 的 ASHMEM_PIN/UNPIN 与 `ashmem_mmap`/`ashmem_vm_close` 的引用关系。
- **N2**：若 N1 无果，审计 hwbinder 与 binder 的 release 路径（thread/proc），找"free 后仍被引用"的对象。
- **N3**：一旦找到悬垂指针，按上面的"用户态链"方案落地；root 后走 firewall 持久化
  （/data/data/com.iqoo.secure.datausage/app_bin/droidwall.sh + 月虹 sud）。

## 安全注意
- 失败若落入 spinlock 内无限自旋会锁死 CPU；尽量让链在用户态可终止（末节点 next 指回已知用户地址）。
- worker 尾部 `kmem_cache_free(events_cache, 假event)` 会污染 slab —— 只允许在回调已入队后发生。
