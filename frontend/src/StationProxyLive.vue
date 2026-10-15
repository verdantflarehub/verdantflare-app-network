<script setup lang="ts">
import {
  computed,
  onMounted,
  onUnmounted,
  ref,
  reactive,
  watch,
  nextTick,
} from "vue";
import {
  api,
  payload,
  exportData,
  parseImport,
  message,
  exitProfile,
  type ProxyItem,
  type ProxyInput,
  type ImportRow,
  type Observation,
} from "./egress";
import { host, isActive, subscribeLifecycle } from "./host";
const rows = ref<ProxyItem[]>([]),
  loading = ref(true),
  loadError = ref(""),
  notice = ref(""),
  actionError = ref("");
const search = ref(""),
  protocol = ref(""),
  status = ref(""),
  selected = ref<string[]>([]);
const drawerID = ref(""),
  editing = ref<ProxyItem | null>(null),
  modal = ref<"edit" | "import" | "delete" | "toggle" | "export" | null>(null);
const saving = ref(false),
  running = ref(new Set<string>()),
  deleting = ref<ProxyItem | null>(null);
const importText = ref(""),
  imported = ref<ImportRow[]>([]);
const form = reactive({
  name: "",
  protocol: "socks5",
  host: "",
  port: 7891,
  username: "",
  password: "",
  clear_auth: false,
  tag: "",
  note: "",
  expires_at: "",
});
const detail = computed(() =>
  rows.value.find((r) => r.proxy_id === drawerID.value),
);
const isTesting = (r: ProxyItem) => r.testing || running.value.has(r.proxy_id);
const expired = (r: ProxyItem) =>
  !!r.expires_at && Date.parse(r.expires_at) <= Date.now();
const state = (r: ProxyItem) =>
  r.status === "off"
    ? "off"
    : expired(r)
      ? "expired"
      : isTesting(r)
        ? "testing"
        : r.probe?.status === "failed"
          ? "failed"
          : r.status;
const stateNames: Record<string, string> = {
  active: "连通通过",
  pending: "待检测",
  off: "已停用",
  testing: "检测中",
  failed: "检测失败",
  expired: "已过期",
};
const filtered = computed(() =>
  rows.value.filter(
    (r) =>
      (!search.value ||
        `${r.name} ${r.host} ${r.tag}`
          .toLowerCase()
          .includes(search.value.toLowerCase())) &&
      (!protocol.value || r.protocol === protocol.value) &&
      (!status.value || state(r) === status.value),
  ),
);
const active = computed(
  () => rows.value.filter((r) => state(r) === "active").length,
);
const recent = computed(() =>
  rows.value
    .map((r) => r.probe?.finished_at)
    .filter((v): v is string => !!v)
    .sort()
    .at(-1),
);
const page = ref(1),
  pageSize = ref(10),
  menuID = ref("");
const pages = computed(() =>
  Math.max(1, Math.ceil(filtered.value.length / pageSize.value)),
);
const visibleRows = computed(() =>
  filtered.value.slice(
    (page.value - 1) * pageSize.value,
    page.value * pageSize.value,
  ),
);
const allSelected = computed(
  () =>
    visibleRows.value.length > 0 &&
    visibleRows.value.every((r) => selected.value.includes(r.proxy_id)),
);
const exportRows = computed(() =>
  selected.value.length
    ? filtered.value.filter((r) => selected.value.includes(r.proxy_id))
    : filtered.value,
);
const readAt = ref(""),
  batchBusy = ref(false),
  authMode = ref("none");
const pendingCount = computed(
  () => rows.value.filter((r) => r.status === "pending" && !r.probe).length,
);
const initialForm = ref("");
watch([search, protocol, status, pageSize], () => {
  page.value = 1;
  selected.value = [];
  menuID.value = "";
});
watch(page, () => {
  selected.value = [];
  menuID.value = "";
});
watch(pages, (value) => {
  if (page.value > value) page.value = value;
});
const endpoint = (r: ProxyItem) =>
  `${r.protocol}://${r.host.includes(":") ? `[${r.host}]` : r.host}:${r.port}`;
function askToggle(row: ProxyItem) {
  deleting.value = row;
  menuID.value = "";
  actionError.value = "";
  modal.value = "toggle";
}
function clearFilters() {
  search.value = "";
  protocol.value = "";
  status.value = "";
}
function openImport() {
  imported.value = [];
  actionError.value = "";
  modal.value = "import";
}
let listScroll = 0;
function openDetail(id: string) {
  listScroll = window.scrollY;
  menuID.value = "";
  drawerID.value = id;
  void nextTick(() =>
    document.querySelector<HTMLElement>(".detail-heading h1")?.focus(),
  );
}
function returnToList() {
  drawerID.value = "";
  void nextTick(() => {
    window.scrollTo(0, listScroll);
    document.querySelector<HTMLElement>(".proxy-name")?.focus();
  });
}

const date = (v?: string | null) =>
  v
    ? new Date(v).toLocaleString("zh-CN", {
        hour12: false,
        timeZone: "Asia/Shanghai",
      })
    : "尚无记录";
const flag = (v: boolean | null | undefined) =>
  v === true ? "来源已标记" : v === false ? "来源未标记" : "未知";
const location = (o?: Observation) =>
  [o?.country, o?.region, o?.city].filter(Boolean).join(" / ") || "未获取";
const profiles = computed(() =>
  Object.fromEntries(
    rows.value.map((row) => [row.proxy_id, exitProfile(row.probe)]),
  ),
);
const flagFiles = import.meta.glob<string>(
  "../node_modules/flag-icons/flags/4x3/*.svg",
  { eager: true, query: "?raw", import: "default" },
);
const flagURL = (code: string) => {
  const svg =
    flagFiles[`../node_modules/flag-icons/flags/4x3/${code.toLowerCase()}.svg`];
  return svg ? `data:image/svg+xml,${encodeURIComponent(svg)}` : undefined;
};
const geoTitle = (row: ProxyItem) => {
  const p = profiles.value[row.proxy_id];
  return p.geo
    ? `位置来源：${p.geo.source}${p.fallback ? "（备用来源）" : ""}${row.probe?.location_conflict ? "；来源存在差异，见详情" : ""}`
    : "尚无可用地理观测";
};
function replace(row: ProxyItem) {
  const index = rows.value.findIndex((r) => r.proxy_id === row.proxy_id);
  if (index < 0) rows.value.unshift(row);
  else rows.value[index] = row;
}
let loadGeneration = 0;
async function refresh() {
  const generation = ++loadGeneration;
  loading.value = true;
  loadError.value = "";
  try {
    const result = await api<{ items: ProxyItem[] }>();
    if (generation !== loadGeneration || !isActive()) return;
    rows.value = result.items;
    readAt.value = new Date().toISOString();
    selected.value = selected.value.filter((id) =>
      rows.value.some((r) => r.proxy_id === id),
    );
  } catch (e) {
    if (generation === loadGeneration && isActive())
      loadError.value = (e as Error).message;
  } finally {
    if (generation === loadGeneration) loading.value = false;
  }
}
function edit(row?: ProxyItem) {
  editing.value = row || null;
  actionError.value = "";
  menuID.value = "";
  Object.assign(
    form,
    row
      ? {
          ...payload(row),
          username: "",
          password: "",
          clear_auth: false,
          expires_at: row.expires_at
            ? new Date(
                Date.parse(row.expires_at) -
                  new Date(row.expires_at).getTimezoneOffset() * 60000,
              )
                .toISOString()
                .slice(0, 16)
            : "",
        }
      : {
          name: "",
          protocol: "socks5",
          host: "",
          port: 7891,
          username: "",
          password: "",
          clear_auth: false,
          tag: "",
          note: "",
          expires_at: "",
        },
  );
  authMode.value = row?.auth_configured ? "keep" : "none";
  initialForm.value = JSON.stringify({ form, auth: authMode.value });
  modal.value = "edit";
}
async function save(andTest = false) {
  saving.value = true;
  actionError.value = "";
  notice.value = "";
  try {
    const input: ProxyInput = {
      name: form.name,
      protocol: form.protocol,
      host: form.host,
      port: Number(form.port),
      tag: form.tag,
      note: form.note,
      expires_at: form.expires_at
        ? new Date(form.expires_at).toISOString()
        : "",
      ...(editing.value ? { revision: editing.value.revision } : {}),
    };
    if (authMode.value === "remove") input.clear_auth = true;
    else if (authMode.value === "replace") {
      input.username = form.username;
      input.password = form.password;
    }
    const saved = (
      await api<{ item: ProxyItem }>(
        editing.value ? `/${editing.value.proxy_id}` : "",
        editing.value ? "PUT" : "POST",
        input,
      )
    ).item;
    replace(saved);
    modal.value = null;
    form.username = "";
    form.password = "";
    notice.value = "代理已保存，待检测。";
    if (andTest) {
      await test(saved);
      if (actionError.value)
        actionError.value = `已保存，检测未完成：${actionError.value}`;
    }
  } catch (e) {
    actionError.value = (e as Error).message;
  } finally {
    saving.value = false;
  }
}
async function test(row: ProxyItem) {
  if (isTesting(row) || row.status === "off" || expired(row)) return;
  running.value.add(row.proxy_id);
  actionError.value = "";
  notice.value = "";
  try {
    const item = (
      await api<{ item: ProxyItem }>(`/${row.proxy_id}/test`, "POST", {})
    ).item;
    replace(item);
    notice.value =
      item.probe?.status === "passed"
        ? "连通检测完成，请查看实测出口及 IP 库来源。"
        : "代理检测失败，请查看各次检测结果。";
  } catch (e) {
    actionError.value = (e as Error).message;
  } finally {
    running.value.delete(row.proxy_id);
  }
}
async function batch() {
  batchBusy.value = true;
  let passed = 0,
    failed = 0,
    skipped = 0;
  try {
    for (const id of [...selected.value]) {
      const row = rows.value.find((r) => r.proxy_id === id);
      if (
        !isActive() ||
        !row ||
        row.status === "off" ||
        expired(row) ||
        isTesting(row)
      ) {
        skipped++;
        continue;
      }
      await test(row);
      const result = rows.value.find((r) => r.proxy_id === id);
      if (!actionError.value && result?.probe?.status === "passed") passed++;
      else failed++;
    }
    notice.value = `批量检测完成：通过 ${passed} 条，失败 ${failed} 条，未执行 ${skipped} 条。`;
  } finally {
    batchBusy.value = false;
  }
}

async function toggle(row: ProxyItem) {
  if (saving.value) return;
  saving.value = true;
  actionError.value = "";
  notice.value = "";
  try {
    replace(
      (
        await api<{ item: ProxyItem }>(`/${row.proxy_id}`, "PUT", {
          ...payload(row),
          status: row.status === "off" ? "pending" : "off",
        })
      ).item,
    );
    notice.value =
      row.status === "off" ? "代理已启用，待检测。" : "代理已停用。";
    modal.value = null;
  } catch (e) {
    actionError.value = (e as Error).message;
  } finally {
    saving.value = false;
  }
}
function selectAll() {
  selected.value = allSelected.value
    ? selected.value.filter(
        (id) => !visibleRows.value.some((r) => r.proxy_id === id),
      )
    : [
        ...new Set([
          ...selected.value,
          ...visibleRows.value.map((r) => r.proxy_id),
        ]),
      ];
}
function askDelete(row: ProxyItem) {
  if (row.assigned_apps.length) return;
  menuID.value = "";
  deleting.value = row;
  modal.value = "delete";
  actionError.value = "";
}
async function remove() {
  if (!deleting.value) return;
  saving.value = true;
  try {
    await api(`/${deleting.value.proxy_id}`, "DELETE");
    rows.value = rows.value.filter(
      (r) => r.proxy_id !== deleting.value!.proxy_id,
    );
    selected.value = selected.value.filter(
      (id) => id !== deleting.value!.proxy_id,
    );
    drawerID.value = "";
    modal.value = null;
    notice.value = "代理已删除";
  } catch (e) {
    actionError.value = (e as Error).message;
  } finally {
    saving.value = false;
  }
}
function exportFile() {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(exportData(exportRows.value), null, 2)], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `station-proxies-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  modal.value = null;
  notice.value = "脱敏文件已生成并启动下载，不包含认证凭据。";
}
function preview() {
  actionError.value = "";
  notice.value = "";
  try {
    imported.value = parseImport(importText.value, rows.value);
  } catch (e) {
    imported.value = [];
    actionError.value = (e as Error).message;
  }
}
async function importFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  if (file.size > 256 * 1024) {
    actionError.value = "文件不能超过 256 KiB";
    return;
  }
  importText.value = await file.text();
  preview();
}
async function commitImport() {
  saving.value = true;
  for (const item of imported.value) {
    if (!isActive()) break;
    if (item.state !== "valid" || !item.input) continue;
    try {
      replace((await api<{ item: ProxyItem }>("", "POST", item.input)).item);
      item.state = "imported";
      item.detail = "已保存；请检测，认证未导出的记录需补填";
    } catch (e) {
      item.state = "failed";
      item.detail = (e as Error).message;
    }
  }
  importText.value = "";
  for (const item of imported.value)
    if (item.input) {
      delete item.input.username;
      delete item.input.password;
    }
  saving.value = false;
}
function closeModal() {
  if (saving.value) return;
  if (
    modal.value === "edit" &&
    JSON.stringify({ form, auth: authMode.value }) !== initialForm.value &&
    !window.confirm("放弃未保存的代理配置？")
  )
    return;
  modal.value = null;
  actionError.value = "";
  form.username = "";
  form.password = "";
  importText.value = "";
  imported.value = [];
}
function keydown(event: KeyboardEvent) {
  if (event.key === "Escape") {
    if (modal.value) closeModal();
    else menuID.value = "";
  }
}
let previousFocus: HTMLElement | null = null;
watch(modal, async (value) => {
  if (value) {
    previousFocus = document.activeElement as HTMLElement;
    document.body.style.overflow = "hidden";
    await nextTick();
    document.querySelector<HTMLDialogElement>(".proxy-modal")?.showModal();
  } else {
    document.body.style.overflow = "";
    previousFocus?.focus();
  }
});
let unsubscribe = () => {},
  unsubscribeRoute = () => {};
let applyingRoute = false;
function applyRoute(route: { path: string; revision: number }) {
  const parsed = new URL(route.path, "https://app.invalid");
  const proxy = parsed.searchParams.get("proxy") || "";
  applyingRoute = true;
  drawerID.value = /^[a-f0-9-]{36}$/.test(proxy) ? proxy : "";
  applyingRoute = false;
}
onMounted(() => {
  document.addEventListener("keydown", keydown);
  applyRoute(host().appSDK.navigation.get());
  unsubscribeRoute = host().appSDK.navigation.subscribe(applyRoute);
  void refresh();
  unsubscribe = subscribeLifecycle((event) => {
    if (event === "active") void refresh();
    else {
      loadGeneration++;
      loading.value = false;
    }
  });
});
onUnmounted(() => {
  document.removeEventListener("keydown", keydown);
  document.body.style.overflow = "";
  unsubscribe();
  unsubscribeRoute();
  form.username = "";
  form.password = "";
  importText.value = "";
  imported.value = [];
});
watch(
  drawerID,
  (value) => {
    if (!applyingRoute && isActive())
      void host()
        .appSDK.navigation.request({
          target: "app",
          path: value ? `/?proxy=${encodeURIComponent(value)}` : "/",
        })
        .catch(() => {
          actionError.value = "页面跳转未完成，请重试";
        });
  },
  { flush: "sync" },
);
watch(
  [modal, saving, importText, () => JSON.stringify(form)],
  () =>
    host().dashboardHost.setDirty(
      saving.value ||
        (modal.value === "edit" &&
          JSON.stringify({ form, auth: authMode.value }) !==
            initialForm.value) ||
        !!importText.value,
    ),
  { flush: "sync" },
);
</script>

<template>
  <div class="proxy-page">
    <main class="network-main">
      <div class="workspace proxy-workspace">
        <header class="heading" :class="{ 'detail-heading': drawerID }">
          <div class="heading-left">
            <button v-if="drawerID" class="back-link" @click="returnToList">
              ← 网络出口
            </button>
            <h1 tabindex="-1">
              {{ drawerID ? detail?.name || "代理详情" : "网络出口" }}
            </h1>
            <p>
              {{
                drawerID
                  ? "代理配置与最近检测结果"
                  : "管理代理，检查真实出口、连接质量与 IP 信息。"
              }}
            </p>
          </div>
          <div class="heading-actions">
            <template v-if="!drawerID"
              ><button class="btn" :disabled="loading" @click="refresh">
                {{ loading ? "读取中…" : "刷新状态" }}</button
              ><button class="btn primary" @click="edit()">
                ＋ 添加代理
              </button></template
            ><template v-else-if="detail"
              ><button
                class="btn primary"
                :disabled="
                  isTesting(detail) ||
                  detail.status === 'off' ||
                  expired(detail)
                "
                @click="test(detail)"
              >
                {{ isTesting(detail) ? "检测中…" : "检测" }}</button
              ><button class="btn" @click="edit(detail)">编辑</button
              ><button class="btn" @click="askToggle(detail)">
                {{ detail.status === "off" ? "启用" : "停用" }}</button
              ><button
                class="btn danger"
                :disabled="!!detail.assigned_apps.length || isTesting(detail)"
                :title="detail.assigned_apps.length ? '被引用，无法删除' : ''"
                @click="askDelete(detail)"
              >
                删除
              </button></template
            >
          </div>
        </header>
        <p v-if="notice" class="feedback" role="status">{{ notice }}</p>
        <p v-if="actionError && !modal" class="feedback error" role="alert">
          {{ actionError }}
        </p>
        <p v-if="loadError && rows.length" class="feedback warn" role="alert">
          刷新失败，以下为上次读取数据（{{ date(readAt) }}）：{{ loadError }}
          <button class="back-link" @click="refresh">重试</button>
        </p>
        <template v-if="!drawerID">
          <section class="proxy-metrics" aria-label="代理概览">
            <article>
              <span>代理总数</span
              ><strong>{{ loading && !readAt ? "—" : rows.length }}</strong>
            </article>
            <article>
              <span>连通通过</span
              ><strong class="ok">{{
                loading && !readAt ? "—" : active
              }}</strong>
            </article>
            <article>
              <span>待检测</span
              ><strong>{{ loading && !readAt ? "—" : pendingCount }}</strong>
            </article>
            <article>
              <span>检测中</span
              ><strong>{{
                loading && !readAt ? "—" : rows.filter(isTesting).length
              }}</strong>
            </article>
          </section>
          <p class="recent">
            最近检测：{{ recent ? date(recent) : "尚未检测" }}
            <span>· 北京时间</span>
          </p>
          <section class="proxy-panel">
            <div class="proxy-toolbar">
              <label class="proxy-search"
                ><span aria-hidden="true">⌕</span
                ><input
                  v-model="search"
                  aria-label="搜索名称、地址或标签"
                  placeholder="搜索名称、地址或标签" /></label
              ><select v-model="protocol" aria-label="协议筛选">
                <option value="">协议：全部</option>
                <option
                  v-for="p in ['http', 'https', 'socks5', 'socks5h']"
                  :key="p"
                  :value="p"
                >
                  {{ p.toUpperCase() }}
                </option></select
              ><select v-model="status" aria-label="状态筛选">
                <option value="">状态：全部</option>
                <option
                  v-for="(label, key) in stateNames"
                  :key="key"
                  :value="key"
                >
                  {{ label }}
                </option></select
              ><button class="btn" @click="openImport">导入</button
              ><button
                class="btn"
                :disabled="!filtered.length"
                @click="modal = 'export'"
              >
                导出
              </button>
            </div>
            <div v-if="selected.length" class="selection">
              <strong>已选择 {{ selected.length }} 个代理</strong
              ><span class="toolbar-grow"></span
              ><button class="btn" :disabled="batchBusy" @click="batch">
                {{ batchBusy ? "检测中…" : "批量检测" }}</button
              ><button class="btn" @click="modal = 'export'">导出所选</button
              ><button class="back-link" @click="selected = []">
                清除选择
              </button>
            </div>
            <div v-if="loading && !readAt" class="empty" role="status">
              <div class="skeleton"></div>
              <div class="skeleton"></div>
              <p>正在读取代理…</p>
            </div>
            <div v-else-if="loadError && !readAt" class="empty" role="alert">
              <h2>无法读取代理列表</h2>
              <p>{{ loadError }}</p>
              <button class="btn" @click="refresh">重试</button>
            </div>
            <div v-else-if="!filtered.length" class="empty">
              <h2>{{ rows.length ? "没有匹配结果" : "暂无代理" }}</h2>
              <p>
                {{
                  rows.length
                    ? "调整搜索或筛选条件。"
                    : "添加代理后即可检测真实出口。"
                }}
              </p>
              <button v-if="rows.length" class="btn" @click="clearFilters">
                清除筛选</button
              ><template v-else
                ><button class="btn primary" @click="edit()">＋ 添加代理</button
                ><button class="btn" @click="openImport">
                  导入代理
                </button></template
              >
            </div>
            <div v-else class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th class="check-cell">
                      <input
                        type="checkbox"
                        aria-label="选择当前页代理"
                        :checked="allSelected"
                        @change="selectAll"
                      />
                    </th>
                    <th>代理</th>
                    <th>地址</th>
                    <th>出口 IP</th>
                    <th>连接质量</th>
                    <th>状态 / 检测时间</th>
                    <th class="actions-cell">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="row in visibleRows"
                    :key="row.proxy_id"
                    :class="{ chosen: selected.includes(row.proxy_id) }"
                  >
                    <td class="check-cell">
                      <input
                        v-model="selected"
                        type="checkbox"
                        :value="row.proxy_id"
                        :aria-label="`选择 ${row.name}`"
                      />
                    </td>
                    <td data-label="代理">
                      <button
                        class="proxy-name"
                        @click="openDetail(row.proxy_id)"
                      >
                        {{ row.name }}
                      </button>
                    </td>
                    <td data-label="地址" class="address-cell">
                      <code>{{ endpoint(row) }}</code
                      ><small>{{
                        row.auth_configured ? "已配置认证" : "无认证"
                      }}</small>
                    </td>
                    <td data-label="出口 IP" class="exit-profile">
                      <code>{{ row.probe?.exit_ip || "尚未检测" }}</code
                      ><small
                        v-if="row.probe"
                        class="exit-location"
                        :title="geoTitle(row)"
                        ><img
                          v-if="flagURL(profiles[row.proxy_id].countryCode)"
                          class="country-flag"
                          :src="flagURL(profiles[row.proxy_id].countryCode)"
                          alt=""
                        />{{ profiles[row.proxy_id].location
                        }}<button
                          v-if="row.probe.location_conflict"
                          class="type-help warn"
                          aria-label="查看地理来源差异"
                          @click="openDetail(row.proxy_id)"
                        >
                          i
                        </button></small
                      ><small
                        v-if="row.probe"
                        class="exit-type"
                        :title="profiles[row.proxy_id].typeEvidence"
                        >{{ profiles[row.proxy_id].type
                        }}<button
                          v-if="profiles[row.proxy_id].type === '单ISP'"
                          class="type-help"
                          aria-label="了解单ISP"
                          title="ASN 与 Company 类型中只有一项为 ISP；部分服务要求两项均为 ISP。"
                        >
                          ?
                        </button></small
                      >
                    </td>
                    <td data-label="连接质量">
                      <span>{{
                        row.probe?.successes
                          ? `${row.probe.mean_latency_ms} ms`
                          : "—"
                      }}</span
                      ><small v-if="row.probe"
                        >{{ row.probe.successes }}/{{
                          row.probe.attempts
                        }}
                        次成功</small
                      >
                    </td>
                    <td data-label="状态 / 检测时间">
                      <span class="status" :class="state(row)"
                        ><span class="dot"></span
                        >{{ stateNames[state(row)] }}</span
                      ><small>{{
                        row.probe ? date(row.probe.finished_at) : "尚未检测"
                      }}</small
                      ><small v-if="isTesting(row) && row.probe"
                        >上次结果，仅供对照</small
                      >
                    </td>
                    <td class="row-actions" data-label="操作">
                      <button
                        class="btn small"
                        :aria-label="`检测 ${row.name}`"
                        :disabled="
                          isTesting(row) ||
                          row.status === 'off' ||
                          expired(row) ||
                          batchBusy
                        "
                        @click="test(row)"
                      >
                        {{ isTesting(row) ? "检测中…" : "检测" }}
                      </button>
                      <div class="more-wrap">
                        <button
                          class="btn small"
                          :aria-label="`更多 ${row.name}`"
                          :aria-expanded="menuID === row.proxy_id"
                          @click="
                            menuID = menuID === row.proxy_id ? '' : row.proxy_id
                          "
                        >
                          更多 ⋯
                        </button>
                        <div v-if="menuID === row.proxy_id" class="more-menu">
                          <button @click="openDetail(row.proxy_id)">
                            查看详情</button
                          ><button @click="edit(row)">编辑代理</button
                          ><button @click="askToggle(row)">
                            {{
                              row.status === "off" ? "启用代理" : "停用代理"
                            }}</button
                          ><button
                            class="danger"
                            :disabled="
                              !!row.assigned_apps.length || isTesting(row)
                            "
                            :title="
                              row.assigned_apps.length ? '被引用，无法删除' : ''
                            "
                            @click="askDelete(row)"
                          >
                            删除代理</button
                          ><small v-if="row.assigned_apps.length"
                            >被引用，无法删除</small
                          >
                        </div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <footer class="table-footer">
              <span
                >共 {{ filtered.length }} 个代理<span v-if="filtered.length">
                  · 当前显示 {{ (page - 1) * pageSize + 1 }}–{{
                    Math.min(page * pageSize, filtered.length)
                  }}</span
                ></span
              >
              <div class="pagination">
                <label
                  >每页
                  <select v-model.number="pageSize" aria-label="每页条数">
                    <option :value="10">10</option>
                    <option :value="20">20</option>
                    <option :value="50">50</option>
                  </select></label
                ><button
                  class="btn small"
                  :disabled="page <= 1"
                  aria-label="上一页"
                  @click="page--"
                >
                  ‹</button
                ><span>{{ page }} / {{ pages }}</span
                ><button
                  class="btn small"
                  :disabled="page >= pages"
                  aria-label="下一页"
                  @click="page++"
                >
                  ›
                </button>
              </div>
            </footer>
          </section>
          <p class="proxy-footnote">
            连通结果来自最近一次检测；IP 分类与来源可在详情查看。
          </p>
        </template>
        <section v-if="drawerID && detail" class="proxy-detail">
          <div class="drawer-body">
            <section>
              <h3>代理配置</h3>
              <dl>
                <div>
                  <dt>端点</dt>
                  <dd>
                    {{ detail.protocol }}://{{ detail.host }}:{{ detail.port }}
                  </dd>
                </div>
                <div>
                  <dt>认证</dt>
                  <dd>
                    {{
                      detail.auth_configured ? "已配置，凭据不回显" : "未配置"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>有效期</dt>
                  <dd>
                    {{
                      detail.expires_at ? date(detail.expires_at) : "长期有效"
                    }}
                  </dd>
                </div>
                <div>
                  <dt>管理员备注</dt>
                  <dd>{{ detail.note || "无" }}</dd>
                </div>
              </dl>
              <button
                class="btn primary detail-retest"
                :disabled="
                  isTesting(detail) ||
                  detail.status === 'off' ||
                  expired(detail)
                "
                @click="test(detail)"
              >
                {{ isTesting(detail) ? "检测中…" : "检测出口与 IP 质量" }}
              </button>
            </section>
            <template v-if="detail.probe"
              ><section>
                <h3>连通与稳定性</h3>
                <dl>
                  <div>
                    <dt>出口 IP</dt>
                    <dd>{{ detail.probe.exit_ip || "未获取" }}</dd>
                  </div>
                  <div>
                    <dt>结果</dt>
                    <dd>
                      {{
                        detail.probe.status === "passed"
                          ? "连通通过"
                          : "检测失败"
                      }}
                    </dd>
                  </div>
                  <div>
                    <dt>采样成功率</dt>
                    <dd>
                      {{ detail.probe.successes }}/{{
                        detail.probe.attempts
                      }}（{{ detail.probe.success_rate.toFixed(0) }}%）
                    </dd>
                  </div>
                  <div>
                    <dt>平均耗时 / 极差</dt>
                    <dd>
                      {{ detail.probe.mean_latency_ms }} /
                      {{ detail.probe.jitter_ms }} ms
                    </dd>
                  </div>
                  <div>
                    <dt>采样窗口</dt>
                    <dd>
                      {{ date(detail.probe.started_at) }} 至
                      {{ date(detail.probe.finished_at) }}
                    </dd>
                  </div>
                  <div>
                    <dt>固定目标</dt>
                    <dd>{{ detail.probe.target }}</dd>
                  </div>
                </dl>
                <p class="probe-explain">
                  三次独立连接的短时观测，不代表长期稳定性。
                </p>
                <p v-if="detail.probe.exit_changed" class="warn">
                  本次观察到多个出口 IP；信息查询对应首次成功的 IP。
                </p>
                <ul>
                  <li
                    v-for="(sample, index) in detail.probe.samples"
                    :key="index"
                  >
                    第 {{ index + 1 }} 次 · {{ sample.latency_ms }} ms ·
                    {{ sample.error ? message(sample.error) : sample.ip }}
                  </li>
                </ul>
              </section>
              <section>
                <h3>出口画像</h3>
                <span class="status" :class="state(detail)"
                  ><span class="dot"></span
                  >{{ stateNames[state(detail)] }}</span
                >
                <dl>
                  <div>
                    <dt>国家／州／城市</dt>
                    <dd>{{ profiles[detail.proxy_id].location }}</dd>
                  </div>
                  <div>
                    <dt>地理来源</dt>
                    <dd>
                      {{ profiles[detail.proxy_id].geo?.source || "未获取"
                      }}{{
                        profiles[detail.proxy_id].fallback ? "（备用来源）" : ""
                      }}
                    </dd>
                  </div>
                  <div>
                    <dt>IP 类型</dt>
                    <dd>{{ profiles[detail.proxy_id].type }}</dd>
                  </div>
                  <div>
                    <dt>类型依据</dt>
                    <dd>{{ profiles[detail.proxy_id].typeEvidence }}</dd>
                  </div>
                </dl>
                <p class="probe-explain">
                  地理位置来自出口 IP 数据库。按 IPinfo、ipapi.is、IPQuery
                  的顺序选取可用来源。
                </p>
                <p v-if="detail.probe.location_conflict" class="warn">
                  来源的定位或 ASN 存在差异，原始观测如下。
                </p>
              </section>
              <details
                class="source-record"
                v-for="source in detail.probe.observations"
                :key="source.source"
              >
                <summary>
                  {{ source.source }} ·
                  {{
                    source.status === "available" ? "查看来源记录" : "查询失败"
                  }}
                </summary>
                <small>{{ date(source.at) }} · {{ source.ip }}</small>
                <p v-if="source.status !== 'available'" class="error">
                  信息未获取：{{ message(source.error || "") }}
                </p>
                <template v-else
                  ><dl>
                    <div>
                      <dt>IP 库推测位置</dt>
                      <dd>{{ location(source) }}</dd>
                    </div>
                    <div>
                      <dt>ASN</dt>
                      <dd>{{ source.asn || "未知" }}</dd>
                    </div>
                    <div>
                      <dt>运营商 / 组织</dt>
                      <dd>{{ source.isp || source.organization || "未知" }}</dd>
                    </div>
                  </dl>
                  <template v-if="source.source === 'IPinfo (type)'"
                    ><dl>
                      <div>
                        <dt>ASN 类型</dt>
                        <dd>{{ source.asn_type || "未知" }}</dd>
                      </div>
                      <div>
                        <dt>Company</dt>
                        <dd>{{ source.company || "未知" }}</dd>
                      </div>
                      <div>
                        <dt>Company 类型</dt>
                        <dd>{{ source.company_type || "未知" }}</dd>
                      </div>
                      <div>
                        <dt>机房标记</dt>
                        <dd>{{ flag(source.datacenter) }}</dd>
                      </div>
                    </dl>
                    <p class="probe-explain">
                      ASN 与 Company 类型中只有一项为 isp 时归为单ISP，两项均为
                      isp 时归为住宅IP；明确 hosting
                      时归为机房IP。字段不足或冲突时未判定。此数据库分类不保证第三方服务接受。
                    </p></template
                  ><template v-if="source.source === 'IPQuery'"
                    ><dl>
                      <div>
                        <dt>数据中心</dt>
                        <dd>{{ flag(source.datacenter) }}</dd>
                      </div>
                      <div>
                        <dt>代理 / VPN</dt>
                        <dd>
                          {{ flag(source.proxy) }} / {{ flag(source.vpn) }}
                        </dd>
                      </div>
                      <div>
                        <dt>Tor / 移动网络</dt>
                        <dd>
                          {{ flag(source.tor) }} / {{ flag(source.mobile) }}
                        </dd>
                      </div>
                      <div>
                        <dt>来源风险分值</dt>
                        <dd>
                          {{
                            source.risk_score === null
                              ? "未知"
                              : `${source.risk_score} / 100`
                          }}
                        </dd>
                      </div>
                    </dl>
                    <p class="probe-explain">
                      标签与分值来自
                      IPQuery；未标记不保证无风险，非数据中心也不能据此确认住宅
                      IP。
                    </p></template
                  ></template
                ><a :href="source.url" target="_blank" rel="noopener noreferrer"
                  >查看该信息源</a
                >
              </details>
              <section>
                <h3>已有引用</h3>
                <p>
                  {{
                    detail.assigned_apps.length
                      ? detail.assigned_apps.join("、")
                      : "当前没有引用"
                  }}
                </p>
              </section>
              <section>
                <h3>名单级信誉</h3>
                <p class="probe-explain">
                  未检测具体黑名单；不把来源风险分值解释为黑名单全通过。
                </p>
              </section></template
            >
            <p v-else class="empty">
              尚无检测结果。点击检测后查看实测出口、连通质量及 IP 库观测。
            </p>
          </div>
        </section>
        <div v-if="drawerID && !detail" class="empty">
          <p>{{ loading ? "正在读取代理详情…" : "代理不存在或无权访问。" }}</p>
          <button class="btn" @click="returnToList">返回列表</button>
        </div>

        <dialog
          v-if="modal"
          class="proxy-modal"
          @cancel.prevent="closeModal"
          @click="
            (event) => {
              if (event.target === event.currentTarget) closeModal();
            }
          "
        >
          <header>
            <h2>
              {{
                modal === "edit"
                  ? editing
                    ? "编辑代理"
                    : "添加代理"
                  : modal === "import"
                    ? "导入代理"
                    : modal === "toggle"
                      ? deleting?.status === "off"
                        ? "启用代理"
                        : "停用代理"
                      : modal === "export"
                        ? "导出代理"
                        : "删除代理"
              }}
            </h2>
            <button
              type="button"
              class="drawer-close"
              :disabled="saving"
              aria-label="关闭弹窗"
              @click="closeModal"
            >
              ×
            </button>
          </header>
          <p v-if="actionError" class="feedback error" role="alert">
            {{ actionError }}
          </p>
          <form
            v-if="modal === 'edit'"
            @submit.prevent="
              save(
                ($event as SubmitEvent).submitter?.getAttribute('value') ===
                  'test',
              )
            "
          >
            <div class="form-grid">
              <label class="full"
                >名称 *<input
                  v-model="form.name"
                  required
                  maxlength="120"
                  placeholder="例如：美国通用出口" /></label
              ><label
                >协议 *<select v-model="form.protocol">
                  <option
                    v-for="p in ['socks5h', 'socks5', 'http', 'https']"
                    :key="p"
                    :value="p"
                  >
                    {{ p.toUpperCase() }}
                  </option>
                </select></label
              ><label
                >端口 *<input
                  v-model.number="form.port"
                  type="number"
                  required
                  min="1"
                  max="65535" /></label
              ><label class="full"
                >主机 *<input
                  v-model="form.host"
                  required
                  placeholder="proxy.example.com"
              /></label>
              <fieldset class="full auth-options">
                <legend>认证</legend>
                <label v-if="editing?.auth_configured"
                  ><input
                    v-model="authMode"
                    type="radio"
                    value="keep"
                  />保留已有认证</label
                ><label v-else
                  ><input
                    v-model="authMode"
                    type="radio"
                    value="none"
                  />无认证</label
                ><label
                  ><input v-model="authMode" type="radio" value="replace" />{{
                    editing?.auth_configured ? "替换认证" : "用户名与密码"
                  }}</label
                ><label v-if="editing?.auth_configured"
                  ><input
                    v-model="authMode"
                    type="radio"
                    value="remove"
                  />移除认证</label
                >
              </fieldset>
              <template v-if="authMode === 'replace'"
                ><label
                  >用户名 *<input
                    v-model="form.username"
                    required
                    autocomplete="off"
                    maxlength="255" /></label
                ><label
                  >密码 *<input
                    v-model="form.password"
                    required
                    type="password"
                    autocomplete="new-password"
                    maxlength="255" /></label
              ></template>
              <p v-if="authMode === 'remove'" class="full warn">
                保存将移除已有认证。
              </p>
              <label
                >有效期<input
                  v-model="form.expires_at"
                  type="datetime-local" /></label
              ><label
                >标签<input
                  v-model="form.tag"
                  maxlength="256"
                  placeholder="备用、视频" /></label
              ><label class="full"
                >备注<textarea v-model="form.note" maxlength="4000"></textarea>
              </label>
            </div>
            <p class="probe-explain">
              凭据加密保存，不回显。保存后进入待检测状态。
            </p>
            <footer>
              <button
                type="button"
                class="btn"
                :disabled="saving"
                @click="closeModal"
              >
                取消</button
              ><button class="btn" value="save" :disabled="saving">
                {{ saving ? "保存中…" : "保存" }}</button
              ><button
                v-if="!editing"
                class="btn primary"
                value="test"
                :disabled="saving"
              >
                保存并检测
              </button>
            </footer>
          </form>
          <div v-else-if="modal === 'import'" class="import-body">
            <label
              >代理 URL（每行一条）或脱敏 JSON<textarea
                v-model="importText"
                :disabled="saving"
                @input="imported = []"
              ></textarea></label
            ><label
              >选择脱敏 JSON / TXT 文件<input
                type="file"
                accept=".json,.txt"
                :disabled="saving"
                @change="importFile"
            /></label>
            <p class="probe-explain">
              最多 50 条。预览不会写入；脱敏 JSON 中的认证代理需重新填写凭据。
            </p>
            <ol class="import-results">
              <li v-for="item in imported" :key="item.line">
                第 {{ item.line }} 条：{{ item.input?.name || "无效记录" }} —
                {{ item.detail }}
              </li>
            </ol>
            <footer>
              <button class="btn" :disabled="saving" @click="preview">
                解析预览</button
              ><button
                class="btn primary"
                :disabled="saving || !imported.some((r) => r.state === 'valid')"
                @click="commitImport"
              >
                {{
                  saving
                    ? "导入中…"
                    : `导入 ${imported.filter((r) => r.state === "valid").length} 条有效代理`
                }}</button
              ><button class="btn" :disabled="saving" @click="closeModal">
                完成
              </button>
            </footer>
          </div>
          <div v-else-if="modal === 'export'" class="delete-body">
            <p>
              导出{{ selected.length ? "所选" : "当前筛选匹配的全部" }}
              {{ exportRows.length }} 个代理。
            </p>
            <p class="probe-explain">
              文件不包含认证凭据。认证代理重新导入时需补填，此文件不是完整凭据备份。
            </p>
            <footer>
              <button class="btn" @click="closeModal">取消</button
              ><button
                class="btn primary"
                :disabled="!exportRows.length"
                @click="exportFile"
              >
                下载脱敏 JSON
              </button>
            </footer>
          </div>
          <div v-else-if="modal === 'toggle'" class="delete-body">
            <p>
              {{ deleting?.status === "off" ? "启用" : "停用" }}“{{
                deleting?.name
              }}”？{{
                deleting?.status === "off"
                  ? "启用后需重新检测。"
                  : "停用会保留配置与已有引用。"
              }}
            </p>
            <p class="probe-explain">
              已有引用：{{
                deleting?.assigned_apps.join("、") || "无"
              }}。此操作不会停止应用。
            </p>
            <footer>
              <button class="btn" @click="closeModal">取消</button
              ><button
                class="btn primary"
                :disabled="saving"
                @click="deleting && toggle(deleting)"
              >
                确认{{ deleting?.status === "off" ? "启用" : "停用" }}
              </button>
            </footer>
          </div>
          <div v-else class="delete-body">
            <p>
              删除“{{ deleting?.name }}”后不能恢复。仍被引用的代理不能删除。
            </p>
            <footer>
              <button class="btn" :disabled="saving" @click="closeModal">
                取消</button
              ><button
                class="btn danger"
                :disabled="saving || !!deleting?.assigned_apps.length"
                @click="remove"
              >
                确认删除
              </button>
            </footer>
          </div>
        </dialog>
      </div>
    </main>
  </div>
</template>
<style scoped src="./station-proxy.css"></style>
