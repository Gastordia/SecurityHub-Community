import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowPathIcon,
  TrashIcon,
  PlusIcon,
  CheckCircleIcon,
  XCircleIcon,
  BoltIcon,
} from '@heroicons/react/24/outline'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { useAuthStore } from '@/stores/auth-store'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Modal, ConfirmModal } from '@/components/ui/Modal'
import { PageSpinner, EmptyState } from '@/components/ui/Spinner'
import toast from 'react-hot-toast'

type SettingsTab = 'webhooks' | 'sla' | 'project-types' | 'report-standards'

const WEBHOOK_EVENTS = [
  { value: 'vulnerability.created', label: 'Vulnerability Created' },
  { value: 'vulnerability.status_changed', label: 'Vulnerability Status Changed' },
  { value: 'project.completed', label: 'Project Completed' },
  { value: 'retest.created', label: 'Retest Created' },
]

function WebhookForm({
  onSave,
  onCancel,
  loading,
}: {
  onSave: (d: any) => void
  onCancel: () => void
  loading: boolean
}) {
  const [form, setForm] = useState({
    name: '',
    url: '',
    secret: '',
    events: [] as string[],
    is_active: true,
  })

  const toggleEvent = (ev: string) =>
    setForm(f => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter(e => e !== ev) : [...f.events, ev],
    }))

  return (
    <form
      onSubmit={e => {
        e.preventDefault()
        onSave(form)
      }}
      className="space-y-4"
    >
      <Input
        label="Name *"
        value={form.name}
        onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
        required
        placeholder="My Webhook"
      />
      <Input
        label="URL *"
        value={form.url}
        onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
        required
        placeholder="https://example.com/webhook"
        type="url"
      />
      <Input
        label="Secret (optional)"
        value={form.secret}
        onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
        placeholder="HMAC signing secret"
      />
      <div>
        <p className="text-xs font-medium text-text-secondary mb-2">Events</p>
        <div className="space-y-2">
          {WEBHOOK_EVENTS.map(ev => (
            <label key={ev.value} className="flex items-center gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={form.events.includes(ev.value)}
                onChange={() => toggleEvent(ev.value)}
                className="w-3.5 h-3.5 rounded accent-accent-500"
              />
              <span className="text-sm text-text-secondary">{ev.label}</span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <Button variant="ghost" size="sm" type="button" onClick={onCancel} disabled={loading}>
          Cancel
        </Button>
        <Button
          size="sm"
          type="submit"
          loading={loading}
          disabled={!form.name.trim() || !form.url.trim()}
        >
          Create Webhook
        </Button>
      </div>
    </form>
  )
}

function DeliveryRow({ delivery }: { delivery: any }) {
  const ok = delivery.status_code >= 200 && delivery.status_code < 300
  return (
    <div className="flex items-center gap-3 px-4 py-2 text-xs">
      {ok ? (
        <CheckCircleIcon className="w-3.5 h-3.5 text-low shrink-0" />
      ) : (
        <XCircleIcon className="w-3.5 h-3.5 text-critical shrink-0" />
      )}
      <span className={ok ? 'text-low' : 'text-critical'}>{delivery.status_code ?? '—'}</span>
      <span className="text-text-muted font-mono flex-1 truncate">{delivery.event ?? '—'}</span>
      <span className="text-text-muted shrink-0">
        {delivery.created_at ? new Date(delivery.created_at).toLocaleString() : '—'}
      </span>
    </div>
  )
}

function WebhookCard({ wh, onDelete }: { wh: any; onDelete: () => void }) {
  const qc = useQueryClient()
  const [showDeliveries, setShowDeliveries] = useState(false)

  const { data: deliveries } = useQuery({
    queryKey: ['webhook-deliveries', wh.id],
    queryFn: () => standardizedApiClient.getWebhookDeliveries(wh.id),
    enabled: showDeliveries,
  })

  const testWebhook = useMutation({
    mutationFn: () => standardizedApiClient.testWebhook(wh.id),
    onSuccess: () => toast.success('Test delivery sent'),
    onError: (e: any) => toast.error(e?.message || 'Test failed'),
  })

  const toggleActive = useMutation({
    mutationFn: () =>
      standardizedApiClient.updateWebhookConfig(wh.id, { is_active: !wh.is_active }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['webhooks'] })
      toast.success(wh.is_active ? 'Webhook disabled' : 'Webhook enabled')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed'),
  })

  const deliveryList = Array.isArray(deliveries) ? deliveries : []

  return (
    <div className="bg-app-surface border border-border-subtle rounded-xl overflow-hidden">
      <div className="px-5 py-4 flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <p className="text-sm font-semibold text-text-primary">{wh.name}</p>
            <span
              className={`text-[10px] font-medium px-1.5 py-0.5 rounded-full ${
                wh.is_active
                  ? 'bg-low/15 text-low border border-low/30'
                  : 'bg-border-default/50 text-text-muted border border-border-default'
              }`}
            >
              {wh.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
          <p className="text-xs text-text-muted font-mono truncate max-w-xs">{wh.url}</p>
          {wh.events?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {wh.events.map((ev: string) => (
                <span
                  key={ev}
                  className="text-[10px] px-1.5 py-0.5 bg-app-overlay border border-border-subtle rounded text-text-muted font-mono"
                >
                  {ev}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="ghost"
            size="sm"
            icon={<BoltIcon className="w-3.5 h-3.5" />}
            onClick={() => testWebhook.mutate()}
            loading={testWebhook.isPending}
          >
            Test
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => toggleActive.mutate()}
            loading={toggleActive.isPending}
          >
            {wh.is_active ? 'Disable' : 'Enable'}
          </Button>
          <button
            onClick={onDelete}
            className="p-1.5 text-text-muted hover:text-critical rounded transition-colors"
          >
            <TrashIcon className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="border-t border-border-subtle">
        <button
          onClick={() => setShowDeliveries(s => !s)}
          className="w-full text-left px-5 py-2.5 text-xs text-text-muted hover:text-text-secondary transition-colors flex items-center justify-between"
        >
          <span>Recent deliveries</span>
          <span>{showDeliveries ? '▲' : '▼'}</span>
        </button>
        {showDeliveries && (
          <div className="divide-y divide-border-subtle">
            {deliveryList.length === 0 ? (
              <p className="px-5 py-3 text-xs text-text-muted">No deliveries yet.</p>
            ) : (
              deliveryList.slice(0, 10).map((d: any) => (
                <DeliveryRow key={d.id} delivery={d} />
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function WebhooksTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<any>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => standardizedApiClient.getWebhookConfigs(),
  })
  const webhooks = Array.isArray(data?.results) ? data.results : Array.isArray(data) ? data : []

  const create = useMutation({
    mutationFn: (d: any) => standardizedApiClient.createWebhookConfig(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['webhooks'] })
      setShowCreate(false)
      toast.success('Webhook created')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to create webhook'),
  })

  const del = useMutation({
    mutationFn: () => standardizedApiClient.deleteWebhookConfig(deleteTarget.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['webhooks'] })
      setDeleteTarget(null)
      toast.success('Webhook deleted')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to delete webhook'),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-text-muted">{webhooks.length} configured</p>
        {isAdmin && (
          <Button
            size="sm"
            icon={<PlusIcon className="w-4 h-4" />}
            onClick={() => setShowCreate(true)}
          >
            Add Webhook
          </Button>
        )}
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : webhooks.length === 0 ? (
        <EmptyState
          title="No webhooks configured"
          description="Add a webhook to receive real-time events from SecurityHub."
          action={
            isAdmin ? (
              <Button
                size="sm"
                icon={<PlusIcon className="w-4 h-4" />}
                onClick={() => setShowCreate(true)}
              >
                Add Webhook
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          {webhooks.map((wh: any) => (
            <WebhookCard key={wh.id} wh={wh} onDelete={() => setDeleteTarget(wh)} />
          ))}
        </div>
      )}

      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="Add Webhook" size="lg">
        <WebhookForm
          onSave={d => create.mutate(d)}
          onCancel={() => setShowCreate(false)}
          loading={create.isPending}
        />
      </Modal>

      <ConfirmModal
        isOpen={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => del.mutate()}
        title="Delete Webhook"
        message={`Delete webhook "${deleteTarget?.name}"? This cannot be undone.`}
        loading={del.isPending}
      />
    </div>
  )
}

function SLAPolicyTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['sla-policy'],
    queryFn: () => standardizedApiClient.getSLAPolicy(),
  })

  const [form, setForm] = useState<{
    critical_days: number
    high_days: number
    medium_days: number
    low_days: number
    informational_days: number
  } | null>(null)

  const save = useMutation({
    mutationFn: (d: any) => standardizedApiClient.updateSLAPolicy(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sla-policy'] })
      toast.success('SLA policy updated')
    },
    onError: (e: any) => toast.error(e?.message || 'Failed to save'),
  })

  const policy = form ?? data
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...(f ?? data ?? {}), [k]: Number(e.target.value) }))

  if (isLoading) return <PageSpinner />

  return (
    <div className="space-y-4 max-w-sm">
      <p className="text-xs text-text-muted">
        Define how many days each severity level has before a finding is considered overdue.
      </p>
      <div className="space-y-3">
        {[
          { key: 'critical_days', label: 'Critical' },
          { key: 'high_days', label: 'High' },
          { key: 'medium_days', label: 'Medium' },
          { key: 'low_days', label: 'Low' },
          { key: 'informational_days', label: 'Informational' },
        ].map(({ key, label }) => (
          <div key={key} className="flex items-center gap-4">
            <label className="text-sm text-text-secondary w-28 shrink-0">{label}</label>
            <Input
              type="number"
              min={1}
              max={3650}
              value={policy?.[key as keyof typeof policy] ?? ''}
              onChange={set(key)}
              disabled={!isAdmin}
              className="w-24"
            />
            <span className="text-xs text-text-muted">days</span>
          </div>
        ))}
      </div>
      {isAdmin && (
        <Button
          size="sm"
          onClick={() => save.mutate(form ?? data)}
          loading={save.isPending}
          disabled={!form}
        >
          Save Policy
        </Button>
      )}
    </div>
  )
}

function ListViewer<T extends { id: number; name?: string }>({
  items,
  loading,
  nameKey,
  isAdmin,
  onSync,
  syncing,
}: {
  items: T[]
  loading: boolean
  nameKey: keyof T
  isAdmin: boolean
  onSync: () => void
  syncing: boolean
}) {
  return (
    <>
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-text-muted">{items.length} entries — sourced from GitHub</p>
        {isAdmin && (
          <Button
            size="sm"
            variant="outline"
            icon={<ArrowPathIcon className="w-4 h-4" />}
            onClick={onSync}
            loading={syncing}
          >
            Sync from GitHub
          </Button>
        )}
      </div>
      {loading ? (
        <PageSpinner />
      ) : items.length === 0 ? (
        <div className="py-8 text-center">
          <p className="text-sm text-text-muted mb-3">None defined yet.</p>
          {isAdmin && (
            <Button
              size="sm"
              variant="outline"
              icon={<ArrowPathIcon className="w-4 h-4" />}
              onClick={onSync}
              loading={syncing}
            >
              Sync from GitHub
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-1">
          {items.map(item => (
            <div
              key={item.id}
              className="flex items-center bg-app-overlay border border-border-subtle rounded-lg px-4 py-2.5"
            >
              <span className="text-sm text-text-primary">{item[nameKey] as string}</span>
            </div>
          ))}
        </div>
      )}
    </>
  )
}

export default function SettingsPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = !!(user?.is_superuser || user?.is_staff)
  const [tab, setTab] = useState<SettingsTab>('webhooks')

  const { data: ptData, isLoading: ptLoading } = useQuery({
    queryKey: ['project-types'],
    queryFn: () => standardizedApiClient.getProjectTypes(),
  })
  const { data: rsData, isLoading: rsLoading } = useQuery({
    queryKey: ['report-standards'],
    queryFn: () => standardizedApiClient.getReportStandards(),
  })

  const pts = Array.isArray(ptData?.results) ? ptData.results : Array.isArray(ptData) ? ptData : []
  const rss = Array.isArray(rsData?.results) ? rsData.results : Array.isArray(rsData) ? rsData : []

  const syncPT = useMutation({
    mutationFn: () => standardizedApiClient.syncProjectTypes(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['project-types'] })
      toast.success(`Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`)
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })
  const syncRS = useMutation({
    mutationFn: () => standardizedApiClient.syncReportStandards(),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ['report-standards'] })
      toast.success(`Sync complete — ${result?.created ?? 0} added, ${result?.updated ?? 0} updated`)
    },
    onError: (e: any) => toast.error(e?.message || 'Sync failed'),
  })

  const TABS: { id: SettingsTab; label: string }[] = [
    { id: 'webhooks', label: 'Webhooks' },
    { id: 'sla', label: 'SLA Policy' },
    { id: 'project-types', label: 'Project Types' },
    { id: 'report-standards', label: 'Report Standards' },
  ]

  return (
    <div className="p-6 space-y-5 max-w-3xl">
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Settings</h1>
        <p className="text-xs text-text-muted mt-0.5">Configure your SecurityHub workspace</p>
      </div>

      <div className="border-b border-border-subtle">
        <nav className="-mb-px flex gap-1">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 pb-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t.id
                  ? 'border-accent-500 text-accent-400'
                  : 'border-transparent text-text-muted hover:text-text-secondary hover:border-border-default'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="bg-app-surface border border-border-subtle rounded-xl p-5">
        {tab === 'webhooks' && <WebhooksTab isAdmin={isAdmin} />}
        {tab === 'sla' && <SLAPolicyTab isAdmin={isAdmin} />}
        {tab === 'project-types' && (
          <ListViewer
            items={pts}
            loading={ptLoading}
            nameKey="name"
            isAdmin={isAdmin}
            onSync={() => syncPT.mutate()}
            syncing={syncPT.isPending}
          />
        )}
        {tab === 'report-standards' && (
          <ListViewer
            items={rss}
            loading={rsLoading}
            nameKey="name"
            isAdmin={isAdmin}
            onSync={() => syncRS.mutate()}
            syncing={syncRS.isPending}
          />
        )}
      </div>
    </div>
  )
}
