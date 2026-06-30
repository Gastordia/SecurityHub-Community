import { useState } from 'react'
import { useAuthStore } from '@/stores/auth-store'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { Button } from '@/components/ui/Button'
import { Input, FormField } from '@/components/ui/Input'
import toast from 'react-hot-toast'

export default function ProfilePage() {
  const { user, checkAuthStatus } = useAuthStore()
  const isAdmin = user?.is_superuser || user?.is_staff

  const [profileForm, setProfileForm] = useState({
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    email: user?.email || '',
    position: user?.position || '',
  })
  const [profileLoading, setProfileLoading] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState('')
  const [passwordLoading, setPasswordLoading] = useState(false)

  const setPf = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setProfileForm(f => ({ ...f, [k]: e.target.value }))

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    setProfileLoading(true)
    try {
      await standardizedApiClient.updateProfile(profileForm)
      await checkAuthStatus()
      toast.success('Profile updated')
    } catch (err: any) {
      toast.error(err?.message || 'Failed to update profile')
    } finally {
      setProfileLoading(false)
    }
  }

  const savePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match')
      return
    }
    setPasswordError('')
    setPasswordLoading(true)
    try {
      await standardizedApiClient.updateProfile({ password: newPassword })
      toast.success('Password changed')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: any) {
      toast.error(err?.message || 'Failed to change password')
    } finally {
      setPasswordLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-xl">
      <div>
        <h1 className="text-lg font-semibold text-text-primary">Your Profile</h1>
        <p className="text-xs text-text-muted mt-0.5">@{user?.username}</p>
      </div>

      <div className="bg-app-surface border border-border-subtle rounded-xl">
        <div className="px-5 py-4 border-b border-border-subtle">
          <h2 className="text-sm font-semibold text-text-primary">Account Details</h2>
        </div>
        <form onSubmit={saveProfile} className="px-5 py-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="First Name"
              value={profileForm.first_name}
              onChange={setPf('first_name')}
              placeholder="Jane"
            />
            <Input
              label="Last Name"
              value={profileForm.last_name}
              onChange={setPf('last_name')}
              placeholder="Smith"
            />
          </div>
          <Input
            label="Email"
            type="email"
            value={profileForm.email}
            onChange={setPf('email')}
            readOnly={!isAdmin}
            placeholder="jane@example.com"
          />
          <Input
            label="Position / Title"
            value={profileForm.position}
            onChange={setPf('position')}
            placeholder="Security Engineer"
          />
          <div className="flex justify-end pt-1">
            <Button size="sm" type="submit" loading={profileLoading}>
              Save Changes
            </Button>
          </div>
        </form>
      </div>

      <div className="bg-app-surface border border-border-subtle rounded-xl">
        <div className="px-5 py-4 border-b border-border-subtle">
          <h2 className="text-sm font-semibold text-text-primary">Change Password</h2>
          <p className="text-xs text-text-muted mt-0.5">Choose a strong password with at least 8 characters.</p>
        </div>
        <form onSubmit={savePassword} className="px-5 py-5 space-y-4">
          <FormField label="New Password">
            <input
              type="password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              required
              minLength={8}
              placeholder="Min 8 characters"
              className="w-full rounded-lg bg-app-surface border border-border-default text-text-primary placeholder:text-text-muted px-3 py-2 text-sm outline-none transition-all focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30"
            />
          </FormField>
          <FormField
            label="Confirm Password"
            error={passwordError}
          >
            <input
              type="password"
              value={confirmPassword}
              onChange={e => {
                setConfirmPassword(e.target.value)
                setPasswordError('')
              }}
              required
              minLength={8}
              placeholder="Repeat new password"
              className="w-full rounded-lg bg-app-surface border border-border-default text-text-primary placeholder:text-text-muted px-3 py-2 text-sm outline-none transition-all focus:border-accent-500 focus:ring-1 focus:ring-accent-500/30"
            />
          </FormField>
          <div className="flex justify-end pt-1">
            <Button size="sm" type="submit" loading={passwordLoading}>
              Change Password
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
