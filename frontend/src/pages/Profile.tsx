import { useState } from 'react'
import { useAuthStore } from '@/stores/auth-store'
import { standardizedApiClient } from '@/lib/standardized-api-client'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import toast from 'react-hot-toast'

export default function ProfilePage() {
  const { user, checkAuthStatus } = useAuthStore()
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

  const setPf = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setProfileForm(f => ({ ...f, [k]: e.target.value }))

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

  return (
    <div className="p-6 space-y-6 max-w-xl">
      <div>
        <h1 className="text-lg font-semibold text-white">Profile</h1>
        <p className="text-xs text-slate-500 mt-0.5">@{user?.username}</p>
      </div>

      {/* Profile info */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Account Details</h2>
        <form onSubmit={saveProfile} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Input label="First Name" value={profileForm.first_name} onChange={setPf('first_name')} />
            <Input label="Last Name" value={profileForm.last_name} onChange={setPf('last_name')} />
          </div>
          <Input label="Email" type="email" value={profileForm.email} onChange={setPf('email')} />
          <Input label="Position / Title" value={profileForm.position} onChange={setPf('position')} />
          <div className="flex justify-end pt-1">
            <Button size="sm" type="submit" loading={profileLoading}>Save Changes</Button>
          </div>
        </form>

        <div className="border-t border-slate-700 mt-6 pt-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">Change Password</h3>
          <form onSubmit={savePassword} className="space-y-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                required
                minLength={8}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="Min 8 characters"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => { setConfirmPassword(e.target.value); setPasswordError('') }}
                required
                minLength={8}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="Repeat new password"
              />
              {passwordError && <p className="text-xs text-red-400 mt-1">{passwordError}</p>}
            </div>
            <div className="flex justify-end pt-1">
              <Button size="sm" type="submit" loading={passwordLoading}>Change Password</Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
