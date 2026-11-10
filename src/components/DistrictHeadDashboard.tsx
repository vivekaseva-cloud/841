import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Eye,
  FileText,
  KeyRound,
  MapPin,
  Newspaper,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { DistrictHeadAccount, NewsArticle, ReporterProfile } from '../types';

interface DistrictHeadDashboardProps {
  sessionToken: string;
  onRefreshPublicData: () => void;
}

export const DistrictHeadDashboard: React.FC<DistrictHeadDashboardProps> = ({
  sessionToken,
  onRefreshPublicData,
}) => {
  const [activeTab, setActiveTab] = useState<'REPORTERS' | 'DISTRICT_NEWS' | 'CHANGE_PASSWORD'>('REPORTERS');
  const [profile, setProfile] = useState<DistrictHeadAccount | null>(null);
  const [stats, setStats] = useState<{
    total_district_reporters: number;
    approved_reporters: number;
    pending_reporters: number;
    rejected_reporters: number;
    total_district_news: number;
  }>({
    total_district_reporters: 0,
    approved_reporters: 0,
    pending_reporters: 0,
    rejected_reporters: 0,
    total_district_news: 0,
  });
  const [reporters, setReporters] = useState<ReporterProfile[]>([]);
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [toast, setToast] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [docPreviewModal, setDocPreviewModal] = useState<{
    reporterName: string;
    docType: string;
    maskedRef: string;
    sha256: string;
    decryptedPreview: string | null;
  } | null>(null);

  // Change Own Password State (Section 8)
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const loadDistrictDashboard = async () => {
    const res = await fetch('/api/district-head/dashboard', {
      headers: { 'x-nb-session': sessionToken },
    });
    if (res.ok) {
      const data = await res.json();
      setProfile(data.profile || null);
      if (data.stats) setStats(data.stats);
      setReporters(data.reporters || []);
      setArticles(data.articles || []);
    }
  };

  useEffect(() => {
    loadDistrictDashboard();
  }, [sessionToken]);

  const handleReporterAction = async (reporterId: number, action: 'APPROVE' | 'REJECT') => {
    const res = await fetch(`/api/district-head/reporters/${reporterId}/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-nb-session': sessionToken,
      },
      body: JSON.stringify({
        action,
        rejection_reason:
          action === 'REJECT' ? 'District verification incomplete or unclear document.' : undefined,
      }),
    });
    const data = await res.json();
    if (res.ok) {
      setToast({
        type: 'ok',
        text:
          action === 'APPROVE'
            ? `Reporter #${reporterId} approved in your district! Unique ID: ${data.unique_reporter_id}`
            : `Reporter #${reporterId} application rejected.`,
      });
      loadDistrictDashboard();
      onRefreshPublicData();
    } else {
      setToast({ type: 'err', text: data.error || 'Action failed.' });
    }
  };

  const handleInspectDocument = async (rep: ReporterProfile) => {
    const res = await fetch(`/api/district-head/reporters/${rep.id}/document`, {
      headers: { 'x-nb-session': sessionToken },
    });
    const data = await res.json();
    if (res.ok) {
      setDocPreviewModal({
        reporterName: rep.full_name,
        docType: data.document_type,
        maskedRef: data.masked_document_ref,
        sha256: data.sha256_checksum,
        decryptedPreview: data.decrypted_preview,
      });
    } else {
      setToast({ type: 'err', text: data.error || 'Could not load verification document.' });
    }
  };

  const handleChangeOwnPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setToast(null);
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-nb-session': sessionToken,
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      }),
    });
    const data = await res.json();
    if (res.ok) {
      setToast({
        type: 'ok',
        text: data.message || 'Password updated successfully. Other sessions invalidated.',
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } else {
      setToast({ type: 'err', text: data.error || 'Failed to update password.' });
    }
  };

  if (!profile) {
    return <div className="p-8 text-center text-sm text-stone-600">Loading District Head Workspace...</div>;
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-950 text-white rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-amber-400 uppercase tracking-wider">
            DISTRICT HEAD WORKSPACE • ASSIGNED JURISDICTION ONLY
          </div>
          <h1 className="text-2xl font-bold mt-1">{profile.full_name}</h1>
          <div className="text-xs text-slate-300 mt-1 flex flex-wrap items-center gap-2 tabular-nums">
            <MapPin className="w-3.5 h-3.5 text-amber-400" />
            <span>
              Assigned District: <strong>{profile.district_name_te}</strong> ({profile.district_name_en}) —{' '}
              {profile.state_name_te}
            </span>
            <span>·</span>
            <span>Username: {profile.username}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('REPORTERS')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-lg cursor-pointer ${
              activeTab === 'REPORTERS' ? 'bg-[#991B1B] text-white' : 'bg-slate-800 text-slate-200'
            }`}
          >
            District Reporters ({stats.total_district_reporters})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('DISTRICT_NEWS')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-lg cursor-pointer ${
              activeTab === 'DISTRICT_NEWS' ? 'bg-[#991B1B] text-white' : 'bg-slate-800 text-slate-200'
            }`}
          >
            District News ({stats.total_district_news})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('CHANGE_PASSWORD')}
            className={`px-3.5 py-2 text-xs font-semibold rounded-lg cursor-pointer ${
              activeTab === 'CHANGE_PASSWORD' ? 'bg-[#1E3A8A] text-white' : 'bg-slate-800 text-slate-200'
            }`}
          >
            Change Password
          </button>
        </div>
      </div>

      {Boolean(profile.must_change_password) && (
        <div className="p-4 bg-amber-50 border border-amber-300 text-amber-900 rounded-xl text-xs font-semibold">
          Security Notice: Your password was recently reset with a temporary password. Please update your password in the Change Password tab.
        </div>
      )}

      {toast && (
        <div
          className={`p-4 rounded-xl border text-xs font-semibold flex items-center justify-between ${
            toast.type === 'ok'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
        >
          <span>{toast.text}</span>
          <button type="button" onClick={() => setToast(null)} className="text-stone-500 hover:text-stone-900">
            ✕
          </button>
        </div>
      )}

      {/* District Statistics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 tabular-nums">
        <div className="bg-white border border-stone-200 rounded-xl p-4">
          <div className="text-xs text-stone-500">District Reporters</div>
          <div className="text-2xl font-bold text-stone-900 mt-1">{stats.total_district_reporters}</div>
          <div className="text-[11px] text-stone-500 mt-0.5">{profile.district_name_te}</div>
        </div>
        <div className="bg-white border border-stone-200 rounded-xl p-4">
          <div className="text-xs text-stone-500">Approved Reporters</div>
          <div className="text-2xl font-bold text-emerald-700 mt-1">{stats.approved_reporters}</div>
          <div className="text-[11px] text-stone-500 mt-0.5">Active 6M ID Cards</div>
        </div>
        <div className="bg-white border border-stone-200 rounded-xl p-4">
          <div className="text-xs text-stone-500">Pending Approvals</div>
          <div className="text-2xl font-bold text-amber-700 mt-1">{stats.pending_reporters}</div>
          <div className="text-[11px] text-stone-500 mt-0.5">Awaiting Review</div>
        </div>
        <div className="bg-white border border-stone-200 rounded-xl p-4">
          <div className="text-xs text-stone-500">Rejected</div>
          <div className="text-2xl font-bold text-red-700 mt-1">{stats.rejected_reporters}</div>
          <div className="text-[11px] text-stone-500 mt-0.5">In District</div>
        </div>
        <div className="bg-white border border-stone-200 rounded-xl p-4">
          <div className="text-xs text-stone-500">District News</div>
          <div className="text-2xl font-bold text-[#1E3A8A] mt-1">{stats.total_district_news}</div>
          <div className="text-[11px] text-stone-500 mt-0.5">Published Stories</div>
        </div>
      </div>

      {/* TAB 1: DISTRICT REPORTERS REVIEW & APPROVAL */}
      {activeTab === 'REPORTERS' && (
        <div className="bg-white border border-stone-200 rounded-xl p-6">
          <div className="border-b border-stone-200 pb-3 mb-4">
            <h2 className="text-lg font-bold text-stone-900">
              {profile.district_name_te} ({profile.district_name_en}) — District Reporters &amp; Approvals
            </h2>
            <p className="text-xs text-stone-500 mt-0.5">
              Strict Jurisdiction Enforcement: As District Head, you can review and approve/reject reporters belonging only to {profile.district_name_en} District.
            </p>
          </div>

          {reporters.length === 0 ? (
            <p className="text-xs text-stone-500 py-8 text-center">
              No reporters registered in {profile.district_name_en} district yet.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs tabular-nums">
                <thead>
                  <tr className="border-b border-stone-200 text-stone-500">
                    <th className="py-2.5 px-2">Reporter ID / Reg</th>
                    <th className="py-2.5 px-2">Full Name &amp; Designation</th>
                    <th className="py-2.5 px-2">Mandal &amp; Village</th>
                    <th className="py-2.5 px-2">Status</th>
                    <th className="py-2.5 px-2">Verification Doc</th>
                    <th className="py-2.5 px-2 text-right">District Head Decision</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-stone-200">
                  {reporters.map((r) => (
                    <tr key={r.id} className="hover:bg-stone-50">
                      <td className="py-3 px-2 font-mono font-bold text-stone-900">
                        {r.unique_reporter_id || r.registration_number}
                      </td>
                      <td className="py-3 px-2">
                        <div className="font-bold text-stone-900">{r.full_name}</div>
                        <div className="text-stone-500">
                          {r.designation} · {r.mobile}
                        </div>
                      </td>
                      <td className="py-3 px-2">
                        {r.mandal_name_te || r.village_name}, {r.district_name_te}
                      </td>
                      <td className="py-3 px-2 font-bold">
                        <span
                          className={
                            r.account_status === 'APPROVED'
                              ? 'text-emerald-700'
                              : r.account_status === 'REJECTED'
                              ? 'text-red-700'
                              : 'text-amber-700'
                          }
                        >
                          {r.account_status}
                        </span>
                      </td>
                      <td className="py-3 px-2">
                        <button
                          type="button"
                          onClick={() => handleInspectDocument(r)}
                          className="inline-flex items-center gap-1 px-2 py-1 bg-stone-100 hover:bg-stone-200 rounded text-[11px] font-semibold cursor-pointer"
                        >
                          <Eye className="w-3 h-3" />
                          <span>{r.document_type || 'Inspect Doc'}</span>
                        </button>
                      </td>
                      <td className="py-3 px-2 text-right space-x-1.5 whitespace-nowrap">
                        {r.account_status !== 'APPROVED' && (
                          <button
                            type="button"
                            onClick={() => handleReporterAction(r.id, 'APPROVE')}
                            className="px-2.5 py-1 bg-emerald-700 hover:bg-emerald-800 text-white rounded font-semibold cursor-pointer"
                          >
                            Approve Reporter
                          </button>
                        )}
                        {r.account_status !== 'REJECTED' && (
                          <button
                            type="button"
                            onClick={() => handleReporterAction(r.id, 'REJECT')}
                            className="px-2.5 py-1 bg-red-700 hover:bg-red-800 text-white rounded font-semibold cursor-pointer"
                          >
                            Reject
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: DISTRICT NEWS REVIEW */}
      {activeTab === 'DISTRICT_NEWS' && (
        <div className="bg-white border border-stone-200 rounded-xl p-6">
          <h2 className="text-lg font-bold text-stone-900 border-b border-stone-200 pb-3 mb-4">
            {profile.district_name_te} ({profile.district_name_en}) — District News Feed ({articles.length})
          </h2>
          {articles.length === 0 ? (
            <p className="text-xs text-stone-500 py-8 text-center">
              No news articles filed for {profile.district_name_en} district yet.
            </p>
          ) : (
            <div className="divide-y divide-stone-200">
              {articles.map((art) => (
                <div key={art.id} className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="text-xs text-stone-500 tabular-nums">
                      <span className="font-bold text-[#991B1B]">{art.category_name_te}</span>
                      <span className="mx-1.5">·</span>
                      <span>{art.mandal_name_te || art.village_name}</span>
                      <span className="mx-1.5">·</span>
                      <span>By {art.reporter_name}</span>
                      <span className="mx-1.5">·</span>
                      <span>{new Date(art.news_date).toLocaleDateString('en-IN')}</span>
                    </div>
                    <h3 className="text-sm font-bold text-stone-900 mt-0.5">{art.telugu_title}</h3>
                    <p className="text-xs text-stone-600 mt-0.5 line-clamp-2">{art.short_description}</p>
                  </div>
                  <div className="text-xs font-bold text-emerald-700 shrink-0 tabular-nums">
                    {art.status} · {art.views_count} views
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: CHANGE OWN PASSWORD (SECTION 8) */}
      {activeTab === 'CHANGE_PASSWORD' && (
        <div className="bg-white border border-stone-200 rounded-xl p-6 max-w-lg">
          <div className="border-b border-stone-200 pb-3 mb-4">
            <h2 className="text-base font-bold text-stone-900 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-[#1E3A8A]" />
              <span>Change District Head Password (పాస్‌వర్డ్ మార్పు)</span>
            </h2>
            <p className="text-xs text-stone-500 mt-0.5">
              Changing your password immediately invalidates all other active sessions and records a security audit entry.
            </p>
          </div>
          <form onSubmit={handleChangeOwnPassword} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-stone-700 mb-1">1. Current Password *</label>
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                className="w-full px-3 py-2 text-sm border border-stone-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-stone-700 mb-1">
                2. New Password (Min 8 characters, different from current) *
              </label>
              <input
                type="password"
                required
                minLength={8}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter strong new password"
                className="w-full px-3 py-2 text-sm border border-stone-300 rounded-lg"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-stone-700 mb-1">3. Confirm New Password *</label>
              <input
                type="password"
                required
                minLength={8}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter new password"
                className="w-full px-3 py-2 text-sm border border-stone-300 rounded-lg"
              />
            </div>
            <button
              type="submit"
              className="px-5 py-2.5 bg-[#1E3A8A] hover:bg-blue-950 text-white text-xs font-bold rounded-lg cursor-pointer"
            >
              4. Update Password
            </button>
          </form>
        </div>
      )}

      {/* Private Encrypted Document Modal */}
      {docPreviewModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-stone-200 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#991B1B] font-bold">
                  DISTRICT HEAD VERIFICATION • AES-256 DECRYPTED STREAM
                </span>
                <h3 className="text-base font-bold text-stone-900">{docPreviewModal.reporterName}</h3>
              </div>
              <button type="button" onClick={() => setDocPreviewModal(null)} className="p-1 text-stone-500">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="text-xs space-y-1 text-stone-600 bg-stone-50 p-3 rounded-lg border border-stone-200 tabular-nums">
              <div>
                <strong>Document Type:</strong> {docPreviewModal.docType}
              </div>
              <div>
                <strong>Masked Reference:</strong> {docPreviewModal.maskedRef}
              </div>
              <div className="truncate">
                <strong>SHA-256 Checksum:</strong> {docPreviewModal.sha256}
              </div>
            </div>
            {docPreviewModal.decryptedPreview && docPreviewModal.decryptedPreview.startsWith('data:image/') ? (
              <img
                src={docPreviewModal.decryptedPreview}
                alt="Decrypted Identity Verification"
                className="w-full max-h-64 object-contain rounded border border-stone-200"
              />
            ) : (
              <div className="p-6 text-center bg-stone-100 rounded-lg text-xs text-stone-700 font-mono">
                {docPreviewModal.decryptedPreview || 'Encrypted Binary Stream Verified'}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
