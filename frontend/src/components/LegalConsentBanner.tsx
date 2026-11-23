/**
 * Legal Consent Banner
 * 
 * Displays on first login or when consent hasn't been given.
 * Required for ethical and legal compliance.
 */

import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, Scale, CheckCircle } from 'lucide-react'

const CONSENT_STORAGE_KEY = 'netmonitor-legal-consent'
const CONSENT_VERSION = '1.0' // Increment when terms change

interface LegalConsentBannerProps {
  onAccept?: () => void
}

export default function LegalConsentBanner({ onAccept }: LegalConsentBannerProps) {
  const [showBanner, setShowBanner] = useState(false)
  const [acknowledged, setAcknowledged] = useState(false)

  useEffect(() => {
    const consent = localStorage.getItem(CONSENT_STORAGE_KEY)
    if (!consent || JSON.parse(consent).version !== CONSENT_VERSION) {
      setShowBanner(true)
    }
  }, [])

  const handleAccept = () => {
    localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify({
      accepted: true,
      version: CONSENT_VERSION,
      timestamp: new Date().toISOString()
    }))
    setShowBanner(false)
    onAccept?.()
  }

  if (!showBanner) return null

  return (
    <div className="fixed inset-0 z-[100] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#141414] border border-[#262626] rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-[#141414] border-b border-[#262626] p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-blue-500/10 rounded-xl">
              <Scale className="w-8 h-8 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">Legal Notice & Terms of Use</h2>
              <p className="text-gray-400 text-sm mt-1">Please read and acknowledge before proceeding</p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Defensive Purpose */}
          <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Shield className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="font-medium text-emerald-400">Defensive Use Only</h3>
                <p className="text-sm text-emerald-200/70 mt-1">
                  NetMonitor is designed exclusively for <strong>defensive network monitoring</strong> on 
                  networks you own or have explicit authorization to monitor. This tool helps identify 
                  security vulnerabilities and potential threats to protect your network infrastructure.
                </p>
              </div>
            </div>
          </div>

          {/* Critical Warning */}
          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="font-medium text-red-400">⚠️ Legal Warning</h3>
                <p className="text-sm text-red-200/70 mt-1">
                  <strong>Unauthorized network monitoring and scanning is illegal.</strong> Scanning or 
                  monitoring networks without explicit permission may violate:
                </p>
                <ul className="text-sm text-red-200/70 mt-2 list-disc list-inside space-y-1">
                  <li>Computer Fraud and Abuse Act (CFAA) in the United States</li>
                  <li>Computer Misuse Act (CMA) in the United Kingdom</li>
                  <li>Similar cybercrime laws in other jurisdictions</li>
                </ul>
                <p className="text-sm text-red-200/70 mt-2">
                  Violations can result in <strong>criminal prosecution, fines, and imprisonment</strong>.
                </p>
              </div>
            </div>
          </div>

          {/* User Responsibilities */}
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-4">
            <h3 className="font-medium text-blue-400 mb-3">Your Responsibilities</h3>
            <ul className="text-sm text-blue-200/70 space-y-2">
              <li className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <span>Only monitor networks you own or have <strong>written authorization</strong> to monitor</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <span>Comply with all applicable local, national, and international laws</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <span>Use scanning features responsibly and only on authorized targets</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <span>Never use this tool for offensive security operations without proper authorization</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <span>Respect privacy laws and data protection regulations (GDPR, CCPA, etc.)</span>
              </li>
            </ul>
          </div>

          {/* Acknowledgment checkbox */}
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-1 w-5 h-5 rounded border-[#262626] bg-[#0a0a0a] text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
            />
            <span className="text-sm text-gray-300">
              I acknowledge that I have read and understood this legal notice. I confirm that I will only 
              use NetMonitor for <strong>defensive purposes</strong> on networks I am authorized to monitor, 
              and I accept full responsibility for my use of this software.
            </span>
          </label>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-[#141414] border-t border-[#262626] p-4">
          <button
            onClick={handleAccept}
            disabled={!acknowledged}
            className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
          >
            <Shield className="w-5 h-5" />
            I Accept - Proceed to NetMonitor
          </button>
        </div>
      </div>
    </div>
  )
}
