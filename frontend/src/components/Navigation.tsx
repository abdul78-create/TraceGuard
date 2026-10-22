import React from 'react'
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  BarChart3,
  GitCompare,
} from 'lucide-react'

export type NavTabId = 'overview' | 'traffic' | 'threats' | 'evaluation' | 'drift'

interface NavigationProps {
  activeTab: NavTabId
  onSelectTab: (tab: NavTabId) => void
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onSelectTab,
}) => {
  const tabs = [
    {
      id: 'overview' as NavTabId,
      label: 'Dashboard Overview',
      icon: LayoutDashboard,
    },
    {
      id: 'traffic' as NavTabId,
      label: 'Traffic Analysis',
      icon: Activity,
    },
    {
      id: 'threats' as NavTabId,
      label: 'Threat Detection',
      icon: ShieldAlert,
    },
    {
      id: 'evaluation' as NavTabId,
      label: 'Model Evaluation',
      icon: BarChart3,
    },
    {
      id: 'drift' as NavTabId,
      label: 'Drift Monitoring',
      icon: GitCompare,
    },
  ]

  return (
    <nav className="nav-bar" role="tablist" aria-label="Main Navigation">
      {tabs.map((tab) => {
        const Icon = tab.icon
        const isActive = activeTab === tab.id
        return (
          <button
            key={tab.id}
            id={`nav-tab-${tab.id}`}
            role="tab"
            aria-selected={isActive}
            className={`nav-tab ${isActive ? 'active' : ''}`}
            onClick={() => onSelectTab(tab.id)}
          >
            <Icon size={15} />
            <span>{tab.label}</span>
          </button>
        )
      })}
    </nav>
  )
}
