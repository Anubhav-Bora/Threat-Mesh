import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { PageLoader } from "./components/UI";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const CampaignsPage = lazy(() => import("./pages/CampaignsPage"));
const AttackPage = lazy(() => import("./pages/AttackPage"));
const IndicatorsPage = lazy(() => import("./pages/IndicatorsPage"));
const ReportsPage = lazy(() => import("./pages/ReportsPage"));
const RulesPage = lazy(() => import("./pages/RulesPage"));
const AssistantPage = lazy(() => import("./pages/AssistantPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

export default function App() {
  return (
    <Suspense fallback={<PageLoader label="Loading ThreatMesh workspace" />}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="campaigns" element={<CampaignsPage />} />
          <Route path="attack" element={<AttackPage />} />
          <Route path="indicators" element={<IndicatorsPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="assistant" element={<AssistantPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
