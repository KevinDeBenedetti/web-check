import { Route, Routes } from "react-router";
import { Layout } from "./components/Layout";
import { ComparePage } from "./pages/ComparePage";
import { DashboardPage } from "./pages/DashboardPage";
import { LiveScanPage } from "./pages/LiveScanPage";
import { NewScanPage } from "./pages/NewScanPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ReportPage } from "./pages/ReportPage";
import { ScansPage } from "./pages/ScansPage";
import { SettingsPage } from "./pages/SettingsPage";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/new" element={<NewScanPage />} />
        <Route path="scans/:scanId" element={<ReportPage />} />
        <Route path="scans/:scanId/live" element={<LiveScanPage />} />
        <Route path="compare" element={<ComparePage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
