// SPDX-License-Identifier: AGPL-3.0-or-later

import { Center, Loader } from "@mantine/core";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Layout from "./Layout";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import HomePage from "./pages/HomePage";
import UsersPage from "./pages/UsersPage";
import AuditPage from "./pages/AuditPage";
import NotificationsPage from "./pages/NotificationsPage";
import BackupPage from "./pages/BackupPage";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import CorrelationWizard from "./pages/CorrelationWizard";
import AttackPage from "./pages/AttackPage";
import RiskPage from "./pages/RiskPage";
import RulesPage from "./pages/RulesPage";
import RuleTrialsPage from "./pages/RuleTrialsPage";
import AccountSecurityPage from "./pages/AccountSecurityPage";
import ProfilesPage from "./pages/ProfilesPage";
import LdapPage from "./pages/LdapPage";
import ApiTokensPage from "./pages/ApiTokensPage";
import AiAccessPage from "./pages/AiAccessPage";
import IncidentsPage from "./pages/IncidentsPage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import DecodersPage from "./pages/DecodersPage";
import QuarantinePage from "./pages/QuarantinePage";
import IdentitiesPage from "./pages/IdentitiesPage";
import SystemPage from "./pages/SystemPage";
import AgentsPage from "./pages/AgentsPage";
import AgentDetailPage from "./pages/AgentDetailPage";
import DeployPage from "./pages/DeployPage";
import EventsPage from "./pages/EventsPage";
import GroupsPage from "./pages/GroupsPage";
import ArchivePage from "./pages/ArchivePage";

export default function App() {
  const { user, loading, can } = useAuth();

  if (loading) {
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  }
  if (!user) return <LoginPage />;
  if (user.must_change_password) return <ChangePasswordPage forced />;

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/agents/:id" element={<AgentDetailPage />} />
        <Route path="/groups" element={<GroupsPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/deploy" element={<DeployPage />} />
        <Route path="/archive" element={<ArchivePage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:id" element={<AlertDetailPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:id" element={<IncidentDetailPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/rules/correlation" element={<CorrelationWizard />} />
        <Route path="/rules/trial" element={<RuleTrialsPage />} />
        <Route path="/attack" element={<AttackPage />} />
        {can("risk", "read") && <Route path="/risk" element={<RiskPage />} />}
        <Route path="/decoders" element={<DecodersPage />} />
        <Route path="/quarantine" element={<QuarantinePage />} />
        <Route path="/identities" element={<IdentitiesPage />} />
        <Route path="/system" element={<SystemPage />} />
        <Route path="/account/password" element={<ChangePasswordPage />} />
        <Route path="/account/security" element={<AccountSecurityPage />} />
        {can("users", "read") && <Route path="/admin/users" element={<UsersPage />} />}
        {can("users", "read") && <Route path="/admin/profiles" element={<ProfilesPage />} />}
        {can("users", "read") && <Route path="/admin/ldap" element={<LdapPage />} />}
        {can("users", "read") && <Route path="/admin/api-tokens" element={<ApiTokensPage />} />}
        {can("ai", "read") && <Route path="/admin/ai" element={<AiAccessPage />} />}
        {can("audit", "read") && <Route path="/admin/audit" element={<AuditPage />} />}
        {can("notify", "read") && <Route path="/admin/notifications" element={<NotificationsPage />} />}
        {can("backup", "read") && <Route path="/admin/backup" element={<BackupPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
