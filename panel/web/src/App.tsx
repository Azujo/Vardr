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
import RulesPage from "./pages/RulesPage";
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
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  }
  if (!user) return <LoginPage />;
  if (user.must_change_password) return <ChangePasswordPage forced />;

  const admin = user.role === "admin";
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
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/decoders" element={<DecodersPage />} />
        <Route path="/quarantine" element={<QuarantinePage />} />
        <Route path="/identities" element={<IdentitiesPage />} />
        <Route path="/system" element={<SystemPage />} />
        <Route path="/account/password" element={<ChangePasswordPage />} />
        {admin && <Route path="/admin/users" element={<UsersPage />} />}
        {admin && <Route path="/admin/audit" element={<AuditPage />} />}
        {admin && <Route path="/admin/notifications" element={<NotificationsPage />} />}
        {admin && <Route path="/admin/backup" element={<BackupPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
