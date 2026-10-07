import { Center, Loader } from "@mantine/core";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Layout from "./Layout";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import HomePage from "./pages/HomePage";
import UsersPage from "./pages/UsersPage";
import AuditPage from "./pages/AuditPage";
import AgentsPage from "./pages/AgentsPage";
import AgentDetailPage from "./pages/AgentDetailPage";
import DeployPage from "./pages/DeployPage";
import EventsPage from "./pages/EventsPage";

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
        <Route path="/events" element={<EventsPage />} />
        <Route path="/deploy" element={<DeployPage />} />
        <Route path="/account/password" element={<ChangePasswordPage />} />
        {admin && <Route path="/admin/users" element={<UsersPage />} />}
        {admin && <Route path="/admin/audit" element={<AuditPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
