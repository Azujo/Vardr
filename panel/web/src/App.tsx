import { Center, Loader } from "@mantine/core";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import Layout from "./Layout";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import HomePage from "./pages/HomePage";
import UsersPage from "./pages/UsersPage";
import AuditPage from "./pages/AuditPage";
import ComingSoon from "./pages/ComingSoon";

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
        <Route
          path="/agents"
          element={<ComingSoon name="Huginn – agenci" what="Lista agentów z heartbeatem, wersje, stan kanałów i grupy." />}
        />
        <Route
          path="/events"
          element={<ComingSoon name="Mímir – zdarzenia" what="Wyszukiwarka zdarzeń z filtrami i podglądem surowego XML." />}
        />
        <Route
          path="/deploy"
          element={<ComingSoon name="Bifröst – wdrażanie" what="Tokeny rejestracyjne i instalator agenta bez klucza prywatnego." />}
        />
        <Route path="/account/password" element={<ChangePasswordPage />} />
        {admin && <Route path="/admin/users" element={<UsersPage />} />}
        {admin && <Route path="/admin/audit" element={<AuditPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
