import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";

// Pages
import LandingPage from "@/pages/LandingPage";
import GatePage from "@/pages/GatePage";
import RegisterPickPage from "@/pages/RegisterPickPage";
import RegisterVerifyPage from "@/pages/RegisterVerifyPage";
import RegisterCreatePage from "@/pages/RegisterCreatePage";
import RegisterDonePage from "@/pages/RegisterDonePage";
import LoginPage from "@/pages/LoginPage";
import ChatApp from "@/pages/ChatApp";
import AdminLoginPage from "@/pages/AdminLoginPage";
import AdminDashboard from "@/pages/AdminDashboard";

// Protected route wrapper
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-black border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }
  
  if (!user) {
    return <Navigate to="/gate" replace />;
  }
  
  return children;
};

// Admin protected route
const AdminRoute = ({ children }) => {
  const admin = localStorage.getItem("admin_token");
  if (!admin) {
    return <Navigate to="/admin/login" replace />;
  }
  return children;
};

function App() {
  return (
    <AuthProvider>
      <div className="App noise-overlay">
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/gate" element={<GatePage />} />
            
            {/* Registration flow */}
            <Route path="/register/pick" element={<RegisterPickPage />} />
            <Route path="/register/verify" element={<RegisterVerifyPage />} />
            <Route path="/register/create" element={<RegisterCreatePage />} />
            <Route path="/register/done" element={<RegisterDonePage />} />
            
            {/* Login */}
            <Route path="/login" element={<LoginPage />} />
            
            {/* Protected chat app */}
            <Route path="/app" element={
              <ProtectedRoute>
                <ChatApp />
              </ProtectedRoute>
            } />
            
            {/* Admin routes */}
            <Route path="/admin/login" element={<AdminLoginPage />} />
            <Route path="/admin" element={
              <AdminRoute>
                <AdminDashboard />
              </AdminRoute>
            } />
            
            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
        <Toaster position="top-center" richColors />
      </div>
    </AuthProvider>
  );
}

export default App;
