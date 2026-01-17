import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { Shield, ArrowLeft, User, Lock } from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const AdminLoginPage = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!username.trim() || !password.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/admin/login`, {
        username: username.trim(),
        password: password
      });
      
      localStorage.setItem('admin_token', response.data.access_token);
      localStorage.setItem('admin_refresh', response.data.refresh_token);
      toast.success('Admin access granted');
      navigate('/admin');
    } catch (error) {
      const message = error.response?.data?.detail || 'Login failed';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black page-transition flex items-center justify-center px-6">
      <Link 
        to="/" 
        className="fixed top-6 left-6 flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        <span className="text-sm font-medium">Back</span>
      </Link>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <div className="bg-zinc-900 rounded-3xl p-10 border border-zinc-800">
          <div className="flex justify-center mb-8">
            <div className="w-16 h-16 bg-white rounded-2xl flex items-center justify-center">
              <Shield className="w-8 h-8 text-black" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight text-white"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Admin Access
          </h1>
          <p className="text-gray-400 text-center text-sm mb-8">
            ObsidianX Control Panel
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              <Input
                data-testid="admin-username-input"
                type="text"
                placeholder="Admin username..."
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="h-14 pl-12 bg-zinc-800 border-zinc-700 text-white placeholder:text-gray-500 focus:border-white/20 focus:ring-4 focus:ring-white/10 rounded-xl"
                autoFocus
              />
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              <Input
                data-testid="admin-password-input"
                type="password"
                placeholder="Password..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-14 pl-12 bg-zinc-800 border-zinc-700 text-white placeholder:text-gray-500 focus:border-white/20 focus:ring-4 focus:ring-white/10 rounded-xl"
              />
            </div>

            <Button
              data-testid="admin-login-btn"
              type="submit"
              disabled={loading}
              className="w-full h-14 bg-white text-black hover:bg-gray-100 rounded-full text-base font-medium shadow-lg btn-micro mt-6"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-black border-t-transparent rounded-full animate-spin" />
              ) : (
                'Access Control Panel'
              )}
            </Button>
          </form>
        </div>
      </motion.div>
    </div>
  );
};

export default AdminLoginPage;
