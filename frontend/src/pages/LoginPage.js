import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { MessageCircle, ArrowLeft, KeyRound, User, Lock } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

const LoginPage = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [gateCode, setGateCode] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!gateCode.trim() || !username.trim() || !password.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    setLoading(true);
    try {
      await login(gateCode.trim(), username.trim(), password);
      toast.success('Welcome back!');
      navigate('/app');
    } catch (error) {
      const message = error.response?.data?.detail || 'Login failed';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6">
      <Link 
        to="/gate" 
        className="fixed top-6 left-6 flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
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
        <div className="bg-white rounded-3xl p-10 shadow-floating border border-border/50">
          <div className="flex justify-center mb-8">
            <div className="w-16 h-16 bg-black rounded-2xl flex items-center justify-center">
              <MessageCircle className="w-8 h-8 text-white" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Welcome Back
          </h1>
          <p className="text-muted-foreground text-center text-sm mb-8">
            Sign in to continue to ObsidianX
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="login-gate-code-input"
                type="text"
                placeholder="Login code..."
                value={gateCode}
                onChange={(e) => setGateCode(e.target.value.toUpperCase())}
                className="h-14 pl-12 font-mono tracking-widest bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
              />
            </div>

            <div className="relative">
              <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="login-username-input"
                type="text"
                placeholder="Username..."
                value={username}
                onChange={(e) => setUsername(e.target.value.toLowerCase())}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
              />
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="login-password-input"
                type="password"
                placeholder="Password..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
              />
            </div>

            <Button
              data-testid="login-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro mt-6"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                'Sign In'
              )}
            </Button>
          </form>

          <div className="mt-8 pt-6 border-t border-border/50 text-center">
            <p className="text-sm text-muted-foreground">
              Don't have an account?{' '}
              <Link to="/gate" className="text-[#007AFF] font-medium hover:underline">
                Use your first-time code
              </Link>
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default LoginPage;
