import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { MessageCircle, ArrowLeft, User, Lock, Check, X } from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const RegisterCreatePage = () => {
  const navigate = useNavigate();
  const [student, setStudent] = useState(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const stored = sessionStorage.getItem('register_student');
    const verified = sessionStorage.getItem('register_verified');
    if (!stored || !verified) {
      navigate('/register/pick');
      return;
    }
    setStudent(JSON.parse(stored));
  }, [navigate]);

  const passwordChecks = {
    length: password.length >= 6,
    match: password === confirmPassword && password.length > 0
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (username.length < 3) {
      toast.error('Username must be at least 3 characters');
      return;
    }
    if (!passwordChecks.length) {
      toast.error('Password must be at least 6 characters');
      return;
    }
    if (!passwordChecks.match) {
      toast.error('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/register/create`, {
        student_id: student.id,
        username: username.trim(),
        password: password
      });
      
      sessionStorage.setItem('login_code', response.data.login_code);
      sessionStorage.removeItem('register_student');
      sessionStorage.removeItem('register_verified');
      
      toast.success('Account created successfully!');
      navigate('/register/done');
    } catch (error) {
      const message = error.response?.data?.detail || 'Failed to create account';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  if (!student) return null;

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6 py-12">
      <Link 
        to="/register/verify" 
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
          {/* Progress indicator */}
          <div className="flex items-center justify-center gap-2 mb-8">
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold">✓</div>
            <div className="w-12 h-1 bg-black rounded-full" />
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold">✓</div>
            <div className="w-12 h-1 bg-black rounded-full" />
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold">3</div>
          </div>

          <div className="flex justify-center mb-6">
            <div className="w-14 h-14 bg-black rounded-2xl flex items-center justify-center">
              <User className="w-7 h-7 text-white" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Create Your Account
          </h1>
          <p className="text-muted-foreground text-center text-sm mb-8">
            Set up your username and password
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="create-username-input"
                type="text"
                placeholder="Choose a username..."
                value={username}
                onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
                autoFocus
              />
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="create-password-input"
                type="password"
                placeholder="Create a password..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
              />
            </div>

            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="create-confirm-password-input"
                type="password"
                placeholder="Confirm password..."
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
              />
            </div>

            {/* Password requirements */}
            <div className="space-y-2 py-2">
              <div className="flex items-center gap-2 text-sm">
                {passwordChecks.length ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <X className="w-4 h-4 text-muted-foreground" />
                )}
                <span className={passwordChecks.length ? 'text-foreground' : 'text-muted-foreground'}>
                  At least 6 characters
                </span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                {passwordChecks.match ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <X className="w-4 h-4 text-muted-foreground" />
                )}
                <span className={passwordChecks.match ? 'text-foreground' : 'text-muted-foreground'}>
                  Passwords match
                </span>
              </div>
            </div>

            <Button
              data-testid="create-submit-btn"
              type="submit"
              disabled={loading || !passwordChecks.length || !passwordChecks.match || username.length < 3}
              className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro disabled:opacity-50"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                'Create Account'
              )}
            </Button>
          </form>
        </div>
      </motion.div>
    </div>
  );
};

export default RegisterCreatePage;
