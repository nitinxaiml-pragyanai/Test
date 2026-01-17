import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { MessageCircle, ArrowLeft, KeyRound, AlertCircle } from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const RegisterVerifyPage = () => {
  const navigate = useNavigate();
  const [student, setStudent] = useState(null);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [attemptsLeft, setAttemptsLeft] = useState(3);

  useEffect(() => {
    const stored = sessionStorage.getItem('register_student');
    if (!stored) {
      navigate('/register/pick');
      return;
    }
    setStudent(JSON.parse(stored));
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!password.trim()) {
      toast.error('Please enter your password');
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/register/verify`, {
        student_id: student.id,
        password: password.trim()
      });
      sessionStorage.setItem('register_verified', 'true');
      toast.success('Password verified!');
      navigate('/register/create');
    } catch (error) {
      const message = error.response?.data?.detail || 'Verification failed';
      toast.error(message);
      
      if (message.includes('attempts remaining')) {
        const match = message.match(/(\d+) attempts/);
        if (match) setAttemptsLeft(parseInt(match[1]));
      }
      
      if (message.includes('locked')) {
        sessionStorage.removeItem('register_student');
        setTimeout(() => navigate('/gate'), 2000);
      }
    } finally {
      setLoading(false);
    }
  };

  if (!student) return null;

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6 py-12">
      <Link 
        to="/register/pick" 
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
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold">2</div>
            <div className="w-12 h-1 bg-border rounded-full" />
            <div className="w-8 h-8 rounded-full bg-secondary text-muted-foreground flex items-center justify-center text-sm font-bold">3</div>
          </div>

          <div className="flex justify-center mb-6">
            <div className="w-14 h-14 bg-black rounded-2xl flex items-center justify-center">
              <KeyRound className="w-7 h-7 text-white" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Verify Your Identity
          </h1>
          <p className="text-muted-foreground text-center text-sm mb-2">
            Hello, <span className="font-medium text-foreground">{student.full_name}</span>
          </p>
          <p className="text-muted-foreground text-center text-sm mb-8">
            Enter the first-time password given to you
          </p>

          {attemptsLeft < 3 && (
            <div className="flex items-center gap-2 p-3 bg-destructive/10 rounded-xl mb-6">
              <AlertCircle className="w-4 h-4 text-destructive" />
              <span className="text-sm text-destructive font-medium">
                {attemptsLeft} attempt{attemptsLeft !== 1 ? 's' : ''} remaining
              </span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="relative">
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="verify-password-input"
                type="password"
                placeholder="Enter first-time password..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-14 pl-12 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
                autoFocus
              />
            </div>

            <Button
              data-testid="verify-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                'Verify Password'
              )}
            </Button>
          </form>

          <p className="text-xs text-muted-foreground text-center mt-6">
            Forgot your password? Ask your teacher for help.
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default RegisterVerifyPage;
