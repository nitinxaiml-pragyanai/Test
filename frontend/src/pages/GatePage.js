import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { MessageCircle, ArrowLeft, KeyRound } from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const GatePage = () => {
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!code.trim()) {
      toast.error('Please enter a code');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/gate/validate`, { code: code.trim() });
      const { type, redirect } = response.data;
      
      if (type === 'first_time') {
        toast.success('First-time entry verified');
      } else {
        toast.success('Login code verified');
      }
      
      navigate(redirect);
    } catch (error) {
      const message = error.response?.data?.detail || 'Invalid code';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6">
      {/* Back button */}
      <Link 
        to="/" 
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
          {/* Logo */}
          <div className="flex justify-center mb-8">
            <div className="w-16 h-16 bg-black rounded-2xl flex items-center justify-center">
              <MessageCircle className="w-8 h-8 text-white" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Enter Secret Code
          </h1>
          <p className="text-muted-foreground text-center text-sm mb-8">
            Enter the code provided by your teacher to continue
          </p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="relative">
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <Input
                data-testid="gate-code-input"
                type="text"
                placeholder="Enter code..."
                value={code}
                onChange={(e) => setCode(e.target.value.toUpperCase())}
                className="h-14 pl-12 text-center text-lg font-mono tracking-widest bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white focus:ring-4 focus:ring-[#007AFF]/10 rounded-xl input-premium"
                autoComplete="off"
                autoFocus
              />
            </div>

            <Button
              data-testid="gate-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                'Continue'
              )}
            </Button>
          </form>

          <div className="mt-8 pt-6 border-t border-border/50">
            <p className="text-xs text-muted-foreground text-center leading-relaxed">
              First time? Use the first-time code given in class.
              <br />
              Returning? Use the login code shown after registration.
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default GatePage;
