import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { CheckCircle2, Copy, Check } from 'lucide-react';
import { toast } from 'sonner';

const RegisterDonePage = () => {
  const navigate = useNavigate();
  const [loginCode, setLoginCode] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const code = sessionStorage.getItem('login_code');
    if (!code) {
      navigate('/gate');
      return;
    }
    setLoginCode(code);
  }, [navigate]);

  const handleCopy = () => {
    navigator.clipboard.writeText(loginCode);
    setCopied(true);
    toast.success('Code copied!');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleContinue = () => {
    sessionStorage.removeItem('login_code');
    navigate('/login');
  };

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6 py-12">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <div className="bg-white rounded-3xl p-10 shadow-floating border border-border/50 text-center">
          {/* Success icon */}
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
            className="flex justify-center mb-8"
          >
            <div className="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center">
              <CheckCircle2 className="w-10 h-10 text-white" />
            </div>
          </motion.div>

          <h1 
            className="text-2xl font-bold mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            You're All Set!
          </h1>
          <p className="text-muted-foreground text-sm mb-8">
            Your account has been created successfully
          </p>

          {/* Login code display */}
          <div className="bg-secondary/50 rounded-2xl p-6 mb-8">
            <p className="text-sm text-muted-foreground mb-3">
              Your login code for next time:
            </p>
            <div className="flex items-center justify-center gap-3">
              <code 
                data-testid="login-code-display"
                className="text-2xl font-mono font-bold tracking-widest text-foreground"
              >
                {loginCode}
              </code>
              <button
                data-testid="copy-code-btn"
                onClick={handleCopy}
                className="p-2 rounded-lg hover:bg-secondary transition-colors"
              >
                {copied ? (
                  <Check className="w-5 h-5 text-green-500" />
                ) : (
                  <Copy className="w-5 h-5 text-muted-foreground" />
                )}
              </button>
            </div>
            <p className="text-xs text-muted-foreground mt-3">
              Remember this code to access the login page
            </p>
          </div>

          <Button
            data-testid="continue-to-login-btn"
            onClick={handleContinue}
            className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro"
          >
            Continue to Login
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

export default RegisterDonePage;
