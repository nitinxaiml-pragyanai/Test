import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { MessageCircle, Shield, Users, Lock } from 'lucide-react';

const LandingPage = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen hero-gradient page-transition">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 glass border-b border-black/5">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-black rounded-xl flex items-center justify-center">
              <MessageCircle className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-xl tracking-tight" style={{ fontFamily: 'Manrope, sans-serif' }}>
              ObsidianX
            </span>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="pt-32 pb-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 bg-secondary/80 rounded-full px-4 py-2 mb-8">
              <Shield className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-medium text-muted-foreground tracking-wide">
                SECURE CLASS MESSAGING
              </span>
            </div>

            <h1 
              className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-foreground mb-6"
              style={{ fontFamily: 'Manrope, sans-serif' }}
            >
              Welcome to
              <br />
              <span className="text-black">ObsidianX</span>
            </h1>

            <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-12 leading-relaxed">
              The private messaging platform designed exclusively for your class.
              Connect with classmates in a secure, admin-controlled environment.
            </p>

            <Button
              data-testid="join-class-btn"
              onClick={() => navigate('/gate')}
              className="bg-black text-white hover:bg-black/90 rounded-full px-10 py-7 text-lg font-medium shadow-lg hover:shadow-xl transition-all duration-300 btn-micro"
            >
              Join the Class
            </Button>
          </motion.div>

          {/* Features */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-24 grid grid-cols-1 md:grid-cols-3 gap-6"
          >
            <div className="bg-white rounded-3xl p-8 shadow-soft card-hover border border-border/50">
              <div className="w-14 h-14 bg-secondary rounded-2xl flex items-center justify-center mb-6">
                <Lock className="w-7 h-7 text-foreground" />
              </div>
              <h3 className="font-bold text-lg mb-3" style={{ fontFamily: 'Manrope, sans-serif' }}>
                Private & Secure
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                End-to-end encrypted messages. Only your class has access.
              </p>
            </div>

            <div className="bg-white rounded-3xl p-8 shadow-soft card-hover border border-border/50">
              <div className="w-14 h-14 bg-secondary rounded-2xl flex items-center justify-center mb-6">
                <Users className="w-7 h-7 text-foreground" />
              </div>
              <h3 className="font-bold text-lg mb-3" style={{ fontFamily: 'Manrope, sans-serif' }}>
                Class Groups & DMs
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                One main class chat plus direct messages and custom groups.
              </p>
            </div>

            <div className="bg-white rounded-3xl p-8 shadow-soft card-hover border border-border/50">
              <div className="w-14 h-14 bg-secondary rounded-2xl flex items-center justify-center mb-6">
                <MessageCircle className="w-7 h-7 text-foreground" />
              </div>
              <h3 className="font-bold text-lg mb-3" style={{ fontFamily: 'Manrope, sans-serif' }}>
                Real-time Messaging
              </h3>
              <p className="text-muted-foreground text-sm leading-relaxed">
                Instant delivery with typing indicators and read receipts.
              </p>
            </div>
          </motion.div>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-8 px-6 border-t border-border/50">
        <div className="max-w-7xl mx-auto text-center">
          <p className="text-sm text-muted-foreground">
            ObsidianX — Secure messaging for your class
          </p>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
