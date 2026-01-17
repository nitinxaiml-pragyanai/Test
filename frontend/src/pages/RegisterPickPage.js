import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { MessageCircle, ArrowLeft, Search, User, ChevronRight } from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const RegisterPickPage = () => {
  const navigate = useNavigate();
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStudent, setSelectedStudent] = useState(null);

  useEffect(() => {
    fetchStudents();
  }, []);

  const fetchStudents = async () => {
    try {
      const response = await axios.get(`${API}/register/students`);
      setStudents(response.data);
    } catch (error) {
      toast.error('Failed to load student list');
    } finally {
      setLoading(false);
    }
  };

  const filteredStudents = students.filter(s => 
    s.full_name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleContinue = async () => {
    if (!selectedStudent) {
      toast.error('Please select your name');
      return;
    }

    try {
      await axios.post(`${API}/register/pick`, { student_id: selectedStudent.id });
      sessionStorage.setItem('register_student', JSON.stringify(selectedStudent));
      navigate('/register/verify');
    } catch (error) {
      const message = error.response?.data?.detail || 'Failed to select student';
      toast.error(message);
    }
  };

  return (
    <div className="min-h-screen hero-gradient page-transition flex items-center justify-center px-6 py-12">
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
        className="w-full max-w-lg"
      >
        <div className="bg-white rounded-3xl p-8 shadow-floating border border-border/50">
          {/* Progress indicator */}
          <div className="flex items-center justify-center gap-2 mb-8">
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold">1</div>
            <div className="w-12 h-1 bg-border rounded-full" />
            <div className="w-8 h-8 rounded-full bg-secondary text-muted-foreground flex items-center justify-center text-sm font-bold">2</div>
            <div className="w-12 h-1 bg-border rounded-full" />
            <div className="w-8 h-8 rounded-full bg-secondary text-muted-foreground flex items-center justify-center text-sm font-bold">3</div>
          </div>

          <div className="flex justify-center mb-6">
            <div className="w-14 h-14 bg-black rounded-2xl flex items-center justify-center">
              <MessageCircle className="w-7 h-7 text-white" />
            </div>
          </div>

          <h1 
            className="text-2xl font-bold text-center mb-2 tracking-tight"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            Find Your Name
          </h1>
          <p className="text-muted-foreground text-center text-sm mb-6">
            Select your name from the class roster
          </p>

          {/* Search */}
          <div className="relative mb-4">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              data-testid="student-search-input"
              type="text"
              placeholder="Search by name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-12 pl-11 bg-secondary/50 border-transparent focus:border-[#007AFF]/20 focus:bg-white rounded-xl"
            />
          </div>

          {/* Student list */}
          <ScrollArea className="h-64 mb-6">
            {loading ? (
              <div className="flex items-center justify-center h-full">
                <div className="w-6 h-6 border-2 border-black border-t-transparent rounded-full animate-spin" />
              </div>
            ) : filteredStudents.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                <User className="w-8 h-8 mb-2" />
                <p className="text-sm">No students found</p>
              </div>
            ) : (
              <div className="space-y-2 pr-4">
                {filteredStudents.map((student) => (
                  <button
                    key={student.id}
                    data-testid={`student-item-${student.id}`}
                    onClick={() => setSelectedStudent(student)}
                    className={`w-full flex items-center justify-between p-4 rounded-xl transition-all ${
                      selectedStudent?.id === student.id
                        ? 'bg-black text-white'
                        : 'bg-secondary/50 hover:bg-secondary text-foreground'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold ${
                        selectedStudent?.id === student.id
                          ? 'bg-white/20 text-white'
                          : 'bg-white text-foreground'
                      }`}>
                        {student.full_name.charAt(0)}
                      </div>
                      <span className="font-medium">{student.full_name}</span>
                    </div>
                    {selectedStudent?.id === student.id && (
                      <ChevronRight className="w-5 h-5" />
                    )}
                  </button>
                ))}
              </div>
            )}
          </ScrollArea>

          <Button
            data-testid="pick-continue-btn"
            onClick={handleContinue}
            disabled={!selectedStudent}
            className="w-full h-14 bg-black text-white hover:bg-black/90 rounded-full text-base font-medium shadow-lg btn-micro disabled:opacity-50"
          >
            Continue
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

export default RegisterPickPage;
