import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger 
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { 
  Shield, Users, MessageCircle, Settings, FileText, 
  Plus, Search, MoreVertical, Trash2, RefreshCw, Ban,
  Unlock, Eye, LogOut, Edit, Key, Clock, AlertTriangle
} from 'lucide-react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const AdminDashboard = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('students');
  const [students, setStudents] = useState([]);
  const [chats, setChats] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [config, setConfig] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddStudent, setShowAddStudent] = useState(false);
  const [showEditCodes, setShowEditCodes] = useState(false);
  const [showChatView, setShowChatView] = useState(false);
  const [selectedChat, setSelectedChat] = useState(null);
  const [chatMessages, setChatMessages] = useState([]);
  const [newStudent, setNewStudent] = useState({ full_name: '', password: '' });
  const [newCodes, setNewCodes] = useState({ first_time: '', login: '' });

  const getAdminHeaders = useCallback(() => {
    const token = localStorage.getItem('admin_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, []);

  // Fetch data
  const fetchStudents = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/admin/students`, { headers: getAdminHeaders() });
      setStudents(response.data);
    } catch (error) {
      if (error.response?.status === 401 || error.response?.status === 403) {
        handleLogout();
      }
    }
  }, [getAdminHeaders]);

  const fetchChats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/admin/chats`, { headers: getAdminHeaders() });
      setChats(response.data);
    } catch (error) {
      console.error('Failed to fetch chats:', error);
    }
  }, [getAdminHeaders]);

  const fetchConfig = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/admin/config`, { headers: getAdminHeaders() });
      setConfig(response.data);
      setNewCodes({ first_time: response.data.first_time_code, login: response.data.login_code });
    } catch (error) {
      console.error('Failed to fetch config:', error);
    }
  }, [getAdminHeaders]);

  const fetchAuditLogs = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/admin/audit-logs`, { headers: getAdminHeaders() });
      setAuditLogs(response.data);
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
    }
  }, [getAdminHeaders]);

  useEffect(() => {
    const init = async () => {
      await Promise.all([fetchStudents(), fetchChats(), fetchConfig(), fetchAuditLogs()]);
      setLoading(false);
    };
    init();
  }, [fetchStudents, fetchChats, fetchConfig, fetchAuditLogs]);

  // Student actions
  const handleAddStudent = async () => {
    if (!newStudent.full_name.trim() || !newStudent.password.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    try {
      await axios.post(`${API}/admin/students`, {
        full_name: newStudent.full_name.trim(),
        first_time_password: newStudent.password.trim()
      }, { headers: getAdminHeaders() });
      
      toast.success('Student added');
      setShowAddStudent(false);
      setNewStudent({ full_name: '', password: '' });
      fetchStudents();
    } catch (error) {
      toast.error('Failed to add student');
    }
  };

  const handleDeleteStudent = async (studentId) => {
    if (!window.confirm('Are you sure you want to delete this student?')) return;
    
    try {
      await axios.delete(`${API}/admin/students/${studentId}`, { headers: getAdminHeaders() });
      toast.success('Student deleted');
      fetchStudents();
    } catch (error) {
      toast.error('Failed to delete student');
    }
  };

  const handleResetStudent = async (studentId) => {
    if (!window.confirm('Reset this student? They will need to register again.')) return;
    
    try {
      await axios.post(`${API}/admin/students/${studentId}/reset`, {}, { headers: getAdminHeaders() });
      toast.success('Student reset');
      fetchStudents();
    } catch (error) {
      toast.error('Failed to reset student');
    }
  };

  const handleUnlockStudent = async (studentId) => {
    try {
      await axios.post(`${API}/admin/students/${studentId}/unlock`, {}, { headers: getAdminHeaders() });
      toast.success('Student unlocked');
      fetchStudents();
    } catch (error) {
      toast.error('Failed to unlock student');
    }
  };

  const handleBanStudent = async (studentId, currentlyBanned) => {
    try {
      const endpoint = currentlyBanned ? 'unban' : 'ban';
      await axios.post(`${API}/admin/students/${studentId}/${endpoint}`, {}, { headers: getAdminHeaders() });
      toast.success(currentlyBanned ? 'Student unbanned' : 'Student banned');
      fetchStudents();
    } catch (error) {
      toast.error('Failed to update ban status');
    }
  };

  // Config actions
  const handleUpdateCodes = async () => {
    try {
      await axios.patch(`${API}/admin/config`, {
        first_time_code: newCodes.first_time || undefined,
        login_code: newCodes.login || undefined
      }, { headers: getAdminHeaders() });
      
      toast.success('Codes updated');
      setShowEditCodes(false);
      fetchConfig();
    } catch (error) {
      toast.error('Failed to update codes');
    }
  };

  const handleForceLogoutAll = async () => {
    if (!window.confirm('Force logout all students?')) return;
    
    try {
      await axios.post(`${API}/admin/force-logout-all`, {}, { headers: getAdminHeaders() });
      toast.success('All students logged out');
    } catch (error) {
      toast.error('Failed to force logout');
    }
  };

  // Chat surveillance
  const handleViewChat = async (chat) => {
    setSelectedChat(chat);
    try {
      const response = await axios.get(`${API}/admin/chats/${chat.id}/messages`, {
        headers: getAdminHeaders()
      });
      setChatMessages(response.data);
      setShowChatView(true);
    } catch (error) {
      toast.error('Failed to load messages');
    }
  };

  const handleDeleteMessage = async (messageId) => {
    try {
      await axios.delete(`${API}/admin/messages/${messageId}`, { headers: getAdminHeaders() });
      setChatMessages(prev => prev.filter(m => m.id !== messageId));
      toast.success('Message deleted');
    } catch (error) {
      toast.error('Failed to delete message');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_refresh');
    navigate('/admin/login');
  };

  // Filter
  const filteredStudents = students.filter(s => 
    s.full_name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="w-8 h-8 border-2 border-white border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-white" data-testid="admin-dashboard">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white rounded-xl flex items-center justify-center">
              <Shield className="w-5 h-5 text-black" />
            </div>
            <div>
              <span className="font-bold text-lg" style={{ fontFamily: 'Manrope, sans-serif' }}>
                ObsidianX Admin
              </span>
              <p className="text-xs text-zinc-500">Control Panel</p>
            </div>
          </div>
          
          <Button 
            data-testid="admin-logout-btn"
            variant="ghost" 
            onClick={handleLogout}
            className="text-zinc-400 hover:text-white hover:bg-zinc-800"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-zinc-900 border border-zinc-800 rounded-xl p-1 mb-8">
            <TabsTrigger 
              value="students" 
              className="data-[state=active]:bg-white data-[state=active]:text-black rounded-lg"
            >
              <Users className="w-4 h-4 mr-2" />
              Students
            </TabsTrigger>
            <TabsTrigger 
              value="chats"
              className="data-[state=active]:bg-white data-[state=active]:text-black rounded-lg"
            >
              <MessageCircle className="w-4 h-4 mr-2" />
              Chats
            </TabsTrigger>
            <TabsTrigger 
              value="settings"
              className="data-[state=active]:bg-white data-[state=active]:text-black rounded-lg"
            >
              <Settings className="w-4 h-4 mr-2" />
              Settings
            </TabsTrigger>
            <TabsTrigger 
              value="audit"
              className="data-[state=active]:bg-white data-[state=active]:text-black rounded-lg"
            >
              <FileText className="w-4 h-4 mr-2" />
              Audit Logs
            </TabsTrigger>
          </TabsList>

          {/* Students Tab */}
          <TabsContent value="students">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                  <Input
                    data-testid="admin-student-search"
                    placeholder="Search students..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10 bg-zinc-900 border-zinc-800 text-white rounded-xl"
                  />
                </div>
                
                <Dialog open={showAddStudent} onOpenChange={setShowAddStudent}>
                  <DialogTrigger asChild>
                    <Button data-testid="add-student-btn" className="bg-white text-black hover:bg-zinc-200 rounded-xl">
                      <Plus className="w-4 h-4 mr-2" />
                      Add Student
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="bg-zinc-900 border-zinc-800 text-white">
                    <DialogHeader>
                      <DialogTitle>Add New Student</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4 mt-4">
                      <Input
                        data-testid="new-student-name"
                        placeholder="Full name..."
                        value={newStudent.full_name}
                        onChange={(e) => setNewStudent({ ...newStudent, full_name: e.target.value })}
                        className="bg-zinc-800 border-zinc-700 text-white rounded-xl"
                      />
                      <Input
                        data-testid="new-student-password"
                        placeholder="First-time password..."
                        value={newStudent.password}
                        onChange={(e) => setNewStudent({ ...newStudent, password: e.target.value })}
                        className="bg-zinc-800 border-zinc-700 text-white rounded-xl"
                      />
                      <Button 
                        data-testid="confirm-add-student"
                        onClick={handleAddStudent} 
                        className="w-full bg-white text-black hover:bg-zinc-200 rounded-xl"
                      >
                        Add Student
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>

              {/* Students grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredStudents.map((student) => (
                  <motion.div
                    key={student.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <p className="font-medium text-lg">{student.full_name}</p>
                        <div className="flex items-center gap-2 mt-1">
                          {student.registered ? (
                            <Badge className="bg-green-500/20 text-green-400 border-0">Registered</Badge>
                          ) : (
                            <Badge className="bg-zinc-700 text-zinc-400 border-0">Unregistered</Badge>
                          )}
                          {student.locked && (
                            <Badge className="bg-red-500/20 text-red-400 border-0">Locked</Badge>
                          )}
                        </div>
                      </div>
                      
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="text-zinc-400 hover:text-white">
                            <MoreVertical className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent className="bg-zinc-900 border-zinc-800 text-white">
                          {student.locked && (
                            <DropdownMenuItem onClick={() => handleUnlockStudent(student.id)}>
                              <Unlock className="w-4 h-4 mr-2" />
                              Unlock
                            </DropdownMenuItem>
                          )}
                          {student.registered && (
                            <>
                              <DropdownMenuItem onClick={() => handleBanStudent(student.id, false)}>
                                <Ban className="w-4 h-4 mr-2" />
                                Ban User
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleResetStudent(student.id)}>
                                <RefreshCw className="w-4 h-4 mr-2" />
                                Reset Registration
                              </DropdownMenuItem>
                            </>
                          )}
                          <DropdownMenuItem 
                            onClick={() => handleDeleteStudent(student.id)}
                            className="text-red-400"
                          >
                            <Trash2 className="w-4 h-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                    
                    <p className="text-xs text-zinc-500">
                      Added: {new Date(student.created_at).toLocaleDateString()}
                    </p>
                  </motion.div>
                ))}
              </div>
              
              {filteredStudents.length === 0 && (
                <div className="text-center py-12 text-zinc-500">
                  No students found
                </div>
              )}
            </div>
          </TabsContent>

          {/* Chats Tab */}
          <TabsContent value="chats">
            <div className="space-y-4">
              {chats.map((chat) => (
                <motion.div
                  key={chat.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">
                        {chat.type === 'main_group' ? 'Main Class Group' : 
                         chat.type === 'dm' ? `DM: ${chat.member_details?.map(m => m.display_name).join(' & ')}` :
                         chat.name || 'Group'}
                      </p>
                      <p className="text-sm text-zinc-500">
                        {chat.members?.length || 0} members
                      </p>
                    </div>
                    
                    <Button
                      data-testid={`view-chat-${chat.id}`}
                      variant="secondary"
                      onClick={() => handleViewChat(chat)}
                      className="bg-zinc-800 hover:bg-zinc-700 text-white rounded-xl"
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      View Messages
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Chat view dialog */}
            <Dialog open={showChatView} onOpenChange={setShowChatView}>
              <DialogContent className="bg-zinc-900 border-zinc-800 text-white max-w-2xl max-h-[80vh]">
                <DialogHeader>
                  <DialogTitle>
                    {selectedChat?.type === 'main_group' ? 'Main Class Group' : 
                     selectedChat?.name || 'Chat Messages'}
                  </DialogTitle>
                </DialogHeader>
                <ScrollArea className="h-[60vh] mt-4">
                  <div className="space-y-3 pr-4">
                    {chatMessages.map((msg) => (
                      <div 
                        key={msg.id}
                        className={`p-3 rounded-xl ${msg.deleted ? 'bg-zinc-800/50 opacity-50' : 'bg-zinc-800'}`}
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <p className="text-sm font-medium text-zinc-300">{msg.sender_name}</p>
                            <p className="text-sm mt-1">{msg.content}</p>
                            <p className="text-xs text-zinc-500 mt-2">
                              {new Date(msg.created_at).toLocaleString()}
                            </p>
                          </div>
                          {!msg.deleted && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDeleteMessage(msg.id)}
                              className="text-red-400 hover:text-red-300 hover:bg-red-900/20"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </DialogContent>
            </Dialog>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Secret Codes */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 bg-zinc-800 rounded-xl flex items-center justify-center">
                    <Key className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-bold">Secret Codes</h3>
                    <p className="text-sm text-zinc-500">Manage gate access codes</p>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-zinc-500 mb-1">First-Time Entry Code</p>
                    <code className="text-lg font-mono bg-zinc-800 px-3 py-1 rounded-lg">
                      {config.first_time_code}
                    </code>
                  </div>
                  <div>
                    <p className="text-sm text-zinc-500 mb-1">Login Code</p>
                    <code className="text-lg font-mono bg-zinc-800 px-3 py-1 rounded-lg">
                      {config.login_code}
                    </code>
                  </div>
                  
                  <Dialog open={showEditCodes} onOpenChange={setShowEditCodes}>
                    <DialogTrigger asChild>
                      <Button className="w-full bg-zinc-800 hover:bg-zinc-700 text-white rounded-xl mt-4">
                        <Edit className="w-4 h-4 mr-2" />
                        Edit Codes
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="bg-zinc-900 border-zinc-800 text-white">
                      <DialogHeader>
                        <DialogTitle>Edit Secret Codes</DialogTitle>
                      </DialogHeader>
                      <div className="space-y-4 mt-4">
                        <div>
                          <label className="text-sm text-zinc-500">First-Time Code</label>
                          <Input
                            data-testid="edit-first-time-code"
                            value={newCodes.first_time}
                            onChange={(e) => setNewCodes({ ...newCodes, first_time: e.target.value.toUpperCase() })}
                            className="bg-zinc-800 border-zinc-700 text-white font-mono rounded-xl mt-1"
                          />
                        </div>
                        <div>
                          <label className="text-sm text-zinc-500">Login Code</label>
                          <Input
                            data-testid="edit-login-code"
                            value={newCodes.login}
                            onChange={(e) => setNewCodes({ ...newCodes, login: e.target.value.toUpperCase() })}
                            className="bg-zinc-800 border-zinc-700 text-white font-mono rounded-xl mt-1"
                          />
                        </div>
                        <Button 
                          data-testid="save-codes-btn"
                          onClick={handleUpdateCodes}
                          className="w-full bg-white text-black hover:bg-zinc-200 rounded-xl"
                        >
                          Save Changes
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 bg-zinc-800 rounded-xl flex items-center justify-center">
                    <AlertTriangle className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-bold">Quick Actions</h3>
                    <p className="text-sm text-zinc-500">System-wide controls</p>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <Button 
                    data-testid="force-logout-all-btn"
                    onClick={handleForceLogoutAll}
                    className="w-full bg-red-900/30 hover:bg-red-900/50 text-red-400 border border-red-900/50 rounded-xl"
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Force Logout All Students
                  </Button>
                </div>
              </div>

              {/* Stats */}
              <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
                <h3 className="font-bold mb-4">Statistics</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-zinc-800 rounded-xl p-4 text-center">
                    <p className="text-3xl font-bold">{students.length}</p>
                    <p className="text-sm text-zinc-500">Total Students</p>
                  </div>
                  <div className="bg-zinc-800 rounded-xl p-4 text-center">
                    <p className="text-3xl font-bold">{students.filter(s => s.registered).length}</p>
                    <p className="text-sm text-zinc-500">Registered</p>
                  </div>
                  <div className="bg-zinc-800 rounded-xl p-4 text-center">
                    <p className="text-3xl font-bold">{chats.length}</p>
                    <p className="text-sm text-zinc-500">Total Chats</p>
                  </div>
                  <div className="bg-zinc-800 rounded-xl p-4 text-center">
                    <p className="text-3xl font-bold">{auditLogs.length}</p>
                    <p className="text-sm text-zinc-500">Audit Entries</p>
                  </div>
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Audit Logs Tab */}
          <TabsContent value="audit">
            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
              <div className="p-4 border-b border-zinc-800">
                <h3 className="font-bold">Recent Activity</h3>
              </div>
              <ScrollArea className="h-[600px]">
                <div className="divide-y divide-zinc-800">
                  {auditLogs.map((log) => (
                    <div key={log.id} className="p-4 hover:bg-zinc-800/50 transition-colors">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium">
                            <span className="text-zinc-400">Action:</span> {log.action}
                          </p>
                          <p className="text-sm text-zinc-500">
                            Target: {log.target_type} ({log.target_id?.slice(0, 8)}...)
                          </p>
                        </div>
                        <div className="flex items-center gap-2 text-sm text-zinc-500">
                          <Clock className="w-4 h-4" />
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

export default AdminDashboard;
